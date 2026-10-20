package com.prototype.vulnwatch.migration;

import com.prototype.vulnwatch.service.CredentialEncryptionService;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/** Offline, bounded conversion. Runtime decrypt never accepts plaintext storage. */
public final class ProviderCredentialMigrator {
    public static final int BATCH_SIZE = 100;
    private static final List<Target> TARGETS = List.of(
            new Target("github_sbom_sources", "github_token"),
            new Target("aws_discovery_configs", "credential_secret"),
            new Target("azure_discovery_configs", "client_secret"),
            new Target("sccm_cmdb_configs", "credential_secret"),
            new Target("servicenow_cmdb_configs", "credential_secret"),
            new Target("ai_security_connector_configs", "external_id_ciphertext"),
            new Target("ai_security_azure_credential_profiles", "active_secret_ciphertext"),
            new Target("ai_security_azure_credential_profiles", "pending_secret_ciphertext"));
    private final CredentialEncryptionService encryption;

    public ProviderCredentialMigrator(CredentialEncryptionService encryption) {
        this.encryption = encryption;
    }

    public Summary migrate(Connection connection, boolean apply) throws SQLException {
        if (!connection.getAutoCommit()) throw new IllegalStateException("Credential migration requires its own connection");
        List<String> schemas = new ArrayList<>();
        try (PreparedStatement query = connection.prepareStatement(
                "select distinct schema_name from platform.tenants where schema_name is not null union select 'tenant_default'")) {
            try (ResultSet rows = query.executeQuery()) { while (rows.next()) schemas.add(rows.getString(1)); }
        }
        long inspected = 0;
        long changed = 0;
        for (String schema : schemas) {
            if (!schema.matches("tenant_[a-z0-9_]+")) throw new IllegalStateException("Unrecognized tenant schema identifier");
            for (Target target : TARGETS) {
                if (!exists(connection, schema, target)) continue;
                UUID after = null;
                while (true) {
                    Batch result = migrateBatch(connection, schema, target, after, apply);
                    inspected += result.inspected();
                    changed += result.changed();
                    if (result.inspected() < BATCH_SIZE) break;
                    after = result.lastId();
                }
            }
        }
        return new Summary(inspected, changed, apply);
    }

    private Batch migrateBatch(Connection connection, String schema, Target target, UUID after, boolean apply) throws SQLException {
        String table = '"' + schema + "\".\"" + target.table() + '"';
        String column = '"' + target.column() + '"';
        String query = "select id, " + column + " from " + table + " where " + column
                + " is not null and btrim(" + column + ") <> ''"
                + (after == null ? "" : " and id > ?") + " order by id limit " + BATCH_SIZE
                + (apply ? " for update" : "");
        connection.setAutoCommit(false);
        try {
            int inspected = 0;
            int changed = 0;
            UUID last = after;
            try (PreparedStatement select = connection.prepareStatement(query)) {
                select.setQueryTimeout(30);
                if (after != null) select.setObject(1, after);
                try (ResultSet rows = select.executeQuery()) {
                    while (rows.next()) {
                        UUID id = rows.getObject(1, UUID.class);
                        String stored = rows.getString(2);
                        last = id;
                        inspected++;
                        String plaintext = encryption.isEncrypted(stored) ? encryption.decrypt(stored) : stored;
                        // Verify even active envelopes before declaring the migration complete.
                        if (encryption.usesActiveKey(stored)) continue;
                        changed++;
                        if (!apply) continue;
                        String replacement = encryption.encrypt(plaintext);
                        try (PreparedStatement update = connection.prepareStatement(
                                "update " + table + " set " + column + " = ? where id = ?")) {
                            update.setString(1, replacement);
                            update.setObject(2, id);
                            if (update.executeUpdate() != 1) throw new SQLException("Credential migration row count mismatch");
                        }
                        try (PreparedStatement verify = connection.prepareStatement(
                                "select " + column + " from " + table + " where id = ?")) {
                            verify.setObject(1, id);
                            try (ResultSet checked = verify.executeQuery()) {
                                if (!checked.next() || !plaintext.equals(encryption.decrypt(checked.getString(1)))) {
                                    throw new IllegalStateException("Credential migration readback verification failed");
                                }
                            }
                        }
                    }
                }
            }
            if (apply) connection.commit(); else connection.rollback();
            return new Batch(inspected, changed, last);
        } catch (SQLException | RuntimeException failure) {
            connection.rollback();
            // Provider data and driver error text are intentionally excluded from diagnostics.
            throw new IllegalStateException("Credential migration batch failed; its writes were rolled back");
        } finally {
            connection.setAutoCommit(true);
        }
    }

    private boolean exists(Connection connection, String schema, Target target) throws SQLException {
        try (PreparedStatement query = connection.prepareStatement(
                "select 1 from information_schema.columns where table_schema=? and table_name=? and column_name=?")) {
            query.setString(1, schema);
            query.setString(2, target.table());
            query.setString(3, target.column());
            try (ResultSet rows = query.executeQuery()) { return rows.next(); }
        }
    }

    private record Target(String table, String column) { }
    private record Batch(int inspected, int changed, UUID lastId) { }
    public record Summary(long inspected, long changed, boolean applied) { }
}
