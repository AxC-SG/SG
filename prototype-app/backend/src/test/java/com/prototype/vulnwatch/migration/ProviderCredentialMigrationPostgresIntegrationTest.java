package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.service.CredentialEncryptionService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class ProviderCredentialMigrationPostgresIntegrationTest {
    private static final String KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    @Test
    void dryRunPreservesSecretsAndApplyConvertsMoreThanTwoBoundedBatchesWithReadback() throws Exception {
        var database = LocalPostgresTestDatabase.provision("provider_credential_conversion");
        try (Connection connection = DriverManager.getConnection(database.url(), database.username(), database.password())) {
            initialize(connection);
            try (var insert = connection.prepareStatement("insert into tenant_default.github_sbom_sources values (?,?)")) {
                for (int i = 0; i < 205; i++) {
                    insert.setObject(1, new UUID(0, i + 1));
                    insert.setString(2, "tenant-secret-" + i);
                    insert.executeUpdate();
                }
            }
            var encryption = new CredentialEncryptionService(KEY);
            var migrator = new ProviderCredentialMigrator(encryption);
            assertEquals(205, migrator.migrate(connection, false).changed());
            assertEquals(205, count(connection, "select count(*) from tenant_default.github_sbom_sources where github_token like 'tenant-secret-%'"));
            assertEquals(0, count(connection, "select count(*) from tenant_default.migration_updates"));
            assertEquals(205, migrator.migrate(connection, true).changed());
            assertEquals(205, count(connection, "select count(*) from tenant_default.github_sbom_sources where github_token like 'enc:v2:primary:%'"));
            assertEquals(3, count(connection, "select count(distinct transaction_id) from tenant_default.migration_updates"));
            assertTrue(count(connection, "select max(amount) from (select count(*) amount from tenant_default.migration_updates group by transaction_id) batches") <= 100);
            try (var query = connection.createStatement(); var rows = query.executeQuery("select id, github_token from tenant_default.github_sbom_sources")) {
                while (rows.next()) {
                    assertEquals("tenant-secret-" + (rows.getObject(1, UUID.class).getLeastSignificantBits() - 1), encryption.decrypt(rows.getString(2)));
                }
            }
            assertEquals(0, migrator.migrate(connection, true).changed());
        }
    }

    @Test
    void failedReadbackRollsBackTheWholeBatchWithoutPrintingSensitiveDriverErrors() throws Exception {
        var database = LocalPostgresTestDatabase.provision("provider_credential_rollback");
        try (Connection connection = DriverManager.getConnection(database.url(), database.username(), database.password())) {
            initialize(connection);
            try (var statement = connection.createStatement()) {
                statement.execute("insert into tenant_default.github_sbom_sources values ('00000000-0000-0000-0000-000000000001','first-secret'),('00000000-0000-0000-0000-000000000002','second-secret')");
                statement.execute("create function tenant_default.corrupt_readback() returns trigger language plpgsql as $$ begin if new.id='00000000-0000-0000-0000-000000000002' then new.github_token='enc:v2:missing:invalid'; end if; return new; end $$");
                statement.execute("create trigger corrupt_readback before update on tenant_default.github_sbom_sources for each row execute function tenant_default.corrupt_readback()");
            }
            var failure = assertThrows(IllegalStateException.class, () -> new ProviderCredentialMigrator(new CredentialEncryptionService(KEY)).migrate(connection, true));
            assertEquals("Credential migration batch failed; its writes were rolled back", failure.getMessage());
            assertEquals(2, count(connection, "select count(*) from tenant_default.github_sbom_sources where github_token in ('first-secret','second-secret')"));
            assertEquals(0, count(connection, "select count(*) from tenant_default.migration_updates"));
        }
    }

    @Test
    void rotatingKeyConvertsActualAiAwsExternalIdStorageBeforeOldKeyRetirement() throws Exception {
        var database = LocalPostgresTestDatabase.provision("provider_credential_aws_rotation");
        try (Connection connection = DriverManager.getConnection(database.url(), database.username(), database.password())) {
            initialize(connection);
            byte[] iv = new byte[12];
            new java.security.SecureRandom().nextBytes(iv);
            var cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE,
                    new javax.crypto.spec.SecretKeySpec(java.util.Base64.getDecoder().decode(KEY), "AES"),
                    new javax.crypto.spec.GCMParameterSpec(128, iv));
            byte[] encrypted = cipher.doFinal("legacy-external-id-sentinel".getBytes(java.nio.charset.StandardCharsets.UTF_8));
            byte[] envelope = java.nio.ByteBuffer.allocate(iv.length + encrypted.length).put(iv).put(encrypted).array();
            String legacy = "enc:v1:" + java.util.Base64.getEncoder().encodeToString(envelope);
            try (var sql = connection.createStatement()) {
                sql.execute("create table tenant_default.ai_security_connector_configs (id uuid primary key, external_id_ciphertext text)");
            }
            try (var insert = connection.prepareStatement("insert into tenant_default.ai_security_connector_configs values (?,?)")) {
                insert.setObject(1, UUID.randomUUID()); insert.setString(2, legacy); insert.executeUpdate();
            }
            byte[] nextKeyBytes = new byte[32];
            java.util.Arrays.fill(nextKeyBytes, (byte) 7);
            String nextKey = java.util.Base64.getEncoder().encodeToString(nextKeyBytes);
            var rotating = new CredentialEncryptionService(nextKey, "rotated", "legacy=" + KEY);
            var migrator = new ProviderCredentialMigrator(rotating);
            assertEquals(1, migrator.migrate(connection, false).changed());
            assertEquals(1, migrator.migrate(connection, true).changed());
            try (var sql = connection.createStatement(); var row = sql.executeQuery(
                    "select external_id_ciphertext from tenant_default.ai_security_connector_configs")) {
                row.next();
                assertTrue(row.getString(1).startsWith("enc:v2:rotated:"));
                assertEquals("legacy-external-id-sentinel",
                        new CredentialEncryptionService(nextKey, "rotated", "").decrypt(row.getString(1)));
            }
        }
    }

    private void initialize(Connection connection) throws Exception {
        try (var statement = connection.createStatement()) {
            statement.execute("create schema platform");
            statement.execute("create table platform.tenants (schema_name text)");
            statement.execute("create schema tenant_default");
            statement.execute("create table tenant_default.github_sbom_sources (id uuid primary key, github_token text)");
            statement.execute("create table tenant_default.migration_updates (transaction_id bigint)");
            statement.execute("create function tenant_default.record_migration_update() returns trigger language plpgsql as $$ begin insert into tenant_default.migration_updates values (txid_current()); return new; end $$");
            statement.execute("create trigger record_migration_update after update on tenant_default.github_sbom_sources for each row execute function tenant_default.record_migration_update()");
        }
    }

    private long count(Connection connection, String sql) throws Exception {
        try (var statement = connection.createStatement(); var rows = statement.executeQuery(sql)) {
            rows.next();
            return rows.getLong(1);
        }
    }
}
