package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Map;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Tenant V24 (ownership Release 2, Phase 0B §1.8, §2.2, §3.8, §4.11) applied to a V23 schema that already holds
 * campaigns, members, notify groups, ticket attempts and cloud connector settings. The upgraded schema must match a
 * fresh V24 schema, existing rows must satisfy the new NOT NULL columns, and campaign membership must no longer be
 * cascaded away when a finding is deleted.
 */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class OwnershipReleaseTwoSchemaUpgradePostgresIntegrationTest {

    private static final String TENANT_A = "e5fe0d29-1d64-4175-8ce6-c34f42b214cc";
    private static final String TENANT_B = "00000000-0000-4000-8000-000000002424";
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ownership_release_two_schema_upgrade");

    @Test
    void v24AppliesOverExistingRowsAndMatchesAFreshSchema() throws Exception {
        platform().migrate();
        tenant("tenant_default", TENANT_A, "23").migrate();

        UUID cveCampaign = insertCampaign("CVE campaign");
        UUID findingCampaign = insertCampaign("Finding campaign");
        UUID vulnerability = insertVulnerability();
        update("insert into tenant_default.campaign_vulnerabilities (id, campaign_id, vulnerability_id, external_id, created_at)"
                + " values (gen_random_uuid(), ?, ?, 'CVE-2026-24001', now())", cveCampaign, vulnerability);
        UUID finding = insertFinding("F-V24MEMBER");
        update("insert into tenant_default.campaign_findings (campaign_id, finding_id, added_by) values (?, ?, 'test')",
                findingCampaign, finding);
        update("insert into tenant_default.campaign_notify_groups (id, campaign_id, group_name, created_at, group_email)"
                + " values (gen_random_uuid(), ?, 'Platform team', now(), 'platform@example.test')", findingCampaign);
        update("insert into tenant_default.finding_ticket_attempts (id, finding_id, template, outcome, attempted_by)"
                + " values (gen_random_uuid(), ?, 'DEFAULT', 'SUCCEEDED', 'test')", finding);
        update("insert into tenant_default.aws_discovery_configs (id, auth_type, auto_sync_enabled, created_at, enabled,"
                + " interval_minutes, regions_json, resource_types_json, source_system, updated_at)"
                + " values (gen_random_uuid(), 'INSTANCE_METADATA', false, now(), true, 60, '[]', '[]', 'aws', now())");
        update("insert into tenant_default.gcp_discovery_configs (id) values (gen_random_uuid())");

        tenant("tenant_default", TENANT_A, "24").migrate();

        // Existing campaigns: CVE-linked ones are CVE-scoped, the rest finding-scoped, all complete.
        assertEquals("CVE", text("select scope_kind from tenant_default.campaigns where id = ?", cveCampaign));
        assertEquals("FINDINGS", text("select scope_kind from tenant_default.campaigns where id = ?", findingCampaign));
        assertEquals(2, integer("select count(*) from tenant_default.campaigns"
                + " where membership_state = 'COMPLETE' and reconcile_failures = 0"));
        // Pre-ledger members keep a null add_source and no snapshot.
        assertNull(text("select add_source from tenant_default.campaign_findings where finding_id = ?", finding));
        // Existing notify groups are CUSTOM and keep their address until V26 drops the plaintext column.
        assertEquals("CUSTOM|platform@example.test",
                text("select recipient_type || '|' || group_email from tenant_default.campaign_notify_groups"));
        assertEquals("LEGACY", text("select routing_source from tenant_default.finding_ticket_attempts"));
        assertEquals(1, integer("select count(*) from tenant_default.aws_discovery_configs where ownership_owner_key_enabled"
                + " and ownership_team_key_enabled and ownership_account_input_enabled"));
        assertEquals(1, integer("select count(*) from tenant_default.gcp_discovery_configs where ownership_owner_key_enabled"
                + " and ownership_team_key_enabled and ownership_account_input_enabled"));

        // The defaults only filled existing rows: a writer must name the scope and every routing source.
        assertSqlState("23502", () -> update("insert into tenant_default.campaigns"
                + " (id, tenant_id, name, status, created_by, created_at, updated_at, membership_state)"
                + " values (gen_random_uuid(), ?::uuid, 'No scope', 'ACTIVE', 'test', now(), now(), 'COMPLETE')", TENANT_A));
        assertSqlState("23502", () -> update("insert into tenant_default.finding_ticket_attempts"
                + " (id, finding_id, template, outcome, attempted_by) values (gen_random_uuid(), ?, 'DEFAULT', 'FAILED', 'test')",
                finding));
        // A TEAM recipient needs a team; a CUSTOM one must not have one.
        assertSqlState("23514", () -> update("insert into tenant_default.campaign_notify_groups"
                + " (id, campaign_id, group_name, created_at, recipient_type) values (gen_random_uuid(), ?, 'Team', now(), 'TEAM')",
                findingCampaign));
        // The CMDB support-group reference is a lower-case 32-hex sys_id (checked before the asset FK).
        assertSqlState("23514", () -> update("insert into tenant_default.cis (id, business_criticality, created_at,"
                + " display_name, sys_id, updated_at, asset_id, support_group_sys_id) values (gen_random_uuid(), 'LOW', now(),"
                + " 'host', 'ci-1', now(), gen_random_uuid(), 'NOT-A-SYS-ID')"));

        // §4.13: a finding with campaign membership can no longer be deleted (RESTRICT, not CASCADE).
        assertSqlState("23503", () -> update("delete from tenant_default.findings where id = ?", finding));
        assertEquals(1, integer("select count(*) from tenant_default.campaign_findings where finding_id = ?", finding));

        // The upgraded schema is structurally identical to a tenant provisioned straight to V24.
        registerTenant(TENANT_B, "tenant_v24_fresh");
        tenant("tenant_v24_fresh", TENANT_B, "24").migrate();
        try (Connection connection = connection()) {
            assertEquals(TenantSchemaFingerprint.of(connection, "tenant_v24_fresh"),
                    TenantSchemaFingerprint.of(connection, "tenant_default"));
        }

        // V26 (Phase 0B §4.6): the plaintext recipient address is gone and existing campaigns do not include excepted
        // findings; the upgrade still matches a fresh tenant.
        tenant("tenant_default", TENANT_A, "26").migrate();
        assertEquals(0, integer("select count(*) from information_schema.columns where table_schema = 'tenant_default'"
                + " and table_name = 'campaign_notify_groups' and column_name = 'group_email'"));
        assertEquals(2, integer("select count(*) from tenant_default.campaigns where not include_excepted"));
        tenant("tenant_v24_fresh", TENANT_B, "26").migrate();
        try (Connection connection = connection()) {
            assertEquals(TenantSchemaFingerprint.of(connection, "tenant_v24_fresh"),
                    TenantSchemaFingerprint.of(connection, "tenant_default"));
        }
    }

    private UUID insertCampaign(String name) throws SQLException {
        UUID id = UUID.randomUUID();
        update("insert into tenant_default.campaigns (id, tenant_id, name, status, created_by, created_at, updated_at)"
                + " values (?, ?::uuid, ?, 'ACTIVE', 'test', now(), now())", id, TENANT_A, name);
        return id;
    }

    private UUID insertVulnerability() throws SQLException {
        UUID id = UUID.randomUUID();
        update("insert into platform.vulnerabilities (id, external_id, source, title, severity, in_kev, created_at, updated_at)"
                + " values (?, 'CVE-2026-24001', 'NVD', 'V24 upgrade fixture', 'HIGH', false, now(), now())", id);
        return id;
    }

    /** An AI posture finding avoids the vulnerability subject check and its foreign keys. */
    private UUID insertFinding(String displayId) throws SQLException {
        UUID id = UUID.randomUUID();
        update("insert into tenant_default.findings (id, tenant_id, created_at, updated_at, creation_source, display_id,"
                + " matched_by, risk_score, status, finding_kind) values (?, ?::uuid, now(), now(), 'AI_SECURITY', ?,"
                + " 'AI_SECURITY', 5.0, 'OPEN', 'AI_POSTURE')", id, TENANT_A, displayId);
        return id;
    }

    private void registerTenant(String id, String schema) throws SQLException {
        update("insert into platform.tenants (id, created_at, max_connector_count, max_daily_exposure_refreshes,"
                + " max_daily_sbom_uploads, max_export_rows, max_service_account_count, name, plan_code, schema_name, slug,"
                + " status, updated_at) values (?::uuid, now(), 10, 10, 10, 10000, 10, 'V24 fresh tenant', 'pilot', ?, ?,"
                + " 'ACTIVE', now())", id, schema, schema.replace('_', '-'));
    }

    private Flyway platform() {
        return Flyway.configure().dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public").locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .validateOnMigrate(true).load();
    }

    private Flyway tenant(String schema, String tenantId, String target) {
        return Flyway.configure().dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .schemas(schema).defaultSchema(schema).table("tenant_schema_history")
                .locations("filesystem:src/main/resources/db/migration/tenant")
                .placeholders(Map.of("tenantSchema", schema, "tenantId", tenantId))
                .target(target).validateOnMigrate(true).load();
    }

    private Connection connection() throws SQLException {
        return DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
    }

    private interface SqlAction {
        void run() throws SQLException;
    }

    private static void assertSqlState(String expected, SqlAction action) {
        SQLException failure = assertThrows(SQLException.class, action::run);
        assertEquals(expected, failure.getSQLState(), failure.getMessage());
    }

    private void update(String sql, Object... args) throws SQLException {
        try (Connection connection = connection(); PreparedStatement statement = prepare(connection, sql, args)) {
            statement.executeUpdate();
        }
    }

    private String text(String sql, Object... args) throws SQLException {
        try (Connection connection = connection(); PreparedStatement statement = prepare(connection, sql, args);
             ResultSet resultSet = statement.executeQuery()) {
            assertTrue(resultSet.next(), "expected a row for: " + sql);
            return resultSet.getString(1);
        }
    }

    private int integer(String sql, Object... args) throws SQLException {
        try (Connection connection = connection(); PreparedStatement statement = prepare(connection, sql, args);
             ResultSet resultSet = statement.executeQuery()) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }

    /** Runs as the connecting (owner) role with the tenant pinned, as the migrator does. */
    private static PreparedStatement prepare(Connection connection, String sql, Object... args) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("select set_config('app.current_tenant_id', '" + TENANT_A + "', false)");
        }
        PreparedStatement statement = connection.prepareStatement(sql);
        for (int i = 0; i < args.length; i++) {
            statement.setObject(i + 1, args[i]);
        }
        return statement;
    }
}
