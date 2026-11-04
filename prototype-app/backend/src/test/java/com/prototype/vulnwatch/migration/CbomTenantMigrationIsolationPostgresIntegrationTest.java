package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.service.cbom.CbomRuleRolloutLeaseStore;
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
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/**
 * Real-PostgreSQL proof for the CBOM tenant migrations V11-V19 and platform V10: every new tenant
 * table is forced behind row-level security and isolates tenants for a non-superuser, V15 upgrades
 * a populated V14 schema in place, and the rollout lease admits one owner at a time and resumes
 * from the committed cursor after expiry.
 */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class CbomTenantMigrationIsolationPostgresIntegrationTest {

    private static final String TENANT_A = "e5fe0d29-1d64-4175-8ce6-c34f42b214cc";
    private static final String TENANT_B = "00000000-0000-4000-8000-000000001515";
    private static final String RLS_ROLE = "cbom_migration_rls_role";
    private static final String[] TABLES = {"finding_suppression_requests", "cbom_tenant_settings", "cbom_rule_configurations",
            "cbom_assessment_runs", "cbom_validation_issues", "cbom_claim_assurances", "cbom_relationships",
            "cbom_rule_availability", "cbom_rule_selection_history", "cbom_posture_snapshots", "cbom_report_artifacts", "campaign_findings", "finding_ticket_attempts", "cbom_contradictions", "cbom_gate_policies", "cbom_gate_tokens"};
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("cbom_migration_isolation");

    @Test
    void cbomMigrationsForceRlsUpgradeInPlaceAndLeaseAdmitsOneOwner() throws Exception {
        platform().migrate();
        registerTenant(TENANT_B, "tenant_b");
        tenant("tenant_default", TENANT_A, "14").migrate();

        // A V14 tenant already holding a rule configuration upgrades to V15 without losing it.
        execute("insert into tenant_default.cbom_rule_configurations (tenant_id, version_policy, pinned_version)"
                + " values ('" + TENANT_A + "', 'PINNED', '1.0.0')");
        tenant("tenant_default", TENANT_A, "19").migrate();
        assertEquals("19", tenant("tenant_default", TENANT_A, "19").info().current().getVersion().getVersion());
        assertEquals("CURRENT", queryText("select pin_state from tenant_default.cbom_rule_configurations"));
        assertEquals("1.0.0", queryText("select pinned_version from tenant_default.cbom_rule_configurations"));
        assertNull(queryText("select effective_version from tenant_default.cbom_rule_configurations"));
        assertThrows(SQLException.class, () -> execute(
                "update tenant_default.cbom_rule_configurations set pin_state = 'BOGUS'"));
        assertTrue(queryBoolean("select count(*) = 1 from information_schema.columns where table_schema = 'tenant_default'"
                + " and table_name = 'findings' and column_name = 'verification_status'"), "V13 verification columns");

        prepareNonSuperuserRole();
        for (String table : TABLES) {
            assertTrue(queryBoolean("select c.relrowsecurity and c.relforcerowsecurity from pg_class c"
                    + " join pg_namespace n on n.oid = c.relnamespace"
                    + " where n.nspname = 'tenant_default' and c.relname = '" + table + "'"), table + " must FORCE RLS");
            assertEquals(1, queryInt("select count(*) from pg_policies where schemaname = 'tenant_default'"
                    + " and tablename = '" + table + "' and policyname = 'tenant_isolation'"), table);
        }

        insertSettings(TENANT_B, TENANT_B);
        insertHistory(TENANT_A, TENANT_A);
        insertHistory(TENANT_B, TENANT_B);
        insertAvailability(TENANT_B, TENANT_B);

        assertEquals(1, queryIntAsTenant(TENANT_A, "select count(*) from tenant_default.cbom_rule_configurations"));
        assertEquals(0, queryIntAsTenant(TENANT_B, "select count(*) from tenant_default.cbom_rule_configurations"));
        assertEquals(0, queryIntAsTenant(TENANT_A, "select count(*) from tenant_default.cbom_tenant_settings"));
        assertEquals(1, queryIntAsTenant(TENANT_B, "select count(*) from tenant_default.cbom_tenant_settings"));
        assertEquals(1, queryIntAsTenant(TENANT_A, "select count(*) from tenant_default.cbom_rule_selection_history"));
        assertEquals(0, queryIntAsTenant(TENANT_A, "select count(*) from tenant_default.cbom_rule_availability"));
        assertEquals(1, queryIntAsTenant(TENANT_B, "select count(*) from tenant_default.cbom_rule_availability"));
        assertEquals(0, queryIntAsTenant(null, "select count(*) from tenant_default.cbom_rule_selection_history"));

        // WITH CHECK stops a tenant from writing rows attributed to another tenant.
        for (var attempt : new ThrowingRunnable[] {() -> insertSettings(TENANT_A, TENANT_B),
                () -> insertHistory(TENANT_A, TENANT_B), () -> insertAvailability(TENANT_A, TENANT_B)}) {
            SQLException spoof = assertThrows(SQLException.class, attempt::run);
            assertTrue(spoof.getMessage().toLowerCase().contains("row-level security"), spoof.getMessage());
        }

        leaseAdmitsOneOwnerAndResumesFromTheCommittedCursor();
    }

    private void leaseAdmitsOneOwnerAndResumesFromTheCommittedCursor() throws SQLException {
        DriverManagerDataSource dataSource = new DriverManagerDataSource(DATABASE.url(), DATABASE.username(), DATABASE.password());
        CbomRuleRolloutLeaseStore store = new CbomRuleRolloutLeaseStore(new JdbcTemplate(dataSource));
        String key = "scoutgrid-baseline@1.1.0";
        UUID cursor = UUID.fromString(TENANT_A);

        assertTrue(store.acquire(key, "owner-a", "CANARY", 300).isPresent());
        assertFalse(store.acquire(key, "owner-b", "CANARY", 300).isPresent(), "a live lease is exclusive");
        assertTrue(store.commitCursor(key, "owner-a", cursor, 7, 300));
        assertFalse(store.commitCursor(key, "owner-b", cursor, 1, 300), "a non-owner cannot advance the cursor");

        execute("update platform.cbom_rule_rollout_leases set lease_expires_at = now() - interval '1 second'");
        var resumed = store.acquire(key, "owner-b", "CANARY", 300).orElseThrow();
        assertEquals(cursor, resumed.cursorTenantId(), "the new owner resumes from the committed cursor");
        assertFalse(store.commitCursor(key, "owner-a", cursor, 1, 300), "the expired owner lost the lease");

        var advanced = store.acquire(key, "owner-b", "BATCHED", 300).orElseThrow();
        assertNull(advanced.cursorTenantId(), "a stage change restarts the cursor");
        assertTrue(store.completePass(key, "owner-b"));
        store.release(key, "owner-b");
        var status = store.list().get(0);
        assertNull(status.owner());
        assertEquals("BATCHED", status.completedStage());
        assertEquals(7, status.jobsEnqueued());
        assertEquals(1, status.tenantsProcessed());
    }

    @FunctionalInterface
    private interface ThrowingRunnable { void run() throws SQLException; }

    private void insertSettings(String sessionTenant, String rowTenant) throws SQLException {
        asTenant(sessionTenant, "insert into tenant_default.cbom_tenant_settings (tenant_id) values (?::uuid)", rowTenant);
    }

    private void insertHistory(String sessionTenant, String rowTenant) throws SQLException {
        asTenant(sessionTenant, "insert into tenant_default.cbom_rule_selection_history"
                + " (id, tenant_id, package_id, action, version_policy, actor, reason)"
                + " values (gen_random_uuid(), ?::uuid, 'scoutgrid-baseline', 'TENANT_UPDATE', 'FOLLOW_LATEST', 'admin', 'test')", rowTenant);
    }

    private void insertAvailability(String sessionTenant, String rowTenant) throws SQLException {
        asTenant(sessionTenant, "insert into tenant_default.cbom_rule_availability"
                + " (tenant_id, package_id, package_version, package_digest, evaluator_major, rollout_stage, status)"
                + " values (?::uuid, 'scoutgrid-baseline', '1.0.0', 'sha256:x', 1, 'GENERAL', 'EFFECTIVE')", rowTenant);
    }

    private void asTenant(String sessionTenant, String sql, String rowTenant) throws SQLException {
        try (Connection connection = connection()) {
            enterTenantContext(connection, sessionTenant);
            try (PreparedStatement statement = connection.prepareStatement(sql)) {
                statement.setString(1, rowTenant);
                statement.executeUpdate();
            }
        }
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

    private void prepareNonSuperuserRole() throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.execute("do $$ begin"
                    + " if not exists (select 1 from pg_roles where rolname = '" + RLS_ROLE + "') then"
                    + "   create role " + RLS_ROLE + " nosuperuser nobypassrls;"
                    + " end if;"
                    + " end $$");
            statement.execute("grant usage on schema platform, tenant_default to " + RLS_ROLE);
            statement.execute("grant select, references on all tables in schema platform to " + RLS_ROLE);
            statement.execute("grant select, insert, update, delete on all tables in schema tenant_default to " + RLS_ROLE);
        }
    }

    private void enterTenantContext(Connection connection, String tenantId) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("set role " + RLS_ROLE);
        }
        try (PreparedStatement statement = connection.prepareStatement("select set_config('app.current_tenant_id', ?, false)")) {
            statement.setString(1, tenantId == null ? "" : tenantId);
            statement.execute();
        }
    }

    private void registerTenant(String id, String schema) throws SQLException {
        try (Connection connection = connection(); PreparedStatement statement = connection.prepareStatement(
                "insert into platform.tenants ("
                        + " id,created_at,max_connector_count,max_daily_exposure_refreshes,max_daily_sbom_uploads,"
                        + " max_export_rows,max_service_account_count,name,plan_code,schema_name,slug,status,updated_at)"
                        + " values (?::uuid,now(),10,10,10,10000,10,'Isolation tenant','pilot',?,?,'ACTIVE',now())")) {
            statement.setString(1, id);
            statement.setString(2, schema);
            statement.setString(3, schema.replace('_', '-'));
            statement.executeUpdate();
        }
    }

    private void execute(String sql) throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.execute(sql);
        }
    }

    private int queryInt(String sql) throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }

    private boolean queryBoolean(String sql) throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getBoolean(1);
        }
    }

    private String queryText(String sql) throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getString(1);
        }
    }

    private int queryIntAsTenant(String tenantId, String sql) throws SQLException {
        try (Connection connection = connection()) {
            enterTenantContext(connection, tenantId);
            try (Statement statement = connection.createStatement(); ResultSet resultSet = statement.executeQuery(sql)) {
                resultSet.next();
                return resultSet.getInt(1);
            }
        }
    }
}
