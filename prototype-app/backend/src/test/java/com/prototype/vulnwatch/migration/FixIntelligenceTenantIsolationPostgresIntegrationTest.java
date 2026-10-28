package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
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
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Proves every Fix Intelligence and patch management table added in tenant V9 is forced behind
 * row-level security, against a real database and as a non-superuser.
 */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class FixIntelligenceTenantIsolationPostgresIntegrationTest {

    private static final String TENANT_A = "e5fe0d29-1d64-4175-8ce6-c34f42b214cc";
    private static final String TENANT_B = "00000000-0000-4000-8000-000000000909";
    private static final String RLS_ROLE = "fix_intelligence_rls_role";
    private static final String[] TABLES = {"fix_records", "fix_record_cves", "fix_patch_details", "fix_control_details",
            "device_identities", "patch_deployments", "fix_assets", "fix_asset_events", "patch_connector_configs"};
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("fix_intelligence_isolation");

    @Test
    void v9TablesAreForcedBehindRowLevelSecurityAndCannotCrossTenants() throws Exception {
        platform().migrate();
        registerTenant(TENANT_B, "tenant_b");
        tenant("tenant_default", TENANT_A, "9").migrate();
        prepareNonSuperuserRole();

        for (String table : TABLES) {
            assertTrue(queryBoolean("select c.relrowsecurity and c.relforcerowsecurity from pg_class c"
                    + " join pg_namespace n on n.oid = c.relnamespace"
                    + " where n.nspname = 'tenant_default' and c.relname = '" + table + "'"), table + " must FORCE RLS");
            assertEquals(1, queryInt("select count(*) from pg_policies where schemaname = 'tenant_default'"
                    + " and tablename = '" + table + "' and policyname = 'tenant_isolation'"), table);
        }

        insertConnector(TENANT_A, TENANT_A, "BIGFIX");
        insertConnector(TENANT_B, TENANT_B, "TANIUM");

        assertEquals("BIGFIX", queryTextAsTenant(TENANT_A, "select provider from tenant_default.patch_connector_configs"));
        assertEquals(1, queryIntAsTenant(TENANT_B, "select count(*) from tenant_default.patch_connector_configs"));
        assertEquals("TANIUM", queryTextAsTenant(TENANT_B, "select provider from tenant_default.patch_connector_configs"));

        // WITH CHECK stops a tenant from writing a row attributed to another tenant.
        SQLException spoof = assertThrows(SQLException.class, () -> insertConnector(TENANT_A, TENANT_B, "INTUNE"));
        assertTrue(spoof.getMessage().toLowerCase().contains("row-level security"), spoof.getMessage());

        // No tenant context matches nothing.
        assertEquals(0, queryIntAsTenant(null, "select count(*) from tenant_default.patch_connector_configs"));
    }

    private void insertConnector(String sessionTenant, String rowTenant, String provider) throws SQLException {
        try (Connection connection = connection()) {
            enterTenantContext(connection, sessionTenant);
            try (PreparedStatement statement = connection.prepareStatement(
                    "insert into tenant_default.patch_connector_configs (tenant_id, provider, credential_secret)"
                            + " values (?::uuid, ?, 'encrypted')")) {
                statement.setString(1, rowTenant);
                statement.setString(2, provider);
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

    /**
     * A role with neither superuser nor BYPASSRLS, so the policy is genuinely enforced against
     * it. Created without LOGIN because the tests reach it through {@code SET ROLE}.
     */
    private void prepareNonSuperuserRole() throws SQLException {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.execute(
                    "do $$ begin"
                            + " if not exists (select 1 from pg_roles where rolname = '" + RLS_ROLE + "') then"
                            + "   create role " + RLS_ROLE + " nosuperuser nobypassrls;"
                            + " end if;"
                            + " end $$");
            statement.execute("grant usage on schema platform, tenant_default to " + RLS_ROLE);
            statement.execute("grant select, references on all tables in schema platform to " + RLS_ROLE);
            statement.execute(
                    "grant select, insert, update, delete on all tables in schema tenant_default to " + RLS_ROLE);
        }
    }

    /**
     * Drops to the non-superuser role and pins the tenant, mirroring how the application
     * configures its connections. A null tenant leaves the setting empty.
     */
    private void enterTenantContext(Connection connection, String tenantId) throws SQLException {
        try (Statement statement = connection.createStatement()) {
            statement.execute("set role " + RLS_ROLE);
        }
        try (PreparedStatement statement =
                     connection.prepareStatement("select set_config('app.current_tenant_id', ?, false)")) {
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

    private int queryIntAsTenant(String tenantId, String sql) throws SQLException {
        try (Connection connection = connection()) {
            enterTenantContext(connection, tenantId);
            try (Statement statement = connection.createStatement();
                 ResultSet resultSet = statement.executeQuery(sql)) {
                resultSet.next();
                return resultSet.getInt(1);
            }
        }
    }

    private String queryTextAsTenant(String tenantId, String sql) throws SQLException {
        try (Connection connection = connection()) {
            enterTenantContext(connection, tenantId);
            try (Statement statement = connection.createStatement();
                 ResultSet resultSet = statement.executeQuery(sql)) {
                resultSet.next();
                return resultSet.getString(1);
            }
        }
    }
}
