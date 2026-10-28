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
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Proves the GCP discovery tables are forced behind row-level security against a real database.
 *
 * <p>Assertions run after {@code SET ROLE} to a non-superuser, because superusers bypass even
 * forced RLS and would make any policy look correct.
 */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class GcpDiscoveryTenantIsolationPostgresIntegrationTest {

    private static final String TENANT_A = "e5fe0d29-1d64-4175-8ce6-c34f42b214cc";
    private static final String TENANT_B = "00000000-0000-4000-8000-000000000505";
    private static final String RLS_ROLE = "gcp_discovery_rls_role";
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("gcp_discovery_isolation");

    @Test
    void gcpConnectorTablesAreForcedBehindRowLevelSecurityAndCannotCrossTenants() throws Exception {
        platform().migrate();
        registerTenant(TENANT_B, "tenant_b");
        tenant("tenant_default", TENANT_A, "8").migrate();
        prepareNonSuperuserRole();

        for (String table : new String[]{"gcp_discovery_configs", "gcp_discovery_targets"}) {
            assertTrue(queryBoolean("select c.relforcerowsecurity from pg_class c join pg_namespace n on n.oid = c.relnamespace"
                    + " where n.nspname = 'tenant_default' and c.relname = '" + table + "'"), table + " must FORCE RLS");
            assertEquals(1, queryInt("select count(*) from pg_policies where schemaname = 'tenant_default'"
                    + " and tablename = '" + table + "' and policyname = 'tenant_isolation'"));
        }

        UUID configA = insertConfig(TENANT_A, TENANT_A, "reader@acme-prod.iam.gserviceaccount.com");
        UUID configB = insertConfig(TENANT_B, TENANT_B, "reader@other-prod.iam.gserviceaccount.com");
        insertTarget(TENANT_A, TENANT_A, configA, "acme-prod");
        insertTarget(TENANT_B, TENANT_B, configB, "other-prod");

        // Each tenant sees only its own key and projects.
        assertEquals("reader@acme-prod.iam.gserviceaccount.com", queryTextAsTenant(TENANT_A,
                "select service_account_email from tenant_default.gcp_discovery_configs"));
        assertEquals(1, queryIntAsTenant(TENANT_A, "select count(*) from tenant_default.gcp_discovery_targets"));
        assertEquals("other-prod", queryTextAsTenant(TENANT_B, "select project_id from tenant_default.gcp_discovery_targets"));

        // WITH CHECK stops a tenant from writing a row attributed to another tenant.
        SQLException spoof = assertThrows(SQLException.class, () -> insertTarget(TENANT_A, TENANT_B, configB, "spoofed"));
        assertTrue(spoof.getMessage().toLowerCase().contains("row-level security"), spoof.getMessage());

        // No tenant context matches nothing.
        assertEquals(0, queryIntAsTenant(null, "select count(*) from tenant_default.gcp_discovery_configs"));
    }

    private UUID insertConfig(String sessionTenant, String rowTenant, String email) throws SQLException {
        UUID id = UUID.randomUUID();
        try (Connection connection = connection()) {
            enterTenantContext(connection, sessionTenant);
            try (PreparedStatement statement = connection.prepareStatement(
                    "insert into tenant_default.gcp_discovery_configs (id, tenant_id, service_account_email,"
                            + " credential_secret) values (?, ?::uuid, ?, 'encrypted-key')")) {
                statement.setObject(1, id);
                statement.setString(2, rowTenant);
                statement.setString(3, email);
                statement.executeUpdate();
            }
        }
        return id;
    }

    private void insertTarget(String sessionTenant, String rowTenant, UUID configId, String projectId) throws SQLException {
        try (Connection connection = connection()) {
            enterTenantContext(connection, sessionTenant);
            try (PreparedStatement statement = connection.prepareStatement(
                    "insert into tenant_default.gcp_discovery_targets (id, tenant_id, config_id, project_id, resource_types_json)"
                            + " values (gen_random_uuid(), ?::uuid, ?, ?, '[]')")) {
                statement.setString(1, rowTenant);
                statement.setObject(2, configId);
                statement.setString(3, projectId);
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
