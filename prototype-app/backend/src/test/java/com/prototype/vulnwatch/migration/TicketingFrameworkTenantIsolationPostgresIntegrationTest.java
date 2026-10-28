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
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

/**
 * Proves the ticketing framework's tenant isolation against a real database rather than
 * trusting the migration's SQL.
 *
 * <p>Two properties matter. Row-level security has to be <em>forced</em>, because the
 * application connects as the schema owner and unforced RLS is silently bypassed for owners.
 * And the {@code incident_provider} backfill has to land on every pre-existing ticket, or
 * historical ServiceNow incidents lose their status sync the moment a tenant enables Jira.
 *
 * <p>Every isolation assertion runs after {@code SET ROLE} to a non-superuser role. Postgres
 * exempts superusers and {@code BYPASSRLS} roles even from forced RLS, and the local
 * development account is a superuser — so querying as the connecting user would report the
 * table as perfectly isolated no matter what the policy said, and prove nothing.
 */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class TicketingFrameworkTenantIsolationPostgresIntegrationTest {

    private static final String TENANT_A = "e5fe0d29-1d64-4175-8ce6-c34f42b214cc";
    private static final String TENANT_B = "00000000-0000-4000-8000-000000000404";
    private static final String RLS_ROLE = "ticketing_rls_role";
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ticketing_framework_isolation");

    @Test
    void jiraConnectorRowsAreForcedBehindRowLevelSecurityAndCannotCrossTenants() throws Exception {
        platform().migrate();
        registerTenant(TENANT_B, "tenant_b");
        tenant("tenant_default", TENANT_A, "7").migrate();
        prepareNonSuperuserRole();

        // Unforced RLS would leave the owning role able to read every tenant's credentials.
        assertTrue(queryBoolean(
                "select c.relrowsecurity from pg_class c join pg_namespace n on n.oid = c.relnamespace"
                        + " where n.nspname = 'tenant_default' and c.relname = 'jira_ticketing_configs'"),
                "row level security should be enabled on jira_ticketing_configs");
        assertTrue(queryBoolean(
                "select c.relforcerowsecurity from pg_class c join pg_namespace n on n.oid = c.relnamespace"
                        + " where n.nspname = 'tenant_default' and c.relname = 'jira_ticketing_configs'"),
                "row level security should be FORCED on jira_ticketing_configs");
        assertEquals(1, queryInt(
                "select count(*) from pg_policies where schemaname = 'tenant_default'"
                        + " and tablename = 'jira_ticketing_configs' and policyname = 'tenant_isolation'"));

        insertJiraConfig(TENANT_A, TENANT_A, "SEC");
        insertJiraConfig(TENANT_B, TENANT_B, "OPS");

        // Each tenant sees only its own connector, never the other's project or token.
        assertEquals(1, queryIntAsTenant(TENANT_A, "select count(*) from tenant_default.jira_ticketing_configs"));
        assertEquals("SEC", queryTextAsTenant(TENANT_A,
                "select project_key from tenant_default.jira_ticketing_configs"));
        assertEquals(1, queryIntAsTenant(TENANT_B, "select count(*) from tenant_default.jira_ticketing_configs"));
        assertEquals("OPS", queryTextAsTenant(TENANT_B,
                "select project_key from tenant_default.jira_ticketing_configs"));

        // The policy's WITH CHECK must also stop a write attributed to another tenant.
        SQLException crossTenantWrite = assertThrows(SQLException.class,
                () -> insertJiraConfig(TENANT_A, TENANT_B, "SPOOF"));
        assertTrue(crossTenantWrite.getMessage().toLowerCase().contains("row-level security"),
                "expected a row level security violation, got: " + crossTenantWrite.getMessage());

        // No tenant context resolves the policy to NULL, so the table reads as empty.
        assertEquals(0, queryIntAsTenant(null, "select count(*) from tenant_default.jira_ticketing_configs"));
    }

    @Test
    void existingTicketsAreBackfilledToServiceNowAndUnticketedFindingsAreLeftAlone() throws Exception {
        platform().migrate();
        // Stop at V6 so the findings exist exactly as they would before this feature shipped.
        tenant("tenant_default", TENANT_A, "6").migrate();
        prepareNonSuperuserRole();
        insertFinding("F-TICKETED01", "INC0010005");
        insertFinding("F-UNTICKETED", null);

        tenant("tenant_default", TENANT_A, "7").migrate();

        assertEquals("servicenow", queryTextAsTenant(TENANT_A,
                "select incident_provider from tenant_default.findings where display_id = 'F-TICKETED01'"));
        // A finding with no ticket must not be attributed to a system it never reached.
        assertNull(queryTextAsTenant(TENANT_A,
                "select incident_provider from tenant_default.findings where display_id = 'F-UNTICKETED'"));
    }

    private void insertJiraConfig(String sessionTenantId, String rowTenantId, String projectKey) throws SQLException {
        try (Connection connection = connection()) {
            enterTenantContext(connection, sessionTenantId);
            try (PreparedStatement statement = connection.prepareStatement(
                    "insert into tenant_default.jira_ticketing_configs"
                            + " (id, tenant_id, base_url, auth_type, username, credential_secret,"
                            + "  project_key, issue_type_name, include_priority, enabled)"
                            + " values (gen_random_uuid(), ?::uuid, 'https://example.atlassian.net', 'BASIC',"
                            + "         'bot@example.test', 'encrypted-token', ?, 'Task', true, true)")) {
                statement.setString(1, rowTenantId);
                statement.setString(2, projectKey);
                statement.executeUpdate();
            }
        }
    }

    /** An AI posture finding avoids the vulnerability subject check and its foreign keys. */
    private void insertFinding(String displayId, String incidentId) throws SQLException {
        try (Connection connection = connection()) {
            enterTenantContext(connection, TENANT_A);
            try (PreparedStatement statement = connection.prepareStatement(
                    "insert into tenant_default.findings"
                            + " (id, tenant_id, created_at, updated_at, creation_source, display_id,"
                            + "  matched_by, risk_score, status, finding_kind, incident_id, incident_status)"
                            + " values (gen_random_uuid(), ?::uuid, now(), now(), 'AI_SECURITY', ?,"
                            + "         'AI_SECURITY', 5.0, 'OPEN', 'AI_POSTURE', ?, ?)")) {
                statement.setString(1, TENANT_A);
                statement.setString(2, displayId);
                statement.setString(3, incidentId);
                statement.setString(4, incidentId == null ? null : "New");
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
