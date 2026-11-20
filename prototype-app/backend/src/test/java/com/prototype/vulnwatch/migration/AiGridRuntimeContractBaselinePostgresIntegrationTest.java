package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.Map;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AiGridRuntimeContractBaselinePostgresIntegrationTest {
    private static final String UPGRADE_TENANT_ID = "e5fe0d29-1d64-4175-8ce6-c34f42b214cc";
    private static final String FRESH_TENANT_ID = "00000000-0000-4000-8000-000000000303";
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_grid_runtime_v3_migration");

    @Test
    void freshBaselineRetainsDeferredSchemaWithoutRuntimeEvidenceOrSources() throws Exception {
        platform("1").migrate();
        registerTenant(FRESH_TENANT_ID, "tenant_fresh");
        tenant("tenant_default", UPGRADE_TENANT_ID, "1").migrate();
        tenant("tenant_fresh", FRESH_TENANT_ID, "1").migrate();
        assertEquals(0, queryInt("select count(*) from tenant_default.ai_agent_executions"));
        assertEquals(0, queryInt("select count(*) from tenant_default.ai_runtime_source_configurations"));
        assertEquals(4, queryInt("""
                select count(*) from information_schema.tables
                 where table_schema='tenant_default' and table_name in
                    ('ai_runtime_evidence_producers','ai_runtime_source_configurations',
                     'ai_runtime_quota_windows','ai_runtime_ingestion_receipts')
                """));
        assertEquals(2, queryInt("""
                select count(*) from platform.ai_grid_runtime_field_definitions
                 where field_key in ('event.approval_state','event.action_outcome') and predicate_eligible
                """));
        try (Connection connection = connection()) {
            assertEquals(TenantSchemaFingerprint.of(connection, "tenant_fresh"),
                    TenantSchemaFingerprint.of(connection, "tenant_default"));
        }
    }

    private Flyway platform(String target) {
        return Flyway.configure().configuration(java.util.Map.of("flyway.postgresql.transactional.lock", "false")).dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public").locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .target(target).validateOnMigrate(true).load();
    }

    private Flyway tenant(String schema, String tenantId, String target) {
        return Flyway.configure().dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .schemas(schema).defaultSchema(schema).table("tenant_schema_history")
                .locations("filesystem:src/main/resources/db/migration/tenant")
                .placeholders(Map.of("tenantSchema", schema, "tenantId", tenantId))
                .target(target).validateOnMigrate(true).load();
    }

    private Connection connection() throws Exception {
        return DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
    }

    private void execute(String sql) throws Exception {
        try (Connection connection = connection(); Statement statement = connection.createStatement()) {
            statement.execute("select set_config('app.current_tenant_id','" + UPGRADE_TENANT_ID + "',false)");
            statement.execute(sql);
        }
    }

    private void registerTenant(String id, String schema) throws Exception {
        try (Connection connection = connection(); PreparedStatement statement = connection.prepareStatement("""
                insert into platform.tenants (
                    id,created_at,max_connector_count,max_daily_exposure_refreshes,max_daily_sbom_uploads,
                    max_export_rows,max_service_account_count,name,plan_code,schema_name,slug,status,updated_at)
                values (?::uuid,now(),10,10,10,10000,10,'Fresh V3 tenant','pilot',?,?,'ACTIVE',now())
                """)) {
            statement.setString(1, id);
            statement.setString(2, schema);
            statement.setString(3, schema.replace('_', '-'));
            statement.executeUpdate();
        }
    }

    private int queryInt(String sql) throws Exception {
        try (Connection connection = connection(); Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            result.next();
            return result.getInt(1);
        }
    }
}
