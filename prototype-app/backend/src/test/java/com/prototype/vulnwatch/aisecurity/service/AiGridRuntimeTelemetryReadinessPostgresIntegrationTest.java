package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.migration.PackagedMigrationCatalog;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AiGridRuntimeTelemetryReadinessPostgresIntegrationTest {
    private static final UUID TENANT_ID = UUID.fromString("e5fe0d29-1d64-4175-8ce6-c34f42b214cc");
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_grid_runtime_readiness");

    @Test
    @SuppressWarnings("unchecked")
    void executesOperationalDashboardQueryOnBaselineAndExplicitTestSources() throws Exception {
        migrate();
        try (Connection connection = DriverManager.getConnection(
                DATABASE.url(), DATABASE.username(), DATABASE.password())) {
            int tenantTarget = PackagedMigrationCatalog.resolve().tenantTarget();
            try (Statement statement = connection.createStatement()) {
                statement.execute("set search_path to tenant_default,platform,public");
            }
            try (PreparedStatement statement = connection.prepareStatement(
                    "select set_config('app.current_tenant_id', ?, false)")) {
                statement.setString(1, TENANT_ID.toString());
                statement.execute();
            }
            try (PreparedStatement statement = connection.prepareStatement("""
                        insert into platform.tenant_schema_versions
                            (tenant_id,schema_name,current_version,target_version,status,last_successful_version)
                        values (?,'tenant_default',?,?, 'CURRENT',?)
                        on conflict (tenant_id) do update set current_version=excluded.current_version,
                            target_version=excluded.target_version, status='CURRENT',
                            last_successful_version=excluded.last_successful_version
                        """)) {
                statement.setObject(1, TENANT_ID);
                statement.setInt(2, tenantTarget);
                statement.setInt(3, tenantTarget);
                statement.setInt(4, tenantTarget);
                statement.executeUpdate();
            }
            NamedParameterJdbcTemplate jdbc =
                    new NamedParameterJdbcTemplate(new SingleConnectionDataSource(connection, true));
            TenantSchemaExecutionService execution = mock(TenantSchemaExecutionService.class);
            when(execution.run(any(Tenant.class), any(Supplier.class)))
                    .thenAnswer(invocation -> invocation.getArgument(1, Supplier.class).get());
            Tenant tenant = new Tenant();
            tenant.setId(TENANT_ID);
            tenant.setSchemaName("tenant_default");

            var service = new AiGridRuntimeTelemetryReadinessService(
                    jdbc, execution, new PackagedMigrationCatalog());
            var readiness = service.readiness(tenant);

            assertEquals(true, readiness.available());
            assertFalse(readiness.program2EntryGateMet());
            assertEquals(0, readiness.providers().size(),
                    "the V1 baseline must not activate runtime telemetry sources");

            // Keep exercising the populated dashboard query without enabling production seeds.
            jdbc.update("""
                    insert into ai_runtime_source_configurations
                        (source_id,tenant_id,provider,source_kind,required_for_program_gate,status)
                    values ('AZURE_FOUNDRY_RUNTIME',:tenantId,'AZURE','PROVIDER_CONNECTOR',true,'ACTIVE'),
                           ('COPILOT_STUDIO_RUNTIME',:tenantId,'MICROSOFT_COPILOT','PROVIDER_CONNECTOR',true,'ACTIVE')
                    """, Map.of("tenantId", TENANT_ID));
            readiness = service.readiness(tenant);
            assertFalse(readiness.program2EntryGateMet());
            assertEquals(2, readiness.providers().size());
            assertEquals(java.util.List.of("AZURE_FOUNDRY_RUNTIME", "COPILOT_STUDIO_RUNTIME"),
                    readiness.providers().stream().map(
                            AiGridRuntimeTelemetryReadinessService.SourceReadiness::sourceId).toList());
        }
    }

    private void migrate() {
        Flyway.configure().configuration(java.util.Map.of("flyway.postgresql.transactional.lock", "false")).dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public").locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .validateOnMigrate(true).load().migrate();
        Flyway.configure().dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .schemas("tenant_default").defaultSchema("tenant_default").table("tenant_schema_history")
                .locations("filesystem:src/main/resources/db/migration/tenant")
                .placeholders(Map.of("tenantSchema", "tenant_default", "tenantId", TENANT_ID.toString()))
                .target(Integer.toString(PackagedMigrationCatalog.resolve().tenantTarget()))
                .validateOnMigrate(true).load().migrate();
    }
}
