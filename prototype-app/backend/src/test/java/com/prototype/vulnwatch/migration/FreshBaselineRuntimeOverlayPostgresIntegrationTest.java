package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.prototype.vulnwatch.aisecurity.service.AiAgentExecutionRelationshipProjectionService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class FreshBaselineRuntimeOverlayPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("fresh_baseline_runtime_overlay");
    private static final UUID TENANT_ID = UUID.fromString("e5fe0d29-1d64-4175-8ce6-c34f42b214cc");

    @Test
    void freshBaselineServesAnEmptyRuntimeOverlay() throws Exception {
        Flyway.configure().configuration(java.util.Map.of("flyway.postgresql.transactional.lock", "false")).dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public").locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .load().migrate();
        Flyway tenant = Flyway.configure().dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .schemas("tenant_default").defaultSchema("tenant_default").table("tenant_schema_history")
                .locations("filesystem:src/main/resources/db/migration/tenant")
                .placeholders(Map.of("tenantId", TENANT_ID.toString(), "tenantSchema", "tenant_default"))
                .load();
        tenant.migrate();
        assertEquals(Integer.toString(PackagedMigrationCatalog.resolve().tenantTarget()),
                tenant.info().current().getVersion().getVersion());

        try (Connection connection = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password())) {
            try (Statement statement = connection.createStatement()) {
                statement.execute("set search_path to tenant_default,platform,public");
            }
            try (PreparedStatement preparedStatement =
                         connection.prepareStatement("select set_config('app.current_tenant_id', ?, false)")) {
                preparedStatement.setString(1, TENANT_ID.toString());
                preparedStatement.execute();
            }
            var service = new AiAgentExecutionRelationshipProjectionService(
                    new NamedParameterJdbcTemplate(new SingleConnectionDataSource(connection, true)));
            var overlay = service.aggregate(TENANT_ID, UUID.randomUUID(), Instant.now().minusSeconds(3600), Instant.now());
            assertEquals("AVAILABLE", overlay.status());
            assertEquals(0, overlay.executionCount());
            assertFalse(overlay.truncated());
        }
    }
}
