package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import com.prototype.vulnwatch.service.TenantSchemaService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.Statement;
import java.util.Map;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.SingleConnectionDataSource;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class TenantSchemaParityPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("tenant_schema_staged_parity");
    private static final UUID DEFAULT_ID = UUID.fromString("e5fe0d29-1d64-4175-8ce6-c34f42b214cc");
    private static final UUID LEGACY_ID = UUID.nameUUIDFromBytes("parity-legacy".getBytes());

    @Test
    void freshAndProvisionedTenantsReachIdenticalPackagedTenantTarget() throws Exception {
        platformFlyway().migrate();

        try (Connection connection = connection()) {
            TenantSchemaService schemas = new TenantSchemaService(
                    new JdbcTemplate(new SingleConnectionDataSource(connection, true)), "tenant_default");
            schemas.provisionOrReconcileSchemaFromTemplate("tenant_parity_legacy");
            registerTenant(connection, LEGACY_ID, "Parity Legacy", "parity-legacy", "tenant_parity_legacy");
        }

        int target = PackagedMigrationCatalog.resolve().tenantTarget();
        assertEquals(target, migrateTenant("tenant_default", DEFAULT_ID));
        assertEquals(target, migrateTenant("tenant_parity_legacy", LEGACY_ID));

        try (Connection connection = connection()) {
            assertEquals(TenantSchemaFingerprint.of(connection, "tenant_default"),
                    TenantSchemaFingerprint.of(connection, "tenant_parity_legacy"));
            try (Statement statement = connection.createStatement()) {
                statement.execute("alter table tenant_default.assets add column platform_owned_mutation_probe text");
            }
            assertNotEquals(TenantSchemaFingerprint.of(connection, "tenant_default"),
                    TenantSchemaFingerprint.of(connection, "tenant_parity_legacy"));
        }
    }

    private int migrateTenant(String schema, UUID tenantId) {
        Flyway flyway = Flyway.configure()
                .dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .schemas(schema)
                .defaultSchema(schema)
                .table("tenant_schema_history")
                .locations("filesystem:src/main/resources/db/migration/tenant")
                .placeholders(Map.of("tenantId", tenantId.toString(), "tenantSchema", schema))
                .validateOnMigrate(true)
                .outOfOrder(false)
                .load();
        flyway.migrate();
        return Integer.parseInt(flyway.info().current().getVersion().getVersion());
    }

    private Flyway platformFlyway() {
        var configuration = Flyway.configure().configuration(java.util.Map.of("flyway.postgresql.transactional.lock", "false"))
                .dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public")
                .locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .validateOnMigrate(true)
                .outOfOrder(false);
        return configuration.load();
    }

    private Connection connection() throws Exception {
        return DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
    }

    private void registerTenant(Connection connection, UUID id, String name, String slug, String schema)
            throws Exception {
        try (PreparedStatement statement = connection.prepareStatement("""
                insert into platform.tenants (
                    id, created_at, max_connector_count, max_daily_exposure_refreshes,
                    max_daily_sbom_uploads, max_export_rows, max_service_account_count,
                    name, plan_code, schema_name, slug, status, updated_at
                ) values (?, now(), 10, 10, 10, 10000, 10, ?, 'pilot', ?, ?, 'ACTIVE', now())
                """)) {
            statement.setObject(1, id);
            statement.setString(2, name);
            statement.setString(3, schema);
            statement.setString(4, slug);
            statement.executeUpdate();
        }
    }
}
