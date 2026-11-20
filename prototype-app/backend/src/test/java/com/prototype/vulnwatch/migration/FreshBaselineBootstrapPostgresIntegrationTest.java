package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class FreshBaselineBootstrapPostgresIntegrationTest {

    private static final String CURRENT_SCHEMA_VERSION = Integer.toString(
            PackagedMigrationCatalog.resolve().platformTarget());
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("fresh_baseline_bootstrap");

    @Test
    void canApplyResetBaselineWithoutHistoricalMigrations() throws Exception {
        Flyway flyway = configuredFlyway();
        flyway.migrate();

        assertNotNull(flyway.info().current());
        assertEquals(CURRENT_SCHEMA_VERSION, flyway.info().current().getVersion().getVersion());
        assertEquals(0, flyway.info().pending().length);
        assertEquals(0, failedCount());
        assertEquals(1, historyCount("1"));
        org.junit.jupiter.api.Assertions.assertTrue(queryForInt(DATABASE, "select count(*) from platform.ai_grid_policy_versions") > 0);
        assertEquals(1, queryForInt(DATABASE, "select count(*) from information_schema.schemata where schema_name='tenant_default'"));
        assertEquals(6, queryForInt(DATABASE, """
                select count(*) from platform.ai_grid_release_manifest_items
                 where release_id='R2' and subject_type='CORRELATION' and subject_version='2.0.0'
                """));
        assertEquals(0, queryForInt(DATABASE, """
                select count(*) from platform.ai_grid_release_manifest_items
                 where release_id='R2' and subject_type='CORRELATION' and subject_version='1.0.0'
                """));
        assertEquals(1, queryForInt(DATABASE, "select count(*) from platform.ai_grid_policy_versions where policy_id='AWS_BEDROCK_WEAK_GUARDRAIL'"));
        assertEquals(1, queryForInt(DATABASE, "select count(*) from platform.ai_grid_capability_definitions where capability_id='COPILOT_STUDIO_METADATA'"));
        assertEquals(0, queryForInt(DATABASE, """
                select count(*) from pg_class c join pg_namespace n on n.oid=c.relnamespace
                 where n.nspname='platform' and c.relname in
                       ('ai_grid_policy_migration_ledger','ai_grid_phase_1_tenant_migration_audit')
                """));
    }

    @Test
    void tenantDefaultCanBeMigratedFromTheEmptyPlatformBaseline() throws Exception {
        configuredFlyway().migrate();
        Flyway tenant = Flyway.configure()
                .dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .schemas("tenant_default")
                .defaultSchema("tenant_default")
                .table("tenant_schema_history")
                .locations("filesystem:src/main/resources/db/migration/tenant")
                .placeholders(java.util.Map.of(
                        "tenantSchema", "tenant_default",
                        "tenantId", "e5fe0d29-1d64-4175-8ce6-c34f42b214cc"))
                .validateOnMigrate(true)
                .outOfOrder(false)
                .load();
        tenant.migrate();
        assertEquals(Integer.toString(PackagedMigrationCatalog.resolve().tenantTarget()),
                tenant.info().current().getVersion().getVersion());
    }

    private Flyway configuredFlyway() {
        var config = Flyway.configure().configuration(java.util.Map.of("flyway.postgresql.transactional.lock", "false"))
                .dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public")
                .locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .validateOnMigrate(true)
                .outOfOrder(false);
        return config.load();
    }

    private int historyCount(String version) throws SQLException {
        return queryForInt("select count(*) from flyway_schema_history where version = '" + version + "' and success = true");
    }

    private int failedCount() throws SQLException {
        return queryForInt("select count(*) from flyway_schema_history where success = false");
    }

    private int queryForInt(String sql) throws SQLException {
        return queryForInt(DATABASE, sql);
    }

    private int queryForInt(LocalPostgresTestDatabase.DatabaseConfig database, String sql) throws SQLException {
        try (Connection connection = DriverManager.getConnection(database.url(), database.username(), database.password());
             Statement statement = connection.createStatement();
             ResultSet resultSet = statement.executeQuery(sql)) {
            resultSet.next();
            return resultSet.getInt(1);
        }
    }

}
