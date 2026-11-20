package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class AiGridFrameworkCoverageMigrationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_grid_framework_coverage_migration");

    @Test
    void repeatBaselineMigrationPreservesPublishedPackagesAndDistributionBindings() throws Exception {
        Flyway v1 = flyway("1");
        v1.migrate();
        String packagesBefore = packageRowsDigest();

        Flyway current = flyway("1");
        current.migrate();

        assertEquals(packagesBefore, packageRowsDigest(),
                "A framework-registry migration must not mutate immutable policy-version rows");
        assertEquals(0, queryInt("""
                select count(*)
                  from platform.ai_grid_policy_distribution d
                  join platform.ai_grid_policy_versions p
                    on p.policy_id=d.policy_id and p.version=d.pinned_version
                 where d.available=true
                   and d.approved_package_digest is not null
                   and d.approved_package_digest <> p.package_digest
                """), "Every approved active distribution must remain bound to its pinned package digest");
    }

    private Flyway flyway(String target) {
        return Flyway.configure().configuration(java.util.Map.of("flyway.postgresql.transactional.lock", "false"))
                .dataSource(DATABASE.url(), DATABASE.username(), DATABASE.password())
                .defaultSchema("public")
                .locations("filesystem:src/main/resources/db/migration/postgres_reset")
                .target(target)
                .validateOnMigrate(true)
                .outOfOrder(false)
                .load();
    }

    private String packageRowsDigest() throws Exception {
        return queryString("""
                select md5(coalesce(string_agg(row_to_json(p)::text, E'\\n' order by p.policy_id,p.version),''))
                  from platform.ai_grid_policy_versions p
                """);
    }

    private int queryInt(String sql) throws Exception {
        return Integer.parseInt(queryString(sql));
    }

    private String queryString(String sql) throws Exception {
        try (Connection connection = DriverManager.getConnection(
                DATABASE.url(), DATABASE.username(), DATABASE.password());
             Statement statement = connection.createStatement();
             ResultSet result = statement.executeQuery(sql)) {
            result.next();
            return result.getString(1);
        }
    }
}
