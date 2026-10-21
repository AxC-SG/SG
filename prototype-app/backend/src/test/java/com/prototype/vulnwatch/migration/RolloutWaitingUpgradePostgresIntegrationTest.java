package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

/** Qualifies only the additive V5 -> V6 transition on the reset history, not the deployed older history. */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class RolloutWaitingUpgradePostgresIntegrationTest {
    @Test void forwardMigrationRetainsClaimsAndMakesLegacyProcessingRecoverable() {
        var db = LocalPostgresTestDatabase.provision("closure_rollout_upgrade");
        var jdbc = new JdbcTemplate(new DriverManagerDataSource(db.url(), db.username(), db.password()));
        var config = Flyway.configure().dataSource(db.url(), db.username(), db.password())
                .locations("classpath:db/migration/postgres_reset").defaultSchema("public");
        config.target("5").load().migrate();
        UUID approval = UUID.randomUUID(), rollout = UUID.randomUUID(), owner = UUID.randomUUID();
        String digest = "b".repeat(64);
        jdbc.update("""
                insert into platform.ai_grid_policy_release_decisions
                  (id,policy_id,policy_version,decision,reason,decided_by,package_digest,approved_package_digest)
                values (?,'CLOSURE_UPGRADE','1.0.0','APPROVED','Controlled fixture','test',?,?)
                """, approval, digest, digest);
        jdbc.update("""
                insert into platform.ai_grid_policy_rollouts
                  (id,release_id,release_type,policy_id,new_version,package_digest,
                   approved_package_digest,release_decision_id,distribution_snapshot_json)
                values (?,'controlled-upgrade','POLICY_VERSION','CLOSURE_UPGRADE','1.0.0',?,?,?,'{}')
                """, rollout, digest, digest, approval);
        UUID[] tasks = {UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID()};
        for (int i = 0; i < tasks.length; i++) {
            UUID tenant = UUID.randomUUID(); String slug = "upgrade-" + i;
            jdbc.update("""
                    insert into platform.tenants
                      (id,name,slug,schema_name,status,plan_code,created_at,updated_at,
                       max_connector_count,max_daily_exposure_refreshes,max_daily_sbom_uploads,max_export_rows,max_service_account_count)
                    values (?, ?,?,?,'PROVISIONING','ENTERPRISE',now(),now(),10,10,10,100,10)
                    """, tenant, slug, slug, "tenant_" + slug.replace('-', '_'));
            jdbc.update("insert into platform.ai_grid_policy_rollout_tasks(id,rollout_id,tenant_id,status) values (?,?,?,?)",
                    tasks[i], rollout, tenant, i < 2 ? "PROCESSING" : "PENDING");
        }
        jdbc.update("update platform.ai_grid_policy_rollout_tasks set claim_token=?,lease_expires_at=now()+interval '10 minutes' where id=?", owner, tasks[1]);
        var originalLease = jdbc.queryForObject("select lease_expires_at from platform.ai_grid_policy_rollout_tasks where id=?", java.sql.Timestamp.class, tasks[1]);
        assertThrows(org.springframework.dao.DataIntegrityViolationException.class, () ->
                jdbc.update("update platform.ai_grid_policy_rollout_tasks set status='WAITING_FOR_ASSESSMENT' where id=?", tasks[2]));

        assertEquals(1, config.target("6").load().migrate().migrationsExecuted);
        assertEquals(0, config.target("6").load().migrate().migrationsExecuted);
        assertTrue(jdbc.queryForObject("""
                select lease_expires_at>now() and lease_expires_at<=now()+interval '2 minutes'
                  from platform.ai_grid_policy_rollout_tasks where id=?
                """, Boolean.class, tasks[0]));
        assertEquals(owner, jdbc.queryForObject("select claim_token from platform.ai_grid_policy_rollout_tasks where id=?", UUID.class, tasks[1]));
        assertEquals(originalLease, jdbc.queryForObject("select lease_expires_at from platform.ai_grid_policy_rollout_tasks where id=?", java.sql.Timestamp.class, tasks[1]));
        assertNull(jdbc.queryForObject("select lease_expires_at from platform.ai_grid_policy_rollout_tasks where id=?", java.sql.Timestamp.class, tasks[2]));
        assertEquals(1, jdbc.update("update platform.ai_grid_policy_rollout_tasks set status='WAITING_FOR_ASSESSMENT',assessment_request_id=? where id=?", UUID.randomUUID(), tasks[2]));
        assertThrows(org.springframework.dao.DataIntegrityViolationException.class, () ->
                jdbc.update("update platform.ai_grid_policy_rollout_tasks set status='UNKNOWN_STATE' where id=?", tasks[2]));
    }
}
