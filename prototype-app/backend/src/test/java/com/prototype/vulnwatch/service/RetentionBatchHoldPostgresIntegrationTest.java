package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.aisecurity.service.AiGridRetentionService;
import com.prototype.vulnwatch.config.TenantAwareDataSource;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.support.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionTemplate;

/** Owner creates disposable fixtures; every retention transaction uses a non-owner, non-bypass role. */
@PostgresIntegrationTest
class RetentionBatchHoldPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB =
            LocalPostgresTestDatabase.provision("phase3_retention_boundaries");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DB);
    }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired FindingRepository findings;
    @Autowired JdbcTemplate jdbc;
    Tenant tenant;
    String role;
    JdbcTemplate runtimeJdbc;
    TransactionTemplate runtimeTransactions;
    AiGridRetentionService retention;

    @BeforeEach void setup() {
        TenantContext.clear();
        String slug = "retention-" + UUID.randomUUID().toString().substring(0, 8);
        tenant = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(tenant);
        tenant = tenants.resolveTenantUuid(tenant.getId());
        role = "retention_" + UUID.randomUUID().toString().replace("-", "");
        jdbc.execute("create role " + role + " login nosuperuser nobypassrls noinherit");
        jdbc.execute("grant usage on schema platform, \"" + tenant.getSchemaName() + "\" to " + role);
        jdbc.execute("grant select,insert,update,delete on all tables in schema \"" + tenant.getSchemaName() + "\" to " + role);
        jdbc.execute("grant usage,select on all sequences in schema \"" + tenant.getSchemaName() + "\" to " + role);
        var source = new TenantAwareDataSource(new DriverManagerDataSource(DB.url(), role, ""), true,
                "tenant_default", new SimpleMeterRegistry());
        runtimeJdbc = new JdbcTemplate(source);
        runtimeTransactions = new TransactionTemplate(new DataSourceTransactionManager(source));
        retention = new AiGridRetentionService(new NamedParameterJdbcTemplate(runtimeJdbc), scoped, runtimeTransactions);
        ReflectionTestUtils.setField(retention, "batchSize", 2);
        ReflectionTestUtils.setField(retention, "maxBatches", 1);
        scoped.run(tenant, () -> {
            assertEquals(role, runtimeJdbc.queryForObject("select current_user", String.class));
            assertFalse(runtimeJdbc.queryForObject("select rolsuper or rolbypassrls from pg_roles where rolname=current_user", Boolean.class));
        });
    }
    @AfterEach void cleanupRole() {
        TenantContext.clear();
        if (role != null) { jdbc.execute("drop owned by " + role); jdbc.execute("drop role " + role); }
    }

    @Test void holdsReplayReferencesAndUnexpiredBodiesSurviveRepeatedCleanup() {
        for (int n = 1; n <= 7; n++) body(n);
        retention.createHold(tenant, hold(1, "LEGAL_HOLD"), "operator");
        retention.createHold(tenant, hold(2, "EXCEPTION"), "operator");
        retention.createHold(tenant, new AiGridRetentionService.HoldCommand(id(3), "REPLAY_COMMITMENT",
                "replay", "replay protection", java.time.Instant.now().plusSeconds(86400)), "operator");
        scoped.run(tenant, () -> {
            jdbc.update("update ai_grid_snapshot_bodies set retain_until=now()+interval '1 day' where id=?", id(4));
            manifest(5, false);
            manifest(6, true);
        });
        completeSweep();
        completeSweep();
        scoped.run(tenant, () -> {
            assertEquals(6, count("ai_grid_snapshot_bodies"));
            assertEquals(1, count("ai_grid_retention_purge_audit"));
            assertEquals(id(7), jdbc.queryForObject("select snapshot_body_id from ai_grid_retention_purge_audit", UUID.class));
            assertEquals("ACTIVE_FINDING", jdbc.queryForObject("select reason_code from ai_grid_retention_decisions where snapshot_body_id=?",
                    String.class, id(6)));
            assertEquals("SNAPSHOT_REFERENCE", jdbc.queryForObject("select reason_code from ai_grid_retention_decisions where snapshot_body_id=?",
                    String.class, id(5)));
            assertEquals(6, count("ai_grid_retention_decisions"), "replay must not duplicate unchanged decisions");
        });
    }

    @Test void failureAfterCommittedBatchResumesWithoutSkippedRowsOrDuplicateAudit() {
        for (int n = 1; n <= 7; n++) body(n);
        scoped.run(tenant, () -> {
            jdbc.execute("""
                    create function fail_retention_audit() returns trigger language plpgsql as $$
                    begin
                        if new.snapshot_body_id='00000000-0000-0000-0000-000000000003'::uuid then
                            raise exception 'injected interrupted retention batch';
                        end if;
                        return new;
                    end $$
                    """);
            jdbc.execute("create trigger interrupt_batch before insert on ai_grid_retention_purge_audit "
                    + "for each row execute function fail_retention_audit()");
        });
        assertEquals(2, retention.sweep(tenant).purged());
        assertThrows(RuntimeException.class, () -> retention.sweep(tenant));
        scoped.run(tenant, () -> {
            assertEquals(5, count("ai_grid_snapshot_bodies"));
            assertEquals(2, count("ai_grid_retention_purge_audit"));
            assertEquals(id(2), jdbc.queryForObject("select after_id from ai_grid_retention_progress", UUID.class));
            assertEquals("FAILED", jdbc.queryForObject("select state from ai_grid_retention_progress", String.class));
            jdbc.execute("drop trigger interrupt_batch on ai_grid_retention_purge_audit");
        });
        completeSweep();
        scoped.run(tenant, () -> {
            assertEquals(0, count("ai_grid_snapshot_bodies"));
            assertEquals(7, count("ai_grid_retention_purge_audit"));
            assertEquals(7, jdbc.queryForObject("select count(distinct snapshot_body_id) from ai_grid_retention_purge_audit", Integer.class));
        });
    }

    @Test void overlappingSweepsKeepOneAuditPerPurgedBody() throws Exception {
        for (int n = 1; n <= 7; n++) body(n);
        CyclicBarrier start = new CyclicBarrier(2);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        try {
            Callable<Void> sweep = () -> { start.await(10, TimeUnit.SECONDS); completeSweep(); return null; };
            Future<Void> first = pool.submit(sweep), second = pool.submit(sweep);
            first.get(25, TimeUnit.SECONDS); second.get(25, TimeUnit.SECONDS);
        } finally { pool.shutdownNow(); }
        scoped.run(tenant, () -> {
            assertEquals(0, count("ai_grid_snapshot_bodies"));
            assertEquals(7, count("ai_grid_retention_purge_audit"));
        });
    }

    @Test void uncommittedHoldBlocksPurgeAndCommittedHoldSurvivesRetry() throws Exception {
        body(1);
        CountDownLatch inserted = new CountDownLatch(1), commit = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<?> holder = pool.submit(() -> scoped.run(tenant, () -> runtimeTransactions.executeWithoutResult(status -> {
                retention.createHold(tenant, hold(1, "EXCEPTION"), "operator");
                inserted.countDown();
                try { assertTrue(commit.await(10, TimeUnit.SECONDS)); }
                catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new AssertionError(failure); }
            })));
            assertTrue(inserted.await(10, TimeUnit.SECONDS));
            assertThrows(RuntimeException.class, () -> retention.sweep(tenant), "bounded lock timeout must fail without deleting held data");
            scoped.run(tenant, () -> assertEquals("FAILED", jdbc.queryForObject(
                    "select state from ai_grid_retention_progress", String.class), "a failed first batch must remain visible"));
            commit.countDown(); holder.get(15, TimeUnit.SECONDS);
        } finally { commit.countDown(); pool.shutdownNow(); }
        completeSweep();
        scoped.run(tenant, () -> { assertEquals(1, count("ai_grid_snapshot_bodies")); assertEquals(0, count("ai_grid_retention_purge_audit")); });
    }

    @Test void releasedAndExpiredNonLegalHoldsAllowOneAuditedPurge() {
        body(1); body(2);
        var released = retention.createHold(tenant, hold(1, "EXCEPTION"), "operator");
        retention.releaseHold(tenant, released.id(), "operator");
        retention.createHold(tenant, new AiGridRetentionService.HoldCommand(id(2), "REPLAY_COMMITMENT",
                "expired", "expired replay", java.time.Instant.now().minusSeconds(60)), "operator");
        completeSweep(); completeSweep();
        scoped.run(tenant, () -> { assertEquals(0, count("ai_grid_snapshot_bodies")); assertEquals(2, count("ai_grid_retention_purge_audit")); });
    }

    @Test void concurrentPolicyExtensionPreservesItsLockedBodyAndRetriesTheSweep() throws Exception {
        body(1);
        scoped.run(tenant, () -> jdbc.update("""
                insert into ai_grid_retention_policies(retention_class,tenant_id,retain_days,restricted,updated_by,reason)
                values ('HOT',?,90,false,'fixture','approved fixture policy')
                """, tenant.getId()));
        CountDownLatch extended = new CountDownLatch(1), commit = new CountDownLatch(1);
        ExecutorService pool = Executors.newSingleThreadExecutor();
        try {
            Future<?> updater = pool.submit(() -> scoped.run(tenant, () -> runtimeTransactions.executeWithoutResult(status -> {
                retention.updatePolicy(tenant, new AiGridRetentionService.PolicyCommand(
                        "HOT", 6000, null, false, "fixture extension"), "operator");
                extended.countDown();
                try { assertTrue(commit.await(10, TimeUnit.SECONDS)); }
                catch (InterruptedException failure) { Thread.currentThread().interrupt(); throw new AssertionError(failure); }
            })));
            if (!extended.await(10, TimeUnit.SECONDS)) {
                updater.get(1, TimeUnit.SECONDS);
                fail("policy extension did not reach the transaction boundary");
            }
            assertThrows(RuntimeException.class, () -> retention.sweep(tenant));
            commit.countDown(); updater.get(15, TimeUnit.SECONDS);
        } finally { commit.countDown(); pool.shutdownNow(); }
        completeSweep();
        scoped.run(tenant, () -> {
            assertEquals(1, count("ai_grid_snapshot_bodies"));
            assertEquals(0, count("ai_grid_retention_purge_audit"));
            assertEquals("RETAINED", jdbc.queryForObject("select retention_state from ai_grid_snapshot_bodies", String.class));
        });
    }

    private void body(int n) {
        scoped.run(tenant, () -> jdbc.update("""
                insert into ai_grid_snapshot_bodies
                    (id,tenant_id,content_hash,content_json,byte_size,redaction_profile,created_at,retain_until)
                values (?,?,?,'{}'::jsonb,2,'TEST',now()-interval '5000 days',now()-interval '1 day')
                """, id(n), tenant.getId(), String.format("%064d", n)));
    }
    private void manifest(int n, boolean activeFinding) {
        UUID artifact = UUID.randomUUID(), manifest = UUID.randomUUID(), run = UUID.randomUUID();
        jdbc.update("""
                insert into ai_security_artifacts(id,tenant_id,provider,provider_resource_id,artifact_type,
                    native_kind,name,account_id,region,first_observed_at,last_observed_at)
                values (?,?,'AWS',?,'AGENT','offline','fixture','offline','offline',now(),now())
                """, artifact, tenant.getId(), artifact.toString());
        jdbc.update("""
                insert into ai_grid_snapshot_manifests(id,tenant_id,run_id,artifact_id,scope_key,body_id,schema_version,observed_at)
                values (?,?,?,?,'offline',?,'1',now())
                """, manifest, tenant.getId(), run, artifact, id(n));
        if (activeFinding) {
            UUID assessment = UUID.randomUUID();
            jdbc.update("""
                    insert into ai_grid_assessments(id,tenant_id,run_id,policy_id,policy_version,subject_type,subject_id,
                        snapshot_manifest_id,selection,applicability,evidence_readiness,decision,reason_code,fingerprint,evaluation_as_of)
                    values (?,?,?,'offline','1','ARTIFACT',?,?,'SELECTED','APPLICABLE','READY','FAIL','TEST',?,now())
                    """, assessment, tenant.getId(), run, artifact, manifest, "a".repeat(64));
            Finding finding = new Finding();
            finding.setTenant(tenant); finding.setFindingKind("AI_POSTURE");
            finding.setMatchedBy("retention-fixture"); finding.setAssessmentId(assessment);
            findings.saveAndFlush(finding);
        }
    }
    private void completeSweep() {
        for (int run = 0; run < 10; run++) {
            var result = retention.sweep(tenant);
            assertTrue(result.evaluated() <= 2); assertEquals(1, result.batches());
            if ("COMPLETED".equals(result.status())) return;
        }
        fail("bounded sweeps did not complete");
    }
    private int count(String table) { return jdbc.queryForObject("select count(*) from " + table, Integer.class); }
    private static UUID id(int n) { return new UUID(0, n); }
    private static AiGridRetentionService.HoldCommand hold(int n, String type) {
        return new AiGridRetentionService.HoldCommand(id(n), type, "fixture-" + n, "retention test", null);
    }
}
