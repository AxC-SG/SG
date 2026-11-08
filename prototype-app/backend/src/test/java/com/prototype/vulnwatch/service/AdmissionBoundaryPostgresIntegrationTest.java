package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.repo.GithubSbomSourceRepository;
import com.prototype.vulnwatch.support.*;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.support.StaticListableBeanFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class AdmissionBoundaryPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB =
            LocalPostgresTestDatabase.provision("closure_admission");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DB);
    }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired IngestionJobService jobs;
    @Autowired GithubSbomSourceService github;
    @Autowired GithubSbomSourceRepository sources;
    @Autowired JdbcTemplate jdbc;
    Tenant tenant;

    @BeforeEach void setup() { TenantContext.clear(); tenant = tenant(); }
    @AfterEach void clear() { TenantContext.clear(); }

    @ParameterizedTest
    @ValueSource(strings = {"max_daily_sbom_uploads", "max_sbom_jobs_per_rate_limit_window", "max_active_sbom_jobs"})
    void differentRequestsCannotBothConsumeTheFinalConfiguredSlot(String limit) throws Exception {
        // Names come only from the fixed test cases; production limit values are unchanged.
        jdbc.update("update platform.tenants set " + limit + "=1 where id=?", tenant.getId());
        tenant = tenants.resolveTenantUuid(tenant.getId());
        List<String> outcomes = race(() -> {
            try { jobs.enqueueEndpointJob(tenant, request(UUID.randomUUID().toString()), "test"); return "accepted"; }
            catch (QuotaExceededException denied) { return "quota"; }
        });
        assertEquals(1, outcomes.stream().filter("accepted"::equals).count());
        assertEquals(1, outcomes.stream().filter("quota"::equals).count());
        scoped.run(tenant, () -> assertEquals(1, jdbc.queryForObject("select count(*) from ingestion_jobs", Integer.class)));
        Tenant independent = tenant();
        assertNotNull(jobs.enqueueEndpointJob(independent, request("independent"), "test").jobId());
    }

    @Test void competingConsumersHonorTheSameConfiguredRunningLimit() throws Exception {
        for (int i = 0; i < 3; i++) jobs.enqueueEndpointJob(tenant, request("claim-" + i), "test");
        List<Integer> claimed = race(() -> jobs.claimPendingJobs(tenant, 10, 1).size());
        assertEquals(1, claimed.stream().mapToInt(Integer::intValue).sum());
        scoped.run(tenant, () -> {
            assertEquals(1, jdbc.queryForObject("select count(*) from ingestion_jobs where status='RUNNING'", Integer.class));
            assertEquals(2, jdbc.queryForObject("select count(*) from ingestion_jobs where status='QUEUED'", Integer.class));
        });
    }

    @Test
    void claimsSkipAContendedTenantWithoutConsumingItsAttempt() throws Exception {
        Tenant peer = tenant();
        UUID queued = jobs.enqueueEndpointJob(tenant, request("contended"), "test").jobId();
        UUID peerJob = jobs.enqueueEndpointJob(peer, request("independent"), "test").jobId();
        CountDownLatch locked = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(2);
        try {
            var holder = executor.submit(() -> jobs.withAdmission(tenant, () -> {
                locked.countDown();
                try {
                    assertTrue(release.await(15, TimeUnit.SECONDS));
                } catch (InterruptedException failure) {
                    Thread.currentThread().interrupt();
                    throw new AssertionError(failure);
                }
                return null;
            }));
            assertTrue(locked.await(5, TimeUnit.SECONDS));
            var claims = executor.submit(() -> {
                assertTrue(jobs.claimPendingJobs(tenant, 1, 1).isEmpty());
                assertTrue(jobs.claimPendingJobsByType(tenant, IngestionJobService.JOB_TYPE_AWS_DISCOVERY, 1, 1).isEmpty());
                return jobs.claimPendingJobs(peer, 1, 1);
            });
            assertEquals(peerJob, claims.get(5, TimeUnit.SECONDS).get(0).jobId());
            assertEquals(0, jobs.loadJob(tenant.getId(), queued).getAttemptCount());
            release.countDown();
            holder.get(5, TimeUnit.SECONDS);
            assertEquals(queued, jobs.claimPendingJobs(tenant, 1, 1).get(0).jobId());
            assertEquals(1, jobs.loadJob(tenant.getId(), queued).getAttemptCount());
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
    }

    @Test void scheduledQuotaDenialRollsBackSourceAndRunWhileAnotherTenantProgresses() {
        jdbc.update("update platform.tenants set max_active_sbom_jobs=1 where id=?", tenant.getId());
        tenant = tenants.resolveTenantUuid(tenant.getId());
        UUID blocker = jobs.enqueueEndpointJob(tenant, request("blocker"), "test").jobId();
        UUID deferred = source(tenant);
        Tenant independent = tenant();
        UUID admitted = source(independent);
        github.runScheduledSources();
        scoped.run(tenant, () -> {
            GithubSbomSource unchanged = sources.findById(deferred).orElseThrow();
            assertNull(unchanged.getLastRunAt()); assertNull(unchanged.getLastRunStatus());
            assertEquals(1, jdbc.queryForObject("select count(*) from ingestion_jobs", Integer.class));
        });
        assertEquals(0, jdbc.queryForObject("select count(*) from platform.sync_runs where tenant_id=?", Integer.class, tenant.getId()));
        assertEquals(0, githubScheduleProgress(tenant, deferred));
        scoped.run(independent, () -> {
            assertEquals("QUEUED", sources.findById(admitted).orElseThrow().getLastRunStatus());
            assertEquals(1, jdbc.queryForObject("select count(*) from ingestion_jobs", Integer.class));
        });
        // Finishing the blocker makes the original source eligible without operator repair.
        scoped.run(tenant, () -> jdbc.update("update ingestion_jobs set status='CANCELLED',completed_at=now() where id=?", blocker));
        github.runScheduledSources();
        scoped.run(tenant, () -> assertEquals("QUEUED", sources.findById(deferred).orElseThrow().getLastRunStatus()));
        assertEquals(1, jdbc.queryForObject("select count(*) from platform.sync_runs where tenant_id=?", Integer.class, tenant.getId()));
        assertEquals(1, githubScheduleProgress(tenant, deferred));
    }

    private int githubScheduleProgress(Tenant owner, UUID sourceId) {
        return jdbc.queryForObject("""
                select count(*) from platform.connector_schedule_progress
                where tenant_id = ? and schedule_kind = 'GITHUB_SOURCE' and source_id = ?
                """, Integer.class, owner.getId(), sourceId);
    }

    @Test
    void workerSnapshotMeasuresVisibleIngestionAgeWithoutScrapingTenantDatabases() {
        Instant now = Instant.now();
        Tenant peer = tenant();
        UUID scan = jobs.enqueueEndpointJob(tenant, request("scan-fixture"), "test").jobId();
        UUID running = jobs.enqueueEndpointJob(tenant, request("running-fixture"), "test").jobId();
        UUID pending = jobs.enqueueEndpointJob(peer, request("pending-fixture"), "test").jobId();
        scoped.run(tenant, () -> {
            jdbc.update("update ingestion_jobs set job_type = 'AWS_DISCOVERY', visible_at = ? where id = ?",
                    Timestamp.from(now.minusSeconds(120)), scan);
            jdbc.update("update ingestion_jobs set status = 'RUNNING', visible_at = ? where id = ?",
                    Timestamp.from(now.minusSeconds(240)), running);
        });
        scoped.run(peer, () -> jdbc.update("update ingestion_jobs set visible_at = ? where id = ?",
                Timestamp.from(now.minusSeconds(10)), pending));

        var fixtureTenants = org.mockito.Mockito.mock(TenantService.class);
        org.mockito.Mockito.when(fixtureTenants.listTenants()).thenReturn(List.of(tenant, peer));
        var meters = new SimpleMeterRegistry();
        try {
            var provider = new StaticListableBeanFactory(Map.of("meters", meters)).getBeanProvider(MeterRegistry.class);
            var telemetry = new PerformanceTelemetryService(provider, fixtureTenants, scoped,
                    org.mockito.Mockito.mock(FindingProjectionStatusService.class), jdbc, 15, 30000,
                    BackgroundTaskExecutionPolicy.forRole("worker"), Clock.fixed(now, ZoneOffset.UTC));
            telemetry.refreshFreshnessSnapshot();
            assertEquals(1, meters.get("ingestion.jobs.queue.depth").gauge().value());
            assertEquals(2, meters.get("ingestion.jobs.active").gauge().value());
            var oldest = meters.get("scoutgrid.ingestion.queue.oldest_visible_age_seconds").gauge();
            assertEquals(120, oldest.value());
            scoped.run(tenant, () -> jdbc.update("update ingestion_jobs set status = 'CANCELLED' where id = ?", scan));
            assertEquals(120, oldest.value());
            telemetry.refreshFreshnessSnapshot();
            assertEquals(10, oldest.value());
        } finally {
            meters.close();
        }
    }

    private Tenant tenant() {
        String slug = "admission-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant value = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(value);
        jdbc.update("""
                update platform.tenants set max_daily_sbom_uploads=10,max_sbom_jobs_per_rate_limit_window=10,
                  max_active_sbom_jobs=10 where id=?
                """, value.getId());
        return tenants.resolveTenantUuid(value.getId());
    }
    private UUID source(Tenant owner) {
        return scoped.run(owner, () -> {
            GithubSbomSource source = new GithubSbomSource(); source.setTenant(owner); source.setName("Controlled source");
            source.setOwner("controlled"); source.setRepo("repo"); source.setAssetName("Controlled asset");
            source.setAssetIdentifier("source-" + owner.getId()); source.setFrequency(GithubIngestionFrequency.ONCE);
            return sources.save(source).getId();
        });
    }
    private SbomEndpointIngestionRequest request(String identity) {
        return new SbomEndpointIngestionRequest(AssetType.APPLICATION, "Controlled asset", identity,
                "https://example.test/bom.json", "test", null);
    }
    private <T> List<T> race(Callable<T> action) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(2); CyclicBarrier start = new CyclicBarrier(2);
        try {
            Callable<T> ready = () -> { start.await(10, TimeUnit.SECONDS); return action.call(); };
            Future<T> first = pool.submit(ready), second = pool.submit(ready);
            return List.of(first.get(30, TimeUnit.SECONDS), second.get(30, TimeUnit.SECONDS));
        } finally { pool.shutdownNow(); }
    }
}
