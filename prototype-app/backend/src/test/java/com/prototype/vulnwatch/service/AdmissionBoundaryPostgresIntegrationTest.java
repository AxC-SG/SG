package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.repo.GithubSbomSourceRepository;
import com.prototype.vulnwatch.support.*;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
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
        scoped.run(independent, () -> {
            assertEquals("QUEUED", sources.findById(admitted).orElseThrow().getLastRunStatus());
            assertEquals(1, jdbc.queryForObject("select count(*) from ingestion_jobs", Integer.class));
        });
        // Finishing the blocker makes the original source eligible without operator repair.
        scoped.run(tenant, () -> jdbc.update("update ingestion_jobs set status='CANCELLED',completed_at=now() where id=?", blocker));
        github.runScheduledSources();
        scoped.run(tenant, () -> assertEquals("QUEUED", sources.findById(deferred).orElseThrow().getLastRunStatus()));
        assertEquals(1, jdbc.queryForObject("select count(*) from platform.sync_runs where tenant_id=?", Integer.class, tenant.getId()));
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
