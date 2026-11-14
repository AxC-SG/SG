package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.IngestionJobRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

/**
 * Regression for the async ingestion worker only ever processing the default tenant.
 *
 * <p>{@code claimPendingJobs} used to be {@code @Transactional}, which bound the connection's
 * search_path (default schema) before {@code tenantSchemaExecutionService.run(...)} switched the
 * tenant context inside the method body. As a result a QUEUED job in any non-default tenant was
 * never seen — {@code pollPending} queried the default schema, found nothing, and the job sat in
 * QUEUED forever. This test creates a non-default tenant, enqueues a job in its schema, and asserts
 * the claim actually picks it up.
 */
@PostgresIntegrationTest
@TestPropertySource(properties = "spring.main.allow-circular-references=true")
class IngestionJobTenantScopingPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ingestion_job_tenant_scoping");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Autowired
    private TenantSchemaMigrationService tenantSchemaMigrationService;

    @Autowired
    private IngestionJobRepository ingestionJobRepository;

    @Autowired
    private IngestionJobService ingestionJobService;

    // Silence the live scheduled poller/drain so they don't race this test's explicit claim.
    @MockitoBean
    private IngestionJobWorkerService ingestionJobWorkerService;
    @MockitoBean
    private FindingDeltaQueueService findingDeltaQueueService;

    @Test
    void claimsQueuedJobInNonDefaultTenantSchema() {
        Tenant tenant = tenantService.createTenant("Scoping Co", "scoping-co", "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);

        UUID jobId = tenantSchemaExecutionService.run(tenant, () -> {
            IngestionJob job = new IngestionJob();
            job.setTenant(tenant);
            job.setJobType(IngestionJobService.JOB_TYPE_GITHUB_REPOSITORY);
            job.setSourceType("github");
            job.setAssetIdentifier("github:acme/widget");
            job.setStatus(IngestionJobService.STATUS_QUEUED);
            job.setDedupeKey("github_repository:github:acme/widget");
            job.setVisibleAt(Instant.now());
            return ingestionJobRepository.saveAndFlush(job).getId();
        });

        List<IngestionJobService.ClaimedJobRef> claimed = ingestionJobService.claimPendingJobs(tenant, 10, 1);

        assertEquals(1, claimed.size(), "queued job in a non-default tenant must be claimed");
        assertEquals(jobId, claimed.get(0).jobId());

        IngestionJob reloaded = ingestionJobService.loadJob(tenant.getId(), jobId);
        assertEquals(IngestionJobService.STATUS_RUNNING, reloaded.getStatus());
        assertEquals(1, reloaded.getAttemptCount());
    }
}
