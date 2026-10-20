package com.prototype.vulnwatch.aisecurity.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.aisecurity.aws.AwsBedrockDiscoveryService;
import com.prototype.vulnwatch.aisecurity.aws.AwsBedrockDiscoveryService.DiscoveryResult;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.IngestionJobWorkerService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

@PostgresIntegrationTest
@TestPropertySource(properties = {
        "spring.main.allow-circular-references=true",
        "app.ai-security.jobs.enabled=false"
})
class AiSecurityJobWorkerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_security_worker");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService tenantSchemaMigrationService;
    @Autowired private IngestionJobService jobs;
    @Autowired private AiSecurityJobWorkerService worker;

    @MockBean private AwsBedrockDiscoveryService discovery;
    @MockBean private IngestionJobWorkerService ingestionJobWorkerService;
    @MockBean private FindingDeltaQueueService findingDeltaQueueService;

    @Test
    void isolatesTenantJobsAndPersistsSanitizedProviderFailure() {
        Tenant healthy = provision("Healthy AI Tenant", "healthy-ai-worker");
        Tenant failing = provision("Failing AI Tenant", "failing-ai-worker");
        UUID healthyConnector = UUID.randomUUID();
        UUID failingConnector = UUID.randomUUID();
        UUID healthyJob = jobs.enqueueAiSecurityJob(healthy, healthyConnector, "integration-test").jobId();
        UUID failingJob = jobs.enqueueAiSecurityJob(failing, failingConnector, "integration-test").jobId();

        when(discovery.discover(
                argThat(tenant -> tenant != null && healthy.getId().equals(tenant.getId())),
                eq(healthyConnector)))
                .thenReturn(new DiscoveryResult(UUID.randomUUID(), 7, 0));
        when(discovery.discover(
                argThat(tenant -> tenant != null && failing.getId().equals(tenant.getId())),
                eq(failingConnector)))
                .thenThrow(new IllegalStateException("raw provider response must not persist"));

        jobs.claimPendingJobsByType(healthy,IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK,1,1);
        jobs.claimPendingJobsByType(failing,IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK,1,1);
        worker.execute(healthy.getId(), healthyJob);
        worker.execute(failing.getId(), failingJob);

        var succeeded = jobs.getJob(healthy, healthyJob);
        assertEquals(IngestionJobService.STATUS_SUCCEEDED, succeeded.status());

        var failed = jobs.getJob(failing, failingJob);
        assertEquals(IngestionJobService.STATUS_FAILED, failed.status());
        assertEquals("PROVIDER_UNAVAILABLE", failed.failureCode());
        assertEquals("AI Security discovery could not be completed", failed.failureMessage());

        assertThrows(IllegalArgumentException.class, () -> jobs.getJob(failing, healthyJob));
        assertThrows(IllegalArgumentException.class, () -> jobs.getJob(healthy, failingJob));
    }

    private Tenant provision(String name, String slug) {
        Tenant tenant = tenantService.createTenant(name, slug, "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);
        return tenant;
    }
}
