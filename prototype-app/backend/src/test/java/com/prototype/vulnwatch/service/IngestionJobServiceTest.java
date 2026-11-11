package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomFetchRequest;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.dto.IngestionJobPageResponse;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.repo.IngestionJobRepository;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

@ExtendWith(MockitoExtension.class)
class IngestionJobServiceTest {

    @Mock
    private IngestionJobRepository ingestionJobRepository;
    @Mock
    private CredentialEncryptionService credentialEncryptionService;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;
    @Mock
    private TenantService tenantService;
    @Mock
    private TenantQuotaService tenantQuotaService;
    @Mock
    private AuditEventService auditEventService;
    @Mock
    private IngestionJobMetricsService ingestionJobMetricsService;
    @Mock
    private TransactionTemplate transactionTemplate;

    private IngestionJobService service;
    private final IngestionAttemptService attempts=org.mockito.Mockito.mock(IngestionAttemptService.class);

    @BeforeEach
    void setUp() {
        service = new IngestionJobService(
                ingestionJobRepository,
                attempts,
                credentialEncryptionService,
                tenantSchemaExecutionService,
                tenantService,
                tenantQuotaService,
                auditEventService,
                ingestionJobMetricsService,
                new ObjectMapper(),
                transactionTemplate
        );
        lenient().when(tenantSchemaExecutionService.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());
        lenient().when(tenantSchemaExecutionService.run(any(UUID.class), any(Supplier.class)))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());
        lenient().when(transactionTemplate.execute(any()))
                .thenAnswer(invocation -> ((TransactionCallback<?>) invocation.getArgument(0)).doInTransaction(null));
    }

    @Test
    void cancelsRuntimeJobsOnceWithoutTouchingOtherJobTypes() {
        UUID tenantId = UUID.randomUUID();
        UUID jobId = UUID.randomUUID();
        IngestionJob job = new IngestionJob();
        org.springframework.test.util.ReflectionTestUtils.setField(job, "id", jobId);
        job.setJobType(IngestionJobService.JOB_TYPE_AI_GRID_RUNTIME_ADAPTER);
        job.setStatus(IngestionJobService.STATUS_QUEUED);
        when(ingestionJobRepository.findById(jobId)).thenReturn(Optional.of(job));
        service.cancelRuntimeJob(tenantId, jobId);
        service.cancelRuntimeJob(tenantId, jobId);
        assertEquals(IngestionJobService.STATUS_CANCELLED, job.getStatus());
        assertEquals("RUNTIME_OUT_OF_SCOPE", job.getFailureCode());
        assertNotNull(job.getCompletedAt());
        verify(ingestionJobRepository).save(job);
        verify(auditEventService).recordExplicitActor(eq(tenantId), eq("runtime-scope-release"), eq("SYSTEM"),
                eq("ingestion.job.cancelled"), eq("ingestion_job"), eq(jobId.toString()), anyString(), eq("SUCCESS"));
    }

    @Test
    void enqueueEndpointJobPersistsEncryptedPayloadAndEmitsCreatedEvent() throws Exception {
        Tenant tenant = tenant();
        SbomEndpointIngestionRequest request = new SbomEndpointIngestionRequest(
                AssetType.CONTAINER_IMAGE,
                "Payments API",
                " registry.example.com/payments ",
                "https://example.com/sbom.json",
                "nightly",
                "Bearer secret"
        );
        when(credentialEncryptionService.encrypt("Bearer secret")).thenReturn("enc-secret");
        when(ingestionJobRepository.findActiveByDedupeKeyForUpdate(anyString())).thenReturn(Optional.empty());
        when(ingestionJobRepository.saveAndFlush(any(IngestionJob.class))).thenAnswer(invocation -> {
            IngestionJob job = invocation.getArgument(0);
            setId(job, UUID.randomUUID());
            return job;
        });

        IngestionJobAcceptedResponse response = service.enqueueEndpointJob(tenant, request, "architect");

        assertFalse(response.existingJob());
        assertEquals(IngestionJobService.STATUS_QUEUED, response.status());
        ArgumentCaptor<IngestionJob> jobCaptor = ArgumentCaptor.forClass(IngestionJob.class);
        verify(ingestionJobRepository).saveAndFlush(jobCaptor.capture());
        IngestionJob saved = jobCaptor.getValue();
        assertEquals(" registry.example.com/payments ", saved.getAssetIdentifier());
        assertEquals("remote_endpoint:registry.example.com/payments", saved.getDedupeKey());
        assertTrue(saved.getPayloadJson().contains("\"encryptedAuthorizationHeader\":\"enc-secret\""));
        assertFalse(saved.getPayloadJson().contains("Bearer secret"));
        assertNotNull(saved.getVisibleAt());
        verify(tenantQuotaService).assertCanCreateSbomIngestionJob(tenant, "remote-endpoint");
        verify(auditEventService).record(eq("ingestion.job.created"), eq("ingestion_job"), eq(response.jobId().toString()), eq(null));
        verify(ingestionJobMetricsService).recordEnqueued("remote-endpoint");
    }

    @Test
    void enqueueEndpointJobReturnsExistingActiveJobWhenDuplicateExists() throws Exception {
        Tenant tenant = tenant();
        SbomEndpointIngestionRequest request = new SbomEndpointIngestionRequest(
                AssetType.CONTAINER_IMAGE,
                "Payments API",
                "registry.example.com/payments",
                "https://example.com/sbom.json",
                "nightly",
                null
        );
        IngestionJob existing = new IngestionJob();
        UUID jobId = UUID.randomUUID();
        setId(existing, jobId);
        existing.setStatus(IngestionJobService.STATUS_RUNNING);
        when(credentialEncryptionService.encrypt(null)).thenReturn(null);
        when(ingestionJobRepository.findActiveByDedupeKeyForUpdate("remote_endpoint:registry.example.com/payments"))
                .thenReturn(Optional.of(existing));

        IngestionJobAcceptedResponse response = service.enqueueEndpointJob(tenant, request, "architect");

        assertTrue(response.existingJob());
        assertEquals(jobId, response.jobId());
        assertEquals(IngestionJobService.STATUS_RUNNING, response.status());
        verify(ingestionJobMetricsService).recordDeduped("remote-endpoint");
        verify(auditEventService).record("ingestion.job.deduped", "ingestion_job", jobId.toString(), null);
    }

    @Test
    void enqueueBomFetchJobUsesBomFetchQuotaSource() throws Exception {
        Tenant tenant = tenant();
        BomFetchRequest request = new BomFetchRequest(
                BomType.SBOM,
                AssetType.APPLICATION,
                "Payments API",
                "payments-api",
                "https://example.com/sbom.json",
                "nightly",
                "Acme",
                "Bearer secret"
        );
        when(credentialEncryptionService.encrypt("Bearer secret")).thenReturn("enc-secret");
        when(ingestionJobRepository.findActiveByDedupeKeyForUpdate(anyString())).thenReturn(Optional.empty());
        when(ingestionJobRepository.saveAndFlush(any(IngestionJob.class))).thenAnswer(invocation -> {
            IngestionJob job = invocation.getArgument(0);
            setId(job, UUID.randomUUID());
            return job;
        });

        IngestionJobAcceptedResponse response = service.enqueueBomFetchJob(tenant, request, "architect");

        assertFalse(response.existingJob());
        verify(tenantQuotaService).assertCanCreateSbomIngestionJob(tenant, "bom-fetch");
        verify(ingestionJobMetricsService).recordEnqueued("bom-fetch");
    }

    @Test
    void claimPendingJobsMarksClaimedRowsRunningAndIncrementsAttemptCount() throws Exception {
        Tenant tenant = tenant();
        when(attempts.tryLockCapacity(tenant.getId())).thenReturn(true);
        IngestionJob first = queuedJob(tenant, "asset-1");
        IngestionJob second = queuedJob(tenant, "asset-2");
        UUID firstId = UUID.randomUUID();
        UUID secondId = UUID.randomUUID();
        setId(first, firstId);
        setId(second, secondId);
        when(ingestionJobRepository.countByStatusExcludingJobTypes(
                IngestionJobService.STATUS_RUNNING,
                List.of(
                        IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK,
                        IngestionJobService.JOB_TYPE_AI_SECURITY_AZURE_DISCOVERY,
                        IngestionJobService.JOB_TYPE_AI_SECURITY_COPILOT_STUDIO,
                        IngestionJobService.JOB_TYPE_AI_GRID_RUNTIME_ADAPTER,
                        IngestionJobService.JOB_TYPE_AI_GRID_BOM_PROJECTION,
                        IngestionJobService.JOB_TYPE_AWS_DISCOVERY,IngestionJobService.JOB_TYPE_SERVICENOW_CMDB,
                        IngestionJobService.JOB_TYPE_SCCM_CMDB,
                        IngestionJobService.JOB_TYPE_GCP_DISCOVERY,
                        IngestionJobService.JOB_TYPE_PATCH_SYNC,
                        IngestionJobService.JOB_TYPE_BOM_UPLOAD)
        )).thenReturn(0L);
        when(ingestionJobRepository.pollPendingExcludingJobTypes(
                List.of(
                        IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK,
                        IngestionJobService.JOB_TYPE_AI_SECURITY_AZURE_DISCOVERY,
                        IngestionJobService.JOB_TYPE_AI_SECURITY_COPILOT_STUDIO,
                        IngestionJobService.JOB_TYPE_AI_GRID_RUNTIME_ADAPTER,
                        IngestionJobService.JOB_TYPE_AI_GRID_BOM_PROJECTION,
                        IngestionJobService.JOB_TYPE_AWS_DISCOVERY,IngestionJobService.JOB_TYPE_SERVICENOW_CMDB,
                        IngestionJobService.JOB_TYPE_SCCM_CMDB,
                        IngestionJobService.JOB_TYPE_GCP_DISCOVERY,
                        IngestionJobService.JOB_TYPE_PATCH_SYNC,
                        IngestionJobService.JOB_TYPE_BOM_UPLOAD),
                2
        )).thenReturn(List.of(first, second));

        List<IngestionJobService.ClaimedJobRef> claimed = service.claimPendingJobs(tenant, 2, 2);

        assertEquals(2, claimed.size());
        assertEquals(firstId, claimed.get(0).jobId());
        assertEquals(secondId, claimed.get(1).jobId());
        assertEquals(IngestionJobService.STATUS_RUNNING, first.getStatus());
        assertEquals(IngestionJobService.STATUS_RUNNING, second.getStatus());
        assertEquals(1, first.getAttemptCount());
        assertEquals(1, second.getAttemptCount());
        assertNotNull(first.getStartedAt());
        assertNotNull(second.getStartedAt());
        verify(ingestionJobRepository).saveAll(List.of(first, second));
    }

    @Test
    void aiSecurityClaimerOnlyClaimsAiSecurityJobs() throws Exception {
        Tenant tenant = tenant();
        when(attempts.tryLockCapacity(tenant.getId())).thenReturn(true);
        IngestionJob aiJob = queuedJob(tenant, "ai-security-aws");
        UUID jobId = UUID.randomUUID();
        setId(aiJob, jobId);
        aiJob.setJobType(IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK);
        when(ingestionJobRepository.countByStatusAndJobType(
                IngestionJobService.STATUS_RUNNING,
                IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK
        )).thenReturn(0L);
        when(ingestionJobRepository.pollPendingByJobType(
                IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK, 1
        )).thenReturn(List.of(aiJob));

        List<IngestionJobService.ClaimedJobRef> claimed = service.claimPendingJobsByType(
                tenant, IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK, 1, 1);

        assertEquals(List.of(new IngestionJobService.ClaimedJobRef(tenant.getId(), jobId, aiJob.getClaimToken())), claimed);
        assertEquals(IngestionJobService.STATUS_RUNNING, aiJob.getStatus());
        verify(ingestionJobRepository).pollPendingByJobType(
                IngestionJobService.JOB_TYPE_AI_SECURITY_AWS_BEDROCK, 1);
    }

    @Test
    void recoverOnlyExpiredAttemptsAndRetainRetryableIntent() throws Exception {
        Tenant tenant = tenant();
        when(attempts.tryLockCapacity(tenant.getId())).thenReturn(true);
        IngestionJob running = queuedJob(tenant, "asset-1");
        UUID jobId = UUID.randomUUID();
        setId(running, jobId);
        running.setStatus(IngestionJobService.STATUS_RUNNING);
        running.setStartedAt(Instant.parse("2026-06-15T10:00:00Z"));
        when(tenantService.listActiveTenants()).thenReturn(List.of(tenant));
        when(ingestionJobRepository.pollExpiredAttempts(100)).thenReturn(List.of(running));
        when(attempts.lockExpiredJob(jobId)).thenReturn(true);

        int recovered = service.recoverInterruptedRunningJobs();

        assertEquals(1, recovered);
        assertEquals(IngestionJobService.STATUS_QUEUED, running.getStatus());
        assertEquals("ATTEMPT_EXPIRED", running.getFailureCode());
        assertEquals("Previous worker lease expired", running.getFailureMessage());
        org.junit.jupiter.api.Assertions.assertNull(running.getCompletedAt());
        verify(ingestionJobRepository).saveAll(List.of(running));
        verify(auditEventService,org.mockito.Mockito.never()).record(eq("ingestion.job.failed"),anyString(),anyString(),any());
    }

    @Test
    void listJobsCapsPageSizeAndMapsPagedResponse() throws Exception {
        Tenant tenant = tenant();
        IngestionJob job = queuedJob(tenant, "asset-1");
        UUID jobId = UUID.randomUUID();
        setId(job, jobId);
        job.setRequestedBy("architect");
        job.setRequestedAt(Instant.parse("2026-06-14T12:00:00Z"));
        when(ingestionJobRepository.findAllByOrderByRequestedAtDescIdDesc(any(Pageable.class)))
                .thenReturn(new PageImpl<>(List.of(job)));

        IngestionJobPageResponse response = service.listJobs(tenant, 0, 1000);

        assertEquals(1, response.items().size());
        assertEquals(jobId, response.items().get(0).jobId());
        assertEquals(1, response.size());
        ArgumentCaptor<Pageable> pageableCaptor = ArgumentCaptor.forClass(Pageable.class);
        verify(ingestionJobRepository).findAllByOrderByRequestedAtDescIdDesc(pageableCaptor.capture());
        assertEquals(100, pageableCaptor.getValue().getPageSize());
    }

    private Tenant tenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Acme");
        tenant.setSchemaName("tenant_acme");
        return tenant;
    }

    private IngestionJob queuedJob(Tenant tenant, String assetIdentifier) {
        IngestionJob job = new IngestionJob();
        job.setTenant(tenant);
        job.setJobType(IngestionJobService.JOB_TYPE_REMOTE_ENDPOINT);
        job.setSourceType("remote-endpoint");
        job.setAssetIdentifier(assetIdentifier);
        job.setStatus(IngestionJobService.STATUS_QUEUED);
        job.setRequestedAt(Instant.now());
        job.setVisibleAt(Instant.now());
        return job;
    }

    private void setId(IngestionJob job, UUID id) throws Exception {
        Field idField = IngestionJob.class.getDeclaredField("id");
        idField.setAccessible(true);
        idField.set(job, id);
    }
}
