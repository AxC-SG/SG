package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomIngestionResultResponse;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import java.io.IOException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IngestionJobExecutionServiceTest {

    @Mock
    private BomIngestionOrchestrator bomIngestionOrchestrator;
    @Mock
    private GithubSbomSourceService githubSbomSourceService;
    @Mock
    private IngestionJobService ingestionJobService;

    @Test
    void executeEndpointJobRehydratesPayloadAndReturnsCanonicalBomResult() throws Exception {
        Tenant tenant = tenant();
        IngestionJob job = job(IngestionJobService.JOB_TYPE_REMOTE_ENDPOINT);
        IngestionJobPayloads.EndpointIngestionPayload payload = new IngestionJobPayloads.EndpointIngestionPayload(
                BomType.SBOM,
                AssetType.CONTAINER_IMAGE,
                "Payments API",
                "asset-1",
                "https://example.com/sbom.json",
                "nightly",
                null,
                "enc-token"
        );
        UUID assetId = UUID.randomUUID();
        UUID bomId = UUID.randomUUID();
        when(ingestionJobService.readPayload(job, IngestionJobPayloads.EndpointIngestionPayload.class)).thenReturn(payload);
        when(ingestionJobService.decrypt("enc-token")).thenReturn("Bearer token");
        when(bomIngestionOrchestrator.ingestFromUrl(any(Tenant.class), any()))
                .thenReturn(new BomIngestionResultResponse(
                        bomId,
                        assetId,
                        "SBOM",
                        "CYCLONEDX",
                        "1.5",
                        "CYCLONEDX",
                        "JSON",
                        "PREVIOUS",
                        true,
                        java.util.List.of(),
                        42,
                        0,
                        "ACTIVE",
                        "CREATED"
                ));
        when(ingestionJobService.toJson(any())).thenAnswer(invocation -> invocation.getArgument(0).toString());

        IngestionJobExecutionService service = new IngestionJobExecutionService(
                bomIngestionOrchestrator,
                githubSbomSourceService,
                ingestionJobService,
                org.mockito.Mockito.mock(AwsDiscoverySyncService.class),
                org.mockito.Mockito.mock(ServiceNowCmdbSyncService.class),
                org.mockito.Mockito.mock(SccmCmdbSyncService.class),
                org.mockito.Mockito.mock(GcpDiscoverySyncService.class),
                org.mockito.Mockito.mock(com.prototype.vulnwatch.service.patch.PatchSyncService.class),
                org.mockito.Mockito.mock(com.prototype.vulnwatch.repo.SyncRunRepository.class)
        );

        IngestionJobExecutionService.ExecutionOutcome outcome = service.execute(tenant, job);

        assertEquals(null, outcome.sbomUpload());
        assertNotNull(outcome.resultJson());
        verify(bomIngestionOrchestrator).ingestFromUrl(any(Tenant.class), any());
    }

    @Test
    void executeGithubRepositoryJobDelegatesToGithubSourceService() throws Exception {
        Tenant tenant = tenant();
        IngestionJob job = job(IngestionJobService.JOB_TYPE_GITHUB_REPOSITORY);
        UUID syncRunId = UUID.randomUUID();
        UUID sourceId = UUID.randomUUID();
        IngestionJobPayloads.GithubRepositoryIngestionPayload payload = new IngestionJobPayloads.GithubRepositoryIngestionPayload(
                "acme",
                "payments",
                false,
                AssetType.APPLICATION,
                "Payments API",
                "asset-1",
                syncRunId,
                sourceId,
                "dependency-graph/sbom"
        );
        when(ingestionJobService.readPayload(job, IngestionJobPayloads.GithubRepositoryIngestionPayload.class)).thenReturn(payload);
        when(ingestionJobService.toJson(any())).thenAnswer(invocation -> invocation.getArgument(0).toString());

        IngestionJobExecutionService service = new IngestionJobExecutionService(
                bomIngestionOrchestrator,
                githubSbomSourceService,
                ingestionJobService,
                org.mockito.Mockito.mock(AwsDiscoverySyncService.class),
                org.mockito.Mockito.mock(ServiceNowCmdbSyncService.class),
                org.mockito.Mockito.mock(SccmCmdbSyncService.class),
                org.mockito.Mockito.mock(GcpDiscoverySyncService.class),
                org.mockito.Mockito.mock(com.prototype.vulnwatch.service.patch.PatchSyncService.class),
                org.mockito.Mockito.mock(com.prototype.vulnwatch.repo.SyncRunRepository.class)
        );

        IngestionJobExecutionService.ExecutionOutcome outcome = service.execute(tenant, job);

        assertEquals(null, outcome.sbomUpload());
        verify(githubSbomSourceService).processRepositoryJob(
                tenant,
                syncRunId,
                sourceId,
                new GithubSbomIngestionRequest("acme", "payments", false, AssetType.APPLICATION, "Payments API", "asset-1", "dependency-graph/sbom")
        );
    }

    @Test
    void executeRejectsUnsupportedJobType() {
        Tenant tenant = tenant();
        IngestionJob job = job("LEGACY_SYNC");
        IngestionJobExecutionService service = new IngestionJobExecutionService(
                bomIngestionOrchestrator,
                githubSbomSourceService,
                ingestionJobService,
                org.mockito.Mockito.mock(AwsDiscoverySyncService.class),
                org.mockito.Mockito.mock(ServiceNowCmdbSyncService.class),
                org.mockito.Mockito.mock(SccmCmdbSyncService.class),
                org.mockito.Mockito.mock(GcpDiscoverySyncService.class),
                org.mockito.Mockito.mock(com.prototype.vulnwatch.service.patch.PatchSyncService.class),
                org.mockito.Mockito.mock(com.prototype.vulnwatch.repo.SyncRunRepository.class)
        );

        IOException error = assertThrows(IOException.class, () -> service.execute(tenant, job));

        assertEquals("Unsupported ingestion job type: LEGACY_SYNC", error.getMessage());
    }

    private Tenant tenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Acme");
        return tenant;
    }

    private IngestionJob job(String jobType) {
        IngestionJob job = new IngestionJob();
        job.setJobType(jobType);
        job.setSourceType("github");
        job.setAssetIdentifier("asset-1");
        return job;
    }
}
