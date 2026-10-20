package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GithubSbomIngestionBatchResponse;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import com.prototype.vulnwatch.dto.SbomUploadEvidencePageResponse;
import com.prototype.vulnwatch.dto.SbomUploadEvidenceResponse;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.service.sbomingestion.GithubSbomIngestionCoordinator;
import com.prototype.vulnwatch.service.sbomingestion.SbomContentIngestionService;
import com.prototype.vulnwatch.service.sbomingestion.SbomEndpointFetchResult;
import com.prototype.vulnwatch.service.sbomingestion.SbomEndpointFetchService;
import com.prototype.vulnwatch.service.sbomingestion.SbomIngestionLockService;
import com.prototype.vulnwatch.service.sbomingestion.SbomUploadSupportService;
import java.io.IOException;
import java.util.List;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class SbomIngestionService {

    private final SbomEndpointFetchService sbomEndpointFetchService;
    private final SbomContentIngestionService sbomContentIngestionService;
    private final GithubSbomIngestionCoordinator githubSbomIngestionCoordinator;
    private final SbomIngestionLockService sbomIngestionLockService;
    private final SbomUploadSupportService sbomUploadSupportService;
    private final SbomUploadRepository sbomUploadRepository;

    public SbomIngestionService(
            SbomEndpointFetchService sbomEndpointFetchService,
            SbomContentIngestionService sbomContentIngestionService,
            GithubSbomIngestionCoordinator githubSbomIngestionCoordinator,
            SbomIngestionLockService sbomIngestionLockService,
            SbomUploadSupportService sbomUploadSupportService,
            SbomUploadRepository sbomUploadRepository
    ) {
        this.sbomEndpointFetchService = sbomEndpointFetchService;
        this.sbomContentIngestionService = sbomContentIngestionService;
        this.githubSbomIngestionCoordinator = githubSbomIngestionCoordinator;
        this.sbomIngestionLockService = sbomIngestionLockService;
        this.sbomUploadSupportService = sbomUploadSupportService;
        this.sbomUploadRepository = sbomUploadRepository;
    }

    public SbomIngestionResponse ingestFromEndpoint(Tenant tenant, SbomEndpointIngestionRequest request) throws IOException {
        SbomEndpointFetchResult fetchResult = sbomEndpointFetchService.fetch(request);
        return sbomIngestionLockService.withAssetLock(tenant, request.assetIdentifier(), () ->
                sbomContentIngestionService.ingestBytes(
                        tenant,
                        request.assetType(),
                        request.assetName(),
                        request.assetIdentifier(),
                        fetchResult.content(),
                        "endpoint-sbom.json",
                        fetchResult.metadata(),
                        null
                ));
    }

    // A batch reports per-document success/failure. Each proxied orchestrator call owns
    // its document transaction; a rejected item must not roll back accepted siblings.
    public GithubSbomIngestionBatchResponse ingestFromGithub(Tenant tenant, com.prototype.vulnwatch.dto.GithubSbomIngestionRequest request)
            throws IOException {
        return githubSbomIngestionCoordinator.ingestFromGithub(tenant, request);
    }

    public GithubSbomIngestionBatchResponse ingestBomFilesFromGithub(Tenant tenant, com.prototype.vulnwatch.dto.GithubSbomIngestionRequest request)
            throws IOException {
        return githubSbomIngestionCoordinator.ingestBomFilesFromGithub(tenant, request);
    }

    public GithubGhcrIngestionSummary ingestAllFromGithubContainerRegistry(Tenant tenant, String owner) throws IOException {
        return githubSbomIngestionCoordinator.ingestAllFromGithubContainerRegistry(tenant, owner);
    }

    @Transactional(readOnly = true)
    public List<SbomUploadEvidenceResponse> listUploads(Tenant tenant, String sourceSystem) {
        return sbomUploadSupportService.listUploads(tenant, sourceSystem);
    }

    @Transactional(readOnly = true)
    public SbomUploadEvidencePageResponse listUploadsPage(Tenant tenant, String sourceSystem, int page, int size) {
        return sbomUploadSupportService.listUploadsPage(tenant, sourceSystem, page, size);
    }

    public SbomIngestionResponse executeEndpointJob(Tenant tenant, SbomEndpointIngestionRequest request) throws IOException {
        SbomEndpointFetchResult fetchResult = sbomEndpointFetchService.fetch(request);
        return sbomContentIngestionService.ingestBytes(
                tenant,
                request.assetType(),
                request.assetName(),
                request.assetIdentifier(),
                fetchResult.content(),
                "endpoint-sbom.json",
                fetchResult.metadata(),
                null
        );
    }

    @Transactional(readOnly = true)
    public com.prototype.vulnwatch.domain.SbomUpload getSbomUpload(Tenant tenant, java.util.UUID sbomUploadId) {
        return sbomUploadSupportService.withTenant(tenant, () -> sbomUploadRepository.findById(sbomUploadId)
                .orElseThrow(() -> new IllegalArgumentException("SBOM upload not found: " + sbomUploadId)));
    }

    public record GithubGhcrIngestionSummary(
            int imagesDiscovered,
            int imagesProcessed,
            int imagesSucceeded,
            int imagesFailed,
            int componentsIngested,
            int findingsGenerated,
            String failureSummary,
            List<GithubGhcrImageIngestionResult> results
    ) {
    }

    public record GithubGhcrImageIngestionResult(
            String imageRepository,
            String assetIdentifier,
            String status,
            Integer componentsIngested,
            Integer findingsGenerated,
            String message
    ) {
    }
}
