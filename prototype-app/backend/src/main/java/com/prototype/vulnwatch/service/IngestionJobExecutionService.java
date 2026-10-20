package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.dto.BomFetchRequest;
import com.prototype.vulnwatch.dto.BomIngestionResultResponse;
import com.prototype.vulnwatch.dto.GithubSbomIngestionRequest;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.dto.SbomIngestionResponse;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class IngestionJobExecutionService {

    private final BomIngestionOrchestrator bomIngestionOrchestrator;
    private final AwsDiscoverySyncService awsDiscovery;
    private final ServiceNowCmdbSyncService serviceNow;
    private final com.prototype.vulnwatch.repo.SyncRunRepository syncRuns;
    private final GithubSbomSourceService githubSbomSourceService;
    private final IngestionJobService ingestionJobService;

    public IngestionJobExecutionService(
            BomIngestionOrchestrator bomIngestionOrchestrator,
            GithubSbomSourceService githubSbomSourceService,
            IngestionJobService ingestionJobService,
            AwsDiscoverySyncService awsDiscovery, ServiceNowCmdbSyncService serviceNow,
            com.prototype.vulnwatch.repo.SyncRunRepository syncRuns
    ) {
        this.bomIngestionOrchestrator = bomIngestionOrchestrator;
        this.githubSbomSourceService = githubSbomSourceService;
        this.ingestionJobService = ingestionJobService;
        this.awsDiscovery = awsDiscovery;
        this.serviceNow = serviceNow;
        this.syncRuns = syncRuns;
    }

    public ExecutionOutcome execute(Tenant tenant, IngestionJob job) throws IOException {
        return switch (job.getJobType()) {
            case IngestionJobService.JOB_TYPE_REMOTE_ENDPOINT -> executeEndpointJob(tenant, job);
            case IngestionJobService.JOB_TYPE_GITHUB_REPOSITORY -> executeGithubRepositoryJob(tenant, job);
            case IngestionJobService.JOB_TYPE_GITHUB_GHCR -> executeGithubGhcrJob(tenant, job);
            case IngestionJobService.JOB_TYPE_AWS_DISCOVERY -> executeConnector(tenant, job, true);
            case IngestionJobService.JOB_TYPE_SERVICENOW_CMDB -> executeConnector(tenant, job, false);
            default -> throw new IOException("Unsupported ingestion job type: " + job.getJobType());
        };
    }

    private ExecutionOutcome executeConnector(Tenant tenant, IngestionJob job, boolean aws) {
        var payload = ingestionJobService.readPayload(job, IngestionJobService.ConnectorJobPayload.class);
        if (aws) awsDiscovery.executeQueuedRun(tenant.getId(), payload.configId(), payload.runId(), payload.triggerMode(), payload.targetId());
        else serviceNow.executeQueuedRun(tenant.getId(), payload.configId(), payload.runId(), payload.triggerMode());
        var run = syncRuns.findById(payload.runId()).orElseThrow();
        if ("failed".equalsIgnoreCase(run.getStatus())) {
            throw new IllegalStateException("Connector execution failed; inspect its recorded sync run");
        }
        return new ExecutionOutcome(null, ingestionJobService.toJson(Map.of("syncRunId", payload.runId(), "status", run.getStatus())));
    }

    private ExecutionOutcome executeEndpointJob(Tenant tenant, IngestionJob job) throws IOException {
        IngestionJobPayloads.EndpointIngestionPayload payload = ingestionJobService.readPayload(
                job,
                IngestionJobPayloads.EndpointIngestionPayload.class
        );
        BomIngestionResultResponse response = bomIngestionOrchestrator.ingestFromUrl(
                tenant,
                new BomFetchRequest(
                        payload.bomType() == null ? BomType.SBOM : payload.bomType(),
                        payload.assetType(),
                        payload.assetName(),
                        payload.assetIdentifier(),
                        payload.sourceUrl(),
                        payload.sourceLabel(),
                        payload.supplier(),
                        ingestionJobService.decrypt(payload.encryptedAuthorizationHeader())
                )
        );
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("bomId", response.bomId());
        result.put("assetId", response.assetId());
        result.put("componentsIngested", response.componentCount());
        result.put("findingsGenerated", response.findingsGenerated());
        result.put("bomType", response.bomType());
        result.put("format", response.format());
        result.put("formatVersion", response.formatVersion());
        result.put("specFamily", response.specFamily());
        result.put("documentFormat", response.documentFormat());
        result.put("supportLevel", response.supportLevel());
        result.put("supported", response.supported());
        result.put("warnings", response.warnings());
        result.put("action", response.action());
        result.put("status", response.status());
        return new ExecutionOutcome(null, ingestionJobService.toJson(result));
    }

    private ExecutionOutcome executeGithubRepositoryJob(Tenant tenant, IngestionJob job) throws IOException {
        IngestionJobPayloads.GithubRepositoryIngestionPayload payload = ingestionJobService.readPayload(
                job,
                IngestionJobPayloads.GithubRepositoryIngestionPayload.class
        );
        githubSbomSourceService.processRepositoryJob(
                tenant,
                payload.syncRunId(),
                payload.sourceId(),
                new GithubSbomIngestionRequest(
                        payload.owner(),
                        payload.repo(),
                        payload.includeAllRepos(),
                        payload.assetType(),
                        payload.assetName(),
                        payload.assetIdentifier(),
                        payload.path()
                )
        );
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("syncRunId", payload.syncRunId());
        result.put("sourceId", payload.sourceId());
        return new ExecutionOutcome(null, ingestionJobService.toJson(result));
    }

    private ExecutionOutcome executeGithubGhcrJob(Tenant tenant, IngestionJob job) throws IOException {
        IngestionJobPayloads.GithubGhcrIngestionPayload payload = ingestionJobService.readPayload(
                job,
                IngestionJobPayloads.GithubGhcrIngestionPayload.class
        );
        githubSbomSourceService.processGhcrJob(tenant, payload.syncRunId(), payload.sourceId(), payload.owner());
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("syncRunId", payload.syncRunId());
        result.put("sourceId", payload.sourceId());
        result.put("owner", payload.owner());
        return new ExecutionOutcome(null, ingestionJobService.toJson(result));
    }

    public record ExecutionOutcome(
            SbomUpload sbomUpload,
            String resultJson
    ) {
    }
}
