package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AdvisoryBatchRequest;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.dto.NvdFullSyncRequest;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.dto.SbomUploadEvidencePageResponse;
import com.prototype.vulnwatch.dto.SbomUploadEvidenceResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.dto.VexAssertionRepairSummaryResponse;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.SbomIngestionService;
import com.prototype.vulnwatch.service.VulnerabilityIngestionService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class IngestionController {

    private final WorkspaceService workspaceService;
    private final SbomIngestionService sbomIngestionService;
    private final VulnerabilityIngestionService vulnerabilityIngestionService;
    private final IngestionJobService ingestionJobService;
    private final RequestActorService requestActorService;
    private final AuditEventService auditEventService;

    public IngestionController(
            WorkspaceService workspaceService,
            SbomIngestionService sbomIngestionService,
            VulnerabilityIngestionService vulnerabilityIngestionService,
            IngestionJobService ingestionJobService,
            RequestActorService requestActorService,
            AuditEventService auditEventService
    ) {
        this.workspaceService = workspaceService;
        this.sbomIngestionService = sbomIngestionService;
        this.vulnerabilityIngestionService = vulnerabilityIngestionService;
        this.ingestionJobService = ingestionJobService;
        this.requestActorService = requestActorService;
        this.auditEventService = auditEventService;
    }

    @PostMapping("/sbom-fetch")
    public ResponseEntity<IngestionJobAcceptedResponse> fetchSbomFromEndpoint(
            @Valid @RequestBody SbomEndpointIngestionRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        IngestionJobAcceptedResponse response = ingestionJobService.enqueueEndpointJob(
                tenant,
                request,
                requestActorService.currentActor().userId()
        );
        auditEventService.record("inventory.sbom.fetch.queued", "ingestion_job", response.jobId().toString(), null);
        return ResponseEntity.accepted().body(response);
    }

    @GetMapping("/ingestions")
    public SbomUploadEvidencePageResponse listIngestions(
            @RequestParam(required = false) String sourceSystem,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return sbomIngestionService.listUploadsPage(tenant, sourceSystem, page, size);
    }

    @PostMapping("/ingestion/nvd-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncNvd(@RequestParam(defaultValue = "24") int lookbackHours) {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerNvdSync(lookbackHours);
        auditEventService.record("platform.vulnerability_feed.nvd_sync", "sync_run", response.runId() == null ? null : response.runId().toString(),
                "{\"lookbackHours\":" + lookbackHours + "}");
        return response;
    }

    @PostMapping("/ingestion/nvd-full-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncNvdFull(@RequestBody(required = false) NvdFullSyncRequest request) {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerNvdFullSync(request == null ? null : request.apiKey());
        auditEventService.record("platform.vulnerability_feed.nvd_full_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/nvd-cve/{cveId}")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public IngestionResult refreshCveFromNvd(@PathVariable String cveId) {
        IngestionResult response = vulnerabilityIngestionService.refreshSingleCveFromNvd(cveId);
        auditEventService.record("platform.vulnerability_feed.nvd_cve_refresh", "vulnerability", cveId, null);
        return response;
    }

    @PostMapping("/ingestion/kev-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncKev() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerKevSync();
        auditEventService.record("platform.vulnerability_feed.kev_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/ghsa-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncGhsa() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerGhsaSync();
        auditEventService.record("platform.vulnerability_feed.ghsa_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/euvd-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncEuvd() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerEuvdSync();
        auditEventService.record("platform.vulnerability_feed.euvd_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/jvn-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncJvn() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerJvnSync();
        auditEventService.record("platform.vulnerability_feed.jvn_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/csaf/microsoft-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncMicrosoftCsaf() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerMicrosoftCsafSync();
        auditEventService.record("platform.vulnerability_feed.microsoft_csaf_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/csaf/redhat-sync")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse syncRedhatCsaf() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerRedhatCsafSync();
        auditEventService.record("platform.vulnerability_feed.redhat_csaf_sync", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/vex-assertion-repair")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse repairVexAssertions() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerVexAssertionRepair();
        auditEventService.record("platform.vulnerability_feed.vex_assertion_repair", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @PostMapping("/ingestion/vex-rollout-backfill")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public SyncTriggerResponse runVexRolloutBackfill() {
        SyncTriggerResponse response = vulnerabilityIngestionService.triggerVexRolloutBackfill();
        auditEventService.record("platform.vulnerability_feed.vex_rollout_backfill", "sync_run", response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @GetMapping("/ingestion/vex-assertion-repair/summary")
    public VexAssertionRepairSummaryResponse getVexAssertionRepairSummary() {
        return vulnerabilityIngestionService.getVexAssertionRepairSummary();
    }

    @PostMapping("/ingestion/advisories")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public IngestionResult ingestAdvisories(@Valid @RequestBody AdvisoryBatchRequest request) {
        IngestionResult response = vulnerabilityIngestionService.ingestAdvisories(request);
        auditEventService.record("platform.vulnerability_feed.advisory_ingest", "advisory_batch", null, null);
        return response;
    }

}
