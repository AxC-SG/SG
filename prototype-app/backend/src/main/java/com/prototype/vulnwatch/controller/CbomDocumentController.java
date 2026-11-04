package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.service.cbom.CbomReportService;
import com.prototype.vulnwatch.service.cbom.CbomSemanticDiffService;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Document-scoped CBOM resources (plan section 7): semantic diff and persisted reports for one ingested CBOM. */
@RestController
@RequestMapping("/api/bom/inventory/{bomId}")
public class CbomDocumentController {

    public record ReportRequest(UUID assessmentRunId, String format) { }

    private final WorkspaceService workspace;
    private final RequestActorService actors;
    private final CbomSemanticDiffService diffs;
    private final CbomReportService reports;

    public CbomDocumentController(WorkspaceService workspace, RequestActorService actors, CbomSemanticDiffService diffs,
            CbomReportService reports) {
        this.workspace = workspace; this.actors = actors; this.diffs = diffs; this.reports = reports;
    }

    @GetMapping("/diff")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','READ_ONLY_AUDITOR')")
    public CbomSemanticDiffService.SemanticDiff diff(@PathVariable UUID bomId, @RequestParam(required = false) UUID baselineBomId) {
        return diffs.diff(workspace.getWorkspace(), bomId, baselineBomId);
    }

    @GetMapping("/reports")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','READ_ONLY_AUDITOR')")
    public List<CbomReportService.ReportMetadata> reports(@PathVariable UUID bomId) {
        return reports.list(workspace.getWorkspace(), bomId);
    }

    @PostMapping("/reports")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN')")
    @SensitiveTenantAction("cbom.report.requested")
    public ResponseEntity<CbomReportService.ReportMetadata> requestReport(@PathVariable UUID bomId,
            @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey, @RequestBody ReportRequest request) {
        if (request == null || request.assessmentRunId() == null) throw new IllegalArgumentException("assessmentRunId is required");
        var report = reports.request(workspace.getWorkspace(), bomId, request.assessmentRunId(), request.format(), idempotencyKey, actor());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(report);
    }

    @GetMapping("/reports/{reportId}")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','READ_ONLY_AUDITOR')")
    public CbomReportService.ReportMetadata report(@PathVariable UUID bomId, @PathVariable UUID reportId) {
        return reports.get(workspace.getWorkspace(), bomId, reportId);
    }

    @GetMapping("/reports/{reportId}/download")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','READ_ONLY_AUDITOR')")
    public ResponseEntity<byte[]> download(@PathVariable UUID bomId, @PathVariable UUID reportId) {
        var download = reports.download(workspace.getWorkspace(), bomId, reportId, actor());
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE, download.contentType())
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + download.filename() + "\"")
                .header(HttpHeaders.CACHE_CONTROL, "no-store")
                .header("X-Content-Type-Options", "nosniff")
                .header("X-Content-SHA256", download.checksum())
                .header("X-Report-Signature-Status", "UNSIGNED")
                .body(download.content());
    }

    @PostMapping("/reports/{reportId}/regenerate")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN')")
    @SensitiveTenantAction("cbom.report.regenerated")
    public ResponseEntity<CbomReportService.ReportMetadata> regenerate(@PathVariable UUID bomId, @PathVariable UUID reportId,
            @RequestHeader(name = "Idempotency-Key", required = false) String idempotencyKey) {
        var report = reports.regenerate(workspace.getWorkspace(), bomId, reportId, idempotencyKey, actor());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(report);
    }

    private String actor() {
        var actor = actors.currentActor();
        return actor == null ? "api" : actor.userId();
    }
}
