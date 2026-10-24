package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingBacklogHealthResponse;
import com.prototype.vulnwatch.dto.FindingBulkWorkflowRequest;
import com.prototype.vulnwatch.dto.FindingBulkWorkflowResponse;
import com.prototype.vulnwatch.dto.FindingDistributionsResponse;
import com.prototype.vulnwatch.dto.FindingFilterValuesResponse;
import com.prototype.vulnwatch.dto.FindingProjectionStatusResponse;
import com.prototype.vulnwatch.dto.FindingQueueDefinitionResponse;
import com.prototype.vulnwatch.dto.FindingQueueUpsertRequest;
import com.prototype.vulnwatch.dto.FindingPageResponse;
import com.prototype.vulnwatch.dto.FindingResponse;
import com.prototype.vulnwatch.dto.FindingSummaryResponse;
import com.prototype.vulnwatch.dto.FindingsFilterRequest;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.FindingAnalyticsService;
import com.prototype.vulnwatch.service.FindingListProjectionService;
import com.prototype.vulnwatch.service.FindingProjectionOperationsService;
import com.prototype.vulnwatch.service.FindingQueueService;
import com.prototype.vulnwatch.service.FindingQueryService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/findings")
public class FindingController {

    private final WorkspaceService workspaceService;
    private final FindingQueryService findingQueryService;
    private final FindingAnalyticsService findingAnalyticsService;
    private final FindingProjectionOperationsService findingProjectionOperationsService;
    private final FindingQueueService findingQueueService;
    private final FindingWorkflowService findingWorkflowService;

    public FindingController(
            WorkspaceService workspaceService,
            FindingQueryService findingQueryService,
            FindingAnalyticsService findingAnalyticsService,
            FindingProjectionOperationsService findingProjectionOperationsService,
            FindingQueueService findingQueueService,
            FindingWorkflowService findingWorkflowService
    ) {
        this.workspaceService = workspaceService;
        this.findingQueryService = findingQueryService;
        this.findingAnalyticsService = findingAnalyticsService;
        this.findingProjectionOperationsService = findingProjectionOperationsService;
        this.findingQueueService = findingQueueService;
        this.findingWorkflowService = findingWorkflowService;
    }

    @GetMapping
    public FindingPageResponse list(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) String cursor,
            @RequestParam(required = false) Integer limit,
            FindingsFilterRequest filterRequest
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        var filter = findingQueueService.resolveEffectiveFilter(filterRequest.getQueueKey(), filterRequest.toFilter());
        if (cursor != null || limit != null) {
            return findingQueryService.listByTenantCursor(
                    tenant,
                    cursor,
                    limit != null ? limit : size,
                    filter
            );
        }
        return findingQueryService.listByTenantPage(tenant, page, size, filter);
    }

    @GetMapping("/groups")
    public List<com.prototype.vulnwatch.dto.FindingCountBucketResponse> groups(
            @RequestParam String field, FindingsFilterRequest filterRequest) {
        return findingAnalyticsService.groupCounts(workspaceService.getWorkspace(),
                findingQueueService.resolveEffectiveFilter(filterRequest.getQueueKey(), filterRequest.toFilter()), field);
    }

    @GetMapping("/summary")
    public FindingSummaryResponse summary(FindingsFilterRequest filterRequest) {
        Tenant tenant = workspaceService.getWorkspace();
        return findingAnalyticsService.getSummary(tenant, findingQueueService.resolveEffectiveFilter(filterRequest.getQueueKey(), filterRequest.toFilter()));
    }

    @GetMapping("/distributions")
    public FindingDistributionsResponse distributions(FindingsFilterRequest filterRequest) {
        Tenant tenant = workspaceService.getWorkspace();
        return findingAnalyticsService.getDistributions(tenant, findingQueueService.resolveEffectiveFilter(filterRequest.getQueueKey(), filterRequest.toFilter()));
    }

    @GetMapping("/backlog-health")
    public FindingBacklogHealthResponse backlogHealth(FindingsFilterRequest filterRequest) {
        Tenant tenant = workspaceService.getWorkspace();
        return findingAnalyticsService.getBacklogHealth(tenant, findingQueueService.resolveEffectiveFilter(filterRequest.getQueueKey(), filterRequest.toFilter()));
    }

    @GetMapping("/projection-status")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    public FindingProjectionStatusResponse projectionStatus() {
        Tenant tenant = projectionWorkspace();
        return toProjectionStatusResponse(findingProjectionOperationsService.inspectStatus(tenant));
    }

    @PostMapping("/projection-rebuild")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN')")
    @SensitiveTenantAction("finding.projection.rebuilt")
    public FindingProjectionStatusResponse rebuildProjection() {
        Tenant tenant = projectionWorkspace();
        return toProjectionStatusResponse(findingProjectionOperationsService.rebuild(tenant));
    }

    @GetMapping("/queues")
    public List<FindingQueueDefinitionResponse> queues() {
        Tenant tenant = workspaceService.getWorkspace();
        return findingQueueService.listQueues(tenant);
    }

    @GetMapping("/queues/{queueKey}")
    public FindingQueueDefinitionResponse queue(@PathVariable String queueKey) {
        Tenant tenant = workspaceService.getWorkspace();
        return findingQueueService.getQueue(tenant, queueKey);
    }

    @PostMapping("/queues")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("finding.queue.created")
    public FindingQueueDefinitionResponse createQueue(@RequestBody FindingQueueUpsertRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return findingQueueService.createQueue(tenant, request);
    }

    @PutMapping("/queues/{queueRef}")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("finding.queue.updated")
    public FindingQueueDefinitionResponse updateQueue(
            @PathVariable String queueRef,
            @RequestBody FindingQueueUpsertRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return findingQueueService.updateQueue(tenant, queueRef, request);
    }

    @PostMapping("/queues/{queueRef}/duplicate")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("finding.queue.duplicated")
    public FindingQueueDefinitionResponse duplicateQueue(@PathVariable String queueRef) {
        Tenant tenant = workspaceService.getWorkspace();
        return findingQueueService.duplicateQueue(tenant, queueRef);
    }

    @PostMapping("/queues/{queueRef}/default")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("finding.queue.default_set")
    public ResponseEntity<Void> setDefaultQueue(@PathVariable String queueRef) {
        Tenant tenant = workspaceService.getWorkspace();
        findingQueueService.setDefaultQueue(tenant, queueRef);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/queues/{queueRef}")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("finding.queue.deleted")
    public ResponseEntity<Void> deleteQueue(@PathVariable String queueRef) {
        Tenant tenant = workspaceService.getWorkspace();
        findingQueueService.deleteQueue(tenant, queueRef);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/filters")
    public FindingFilterValuesResponse filters() {
        Tenant tenant = workspaceService.getWorkspace();
        return findingQueryService.listAvailableFilters(tenant);
    }

    @GetMapping("/{findingId}")
    public ResponseEntity<FindingResponse> getById(@PathVariable UUID findingId,@RequestParam(defaultValue="false") boolean includeInactive) {
        Tenant tenant = workspaceService.getWorkspace();
        if (includeInactive) return findingQueryService.history(tenant,findingId).map(ResponseEntity::ok).orElse(ResponseEntity.notFound().build());
        return findingQueryService.listEntitiesByTenantAndIds(tenant, List.of(findingId))
                .stream()
                .findFirst()
                .map(f -> ResponseEntity.ok(findingQueryService.toResponse(f)))
                .orElse(ResponseEntity.notFound().build());
    }

    @PutMapping("/{findingId}/workflow")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("finding.workflow.updated")
    public Finding updateWorkflow(
            @PathVariable UUID findingId,
            @RequestBody FindingWorkflowUpdateRequest request
    ) {
        return findingWorkflowService.updateWorkflow(findingId, request);
    }

    @PostMapping("/bulk-workflow")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("finding.workflow.bulk_updated")
    public FindingBulkWorkflowResponse bulkUpdateWorkflow(
            @RequestBody FindingBulkWorkflowRequest request
    ) {
        if (request.findingIds() == null || request.findingIds().isEmpty()) {
            return new FindingBulkWorkflowResponse(0, 0, 0, "No finding IDs provided");
        }
        int targeted = request.findingIds().size();
        FindingWorkflowUpdateRequest workflowUpdate = new FindingWorkflowUpdateRequest(
                request.workflowStatus(),
                request.assignedTo(),
                null,
                request.dueAt(),
                request.suppressionReason(),
                request.suppressedUntil(),
                request.actor()
        );
        int updated = findingWorkflowService.updateWorkflowBulkByIds(request.findingIds(), workflowUpdate);
        int failed = targeted - updated;
        return new FindingBulkWorkflowResponse(targeted, updated, failed, "Bulk workflow update completed");
    }

    public record BulkDeleteRequest(List<UUID> findingIds) {}
    public record BulkDeleteResponse(int deleted, String message) {}

    @DeleteMapping("/bulk")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("finding.bulk_deleted")
    public ResponseEntity<BulkDeleteResponse> bulkDelete(@RequestBody BulkDeleteRequest request) {
        if (request.findingIds() == null || request.findingIds().isEmpty()) {
            return ResponseEntity.ok(new BulkDeleteResponse(0, "No finding IDs provided"));
        }
        int deleted = findingWorkflowService.bulkDelete(request.findingIds());
        return ResponseEntity.ok(new BulkDeleteResponse(deleted, deleted + " finding(s) permanently deleted"));
    }

    private FindingProjectionStatusResponse toProjectionStatusResponse(FindingListProjectionService.ProjectionStatus status) {
        return new FindingProjectionStatusResponse(
                status.lastComputedAt(),
                status.findingCount(),
                status.sourceFindingCount(),
                status.stale(),
                status.driftCount(),
                status.lastRebuildDurationMs()
        );
    }

    private Tenant projectionWorkspace() {
        return workspaceService.getWorkspace();
    }
}
