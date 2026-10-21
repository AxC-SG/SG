package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingsFilter;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class FindingListProjectionService {

    private final FindingProjectionRefreshService findingProjectionRefreshService;
    private final FindingProjectionStatusService findingProjectionStatusService;
    private final FindingProjectionQueryService findingProjectionQueryService;

    public FindingListProjectionService(
            FindingProjectionRefreshService findingProjectionRefreshService,
            FindingProjectionStatusService findingProjectionStatusService,
            FindingProjectionQueryService findingProjectionQueryService
    ) {
        this.findingProjectionRefreshService = findingProjectionRefreshService;
        this.findingProjectionStatusService = findingProjectionStatusService;
        this.findingProjectionQueryService = findingProjectionQueryService;
    }

    public int refreshTenant(Tenant tenant) {
        return findingProjectionRefreshService.refreshTenant(tenant);
    }

    public int refreshTenantWithSource(Tenant tenant) {
        return findingProjectionRefreshService.refreshTenantWithSource(tenant);
    }

    public void ensureTenantProjection(Tenant tenant) {
        findingProjectionQueryService.ensureTenantProjection(tenant);
    }

    public ProjectionPage queryPage(Tenant tenant, FindingsFilter filter, String cursor, int limit) {
        return findingProjectionQueryService.queryPage(tenant, filter, cursor, limit);
    }

    public List<ProjectionRecord> loadRows(Tenant tenant, FindingsFilter filter) {
        return findingProjectionQueryService.loadRows(tenant, filter);
    }

    public List<com.prototype.vulnwatch.dto.FindingCountBucketResponse> groupCounts(Tenant tenant, FindingsFilter filter, String field) {
        return findingProjectionQueryService.groupCounts(tenant, filter, field);
    }

    public ProjectionStatus getProjectionStatus(Tenant tenant) {
        return findingProjectionStatusService.getProjectionStatus(tenant);
    }

    public ProjectionStatus inspectProjectionStatus(Tenant tenant) {
        return findingProjectionStatusService.inspectProjectionStatus(tenant);
    }

    public record ProjectionPage(List<UUID> findingIds, long totalItems, String nextCursor) {
    }

    public record ProjectionRecord(
            UUID findingId,
            String severity,
            String status,
            String decisionState,
            String creationSource,
            String matchMethod,
            String vexStatus,
            String vexFreshness,
            String vexProvider,
            double confidenceScore,
            String vulnerabilityId,
            String packageName,
            String ecosystem,
            String ownerGroup,
            String assignedTo,
            String incidentId,
            Instant dueAt,
            String assetName,
            String supportGroup,
            boolean patchAvailable,
            Instant suppressedUntil,
            double riskScore,
            Instant updatedAt,
            Instant createdAt,
            Instant firstObservedAt
    ) {
        public boolean isOpen() {
            return FindingStatus.OPEN.name().equalsIgnoreCase(status);
        }
    }

    public record ProjectionStatus(
            Instant lastComputedAt,
            long findingCount,
            long sourceFindingCount,
            Long lastRebuildDurationMs,
            boolean stale,
            long driftCount
    ) {
        public boolean missing() {
            return lastComputedAt == null;
        }

        public static ProjectionStatus empty() {
            return new ProjectionStatus(null, 0L, 0L, null, true, 0L);
        }

        public static ProjectionStatus missing(long sourceFindingCount) {
            return new ProjectionStatus(null, 0L, sourceFindingCount, null, true, sourceFindingCount);
        }
    }
}
