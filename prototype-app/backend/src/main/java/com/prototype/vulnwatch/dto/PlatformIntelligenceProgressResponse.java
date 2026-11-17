package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Stage-specific facts; a fetched source record is never presented as a published CVE. */
public record PlatformIntelligenceProgressResponse(
        Acquisition acquisition, Publication publication, TenantDelivery tenantDelivery,
        CatalogInventory catalogInventory,
        List<SourceCoverage> sources,
        String assetEvaluationStatus) {
    public record Acquisition(UUID runId, String source, String status, long fetchedRecords,
                              long failedRecords, Instant startedAt, Instant completedAt) {}
    public record Publication(long activeGeneration, UUID activeReleaseId, Instant publishedAt,
                              long pendingReviewCandidates, long pendingPublicationJobs) {}
    public record TenantDelivery(long activeTenants, long currentTenants,
                                 long updatingTenants, long failedTenants,
                                 long staleCheckpoints) {}
    public record CatalogInventory(long canonicalRecords, long activeCanonicalRecords,
                                   long withdrawnCanonicalRecords, long sourceObservationRows) {}
    public record SourceCoverage(String source, UUID latestRunId, String latestRunStatus,
                                 long latestFetchedRecords, Instant latestCompletedAt,
                                 String historicalCoverageStatus, long observedWindowCount,
                                 long observedFilterScopeCount, Instant latestObservedIntervalEnd,
                                 String evidenceRole, String acquisitionScope,
                                 boolean tenantPolicySelectable) {}
}
