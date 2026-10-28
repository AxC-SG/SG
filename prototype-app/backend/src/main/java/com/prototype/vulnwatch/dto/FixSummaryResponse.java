package com.prototype.vulnwatch.dto;

import java.util.List;

/** Fix Intelligence KPI cards and distributions for one view (all, patches, ...). */
public record FixSummaryResponse(
        long totalFixes,
        long criticalSeverity,
        long highPriority,
        long ecosystemsCovered,
        List<Bucket> severityDistribution,
        List<Bucket> ecosystems
) {
    /** {@code percent} is count / total, 0 when there are no fixes (never NaN). */
    public record Bucket(String key, long count, int percent) {}
}
