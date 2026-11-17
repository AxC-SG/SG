package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

/** Operator plan from successful interval observations, not a source-completeness certificate. */
public record NvdBaselinePlanResponse(String feedKey, Instant from, Instant to,
                                      List<Partition> partitions, String historicalCoverageStatus) {
    public record Partition(Instant from, Instant to, int observedWindowCount,
                            List<NvdObservedGapsResponse.Interval> unobservedIntervals) {}
}
