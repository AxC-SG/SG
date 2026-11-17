package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

/** An observation-only diagnostic; absence of a gap does not certify source completeness. */
public record NvdObservedGapsResponse(String feedKey, Instant from, Instant to,
                                      int observedWindowCount, List<Interval> unobservedIntervals,
                                      String historicalCoverageStatus) {
    public record Interval(Instant from, Instant to) {}
}
