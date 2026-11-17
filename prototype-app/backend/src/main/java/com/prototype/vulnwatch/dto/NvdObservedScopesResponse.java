package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;

/** Filter-scoped observation inventory, not verified historical source coverage. */
public record NvdObservedScopesResponse(List<Scope> items, boolean hasMore, String nextAfterFeedKey) {
    public record Scope(String feedKey, long observedWindowCount, Instant firstObservedIntervalStart,
                        Instant latestObservedIntervalEnd) {}
}
