package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Compares two completed fetch manifests; agreement is not independent source verification. */
public record NvdObservedIdComparisonResponse(
        UUID firstRunId, UUID secondRunId, String feedKey, Instant from, Instant to,
        int firstCount, int secondCount, long onlyInFirst, long onlyInSecond,
        List<String> onlyInFirstSample, List<String> onlyInSecondSample,
        boolean identical, String historicalCoverageStatus) {}
