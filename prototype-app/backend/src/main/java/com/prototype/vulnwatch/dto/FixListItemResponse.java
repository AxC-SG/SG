package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * One row of a Fix Intelligence list.
 *
 * @param coveragePercent remediated / applicable assets, capped at 100; null when no asset applies
 */
public record FixListItemResponse(
        UUID id,
        String displayId,
        String title,
        String fixType,
        String severity,
        String ecosystem,
        String status,
        List<String> sources,
        long applicableAssets,
        long remediatedAssets,
        Integer coveragePercent,
        long cveCount,
        Instant updatedAt
) {}
