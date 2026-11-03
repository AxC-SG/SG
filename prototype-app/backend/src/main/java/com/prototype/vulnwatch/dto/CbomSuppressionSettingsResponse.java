package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record CbomSuppressionSettingsResponse(
        UUID tenantId,
        boolean requireDistinctSuppressionApprover,
        int suppressionRequestDeadlineDays,
        int lowSuppressionMaxDays,
        int mediumSuppressionMaxDays,
        int highSuppressionMaxDays,
        int criticalSuppressionMaxDays,
        String updatedBy,
        Instant updatedAt,
        long version
) {}
