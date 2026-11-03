package com.prototype.vulnwatch.dto;

public record CbomSuppressionSettingsRequest(
        Boolean requireDistinctSuppressionApprover,
        Integer suppressionRequestDeadlineDays,
        Integer lowSuppressionMaxDays,
        Integer mediumSuppressionMaxDays,
        Integer highSuppressionMaxDays,
        Integer criticalSuppressionMaxDays
) {}
