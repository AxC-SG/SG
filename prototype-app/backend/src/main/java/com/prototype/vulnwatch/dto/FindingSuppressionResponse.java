package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record FindingSuppressionResponse(
        UUID id,
        UUID findingId,
        String findingKind,
        String severityAtRequest,
        String requestedBy,
        Instant requestedAt,
        Instant decisionDueAt,
        String reason,
        String compensatingControl,
        Instant proposedSuppressedUntil,
        String status,
        String decidedBy,
        Instant decidedAt,
        String decisionReason,
        UUID appliedEventId
) {}
