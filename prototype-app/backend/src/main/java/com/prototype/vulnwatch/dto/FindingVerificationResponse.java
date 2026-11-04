package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record FindingVerificationResponse(
        UUID findingId,
        String workflowSubstate,
        String targetState,
        boolean verificationRequired,
        String verificationStatus,
        String verificationEvidence,
        Instant verificationRequestedAt,
        Instant verificationCompletedAt,
        String verificationActor
) {
}
