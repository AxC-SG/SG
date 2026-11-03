package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotBlank;
import java.util.UUID;

public record FindingVerificationRequest(
        @NotBlank String action,
        String targetState,
        String evidence,
        UUID assessmentRunId
) {
}
