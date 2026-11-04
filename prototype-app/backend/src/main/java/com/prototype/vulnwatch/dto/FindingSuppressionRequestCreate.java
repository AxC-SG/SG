package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.time.Instant;

public record FindingSuppressionRequestCreate(
        @NotBlank String reason,
        @NotBlank String compensatingControl,
        @NotNull @Future Instant proposedSuppressedUntil
) {}
