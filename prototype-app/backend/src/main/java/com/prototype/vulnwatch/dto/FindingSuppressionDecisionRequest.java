package com.prototype.vulnwatch.dto;

import jakarta.validation.constraints.NotBlank;

public record FindingSuppressionDecisionRequest(@NotBlank String decision, String reason) {}
