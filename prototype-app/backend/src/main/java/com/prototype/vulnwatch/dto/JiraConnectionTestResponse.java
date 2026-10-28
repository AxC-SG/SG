package com.prototype.vulnwatch.dto;

import java.time.Instant;

public record JiraConnectionTestResponse(
        String status,
        String message,
        boolean credentialsValid,
        boolean projectReachable,
        Instant testedAt
) {
}
