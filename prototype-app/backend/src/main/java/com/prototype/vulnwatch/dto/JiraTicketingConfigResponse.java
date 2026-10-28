package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record JiraTicketingConfigResponse(
        UUID id,
        boolean configured,
        String baseUrl,
        String authType,
        String username,
        boolean hasCredentialSecret,
        String projectKey,
        String issueTypeId,
        String issueTypeName,
        String defaultLabels,
        boolean includePriority,
        boolean enabled,
        String lastTestStatus,
        String lastTestMessage,
        Instant lastTestedAt
) {
}
