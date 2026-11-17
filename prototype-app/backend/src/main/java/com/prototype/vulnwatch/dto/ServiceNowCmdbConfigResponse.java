package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record ServiceNowCmdbConfigResponse(
        UUID id,
        String sourceSystem,
        boolean configured,
        String baseUrl,
        String authType,
        String username,
        boolean hasCredentialSecret,
        String installTable,
        String discoveryModelTable,
        String ciTable,
        String installQuery,
        String discoveryQuery,
        String installFields,
        String discoveryFields,
        Integer pageSize,
        boolean enabled,
        boolean autoSyncEnabled,
        Integer intervalMinutes,
        String lastTestStatus,
        String lastTestMessage,
        Instant lastTestedAt,
        Instant lastSyncAt,
        String defaultAssignmentGroup
) {
}
