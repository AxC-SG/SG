package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record PatchConnectorConfigResponse(
        UUID id,
        String provider,
        String displayName,
        boolean configured,
        boolean hasSecret,
        String baseUrl,
        String directoryId,
        String clientId,
        String username,
        boolean enabled,
        boolean autoSyncEnabled,
        int intervalMinutes,
        String lastTestStatus,
        String lastTestMessage,
        Instant lastTestedAt,
        Instant lastSyncAt
) {}
