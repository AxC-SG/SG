package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record GcpDiscoveryConfigResponse(
        UUID id,
        boolean configured,
        boolean hasCredential,
        String serviceAccountEmail,
        String keyProjectId,
        boolean enabled,
        boolean autoSyncEnabled,
        int intervalMinutes,
        List<String> requiredRoles,
        List<String> supportedResourceTypes,
        String lastTestStatus,
        String lastTestMessage,
        Instant lastTestedAt,
        Instant lastSyncAt
) {}
