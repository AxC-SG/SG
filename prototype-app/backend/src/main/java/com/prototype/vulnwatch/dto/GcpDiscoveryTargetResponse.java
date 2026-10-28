package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record GcpDiscoveryTargetResponse(
        UUID id,
        String projectId,
        String displayName,
        boolean enabled,
        List<String> resourceTypes,
        String lastTestStatus,
        String lastTestMessage,
        Instant lastTestedAt,
        Instant lastSyncAt
) {}
