package com.prototype.vulnwatch.dto;

import java.util.List;

public record GcpDiscoveryTargetRequest(
        String projectId,
        String displayName,
        Boolean enabled,
        List<String> resourceTypes
) {}
