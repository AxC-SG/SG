package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/** One cloud-discovered asset (AWS, Azure or GCP) for the Cloud Resources inventory view. */
public record CloudResourceResponse(
        UUID id,
        String name,
        String identifier,
        String assetType,
        String state,
        String provider,
        String accountId,
        String region,
        String availabilityZone,
        String resourceType,
        String instanceType,
        String network,
        String subnet,
        Map<String, String> labels,
        Instant createdAt,
        Instant lastSeenAt
) {}
