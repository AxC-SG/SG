package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Create or edit a workaround, configuration change or compensating control.
 *
 * @param submit true proposes the fix for approval; false keeps it as a draft
 * @param version the version last read, for optimistic concurrency on edit
 */
public record FixControlRequest(
        String fixType,
        String title,
        String description,
        String severity,
        String ecosystem,
        String installationInstructions,
        String rollbackInstructions,
        String knownLimitations,
        Instant reviewDueAt,
        String controlType,
        String scopeDescription,
        String verificationMethod,
        String residualRisk,
        String owner,
        List<String> cveIds,
        List<UUID> assetIds,
        Boolean submit,
        Long version
) {}
