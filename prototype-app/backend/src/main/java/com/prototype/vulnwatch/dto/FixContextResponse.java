package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Remediation context for a CVE and/or an asset. Informational only: fixes never change
 * finding status.
 */
public record FixContextResponse(String cveId, UUID assetId, List<Item> fixes) {

    public record Item(
            UUID fixId,
            String displayId,
            String title,
            String fixType,
            String status,
            String severity,
            List<String> cveIds,
            String assetStatus,
            String assetProvider,
            Instant scheduledAt,
            Instant deadlineAt,
            Instant installedAt,
            Integer coveragePercent
    ) {}
}
