package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** A fix with its CVEs, tool sources, control detail and per-asset deployment state. */
public record FixDetailResponse(
        UUID id,
        String displayId,
        String title,
        String description,
        String fixType,
        String severity,
        String ecosystem,
        String status,
        String origin,
        boolean editable,
        String owner,
        String proposedBy,
        String approvedBy,
        Instant approvedAt,
        Instant reviewDueAt,
        String installationInstructions,
        String rollbackInstructions,
        String knownLimitations,
        Boolean requiresReboot,
        Integer estimatedDowntimeMinutes,
        long version,
        List<Cve> cves,
        List<PatchSource> patchSources,
        Control control,
        long applicableAssets,
        long remediatedAssets,
        Integer coveragePercent,
        long assetTotal,
        List<AssetState> assets,
        Instant createdAt,
        Instant updatedAt
) {
    public record Cve(String cveId, String source, String confidence, String severity, boolean inKev) {}

    public record PatchSource(
            String provider,
            String externalId,
            String kbArticle,
            String bulletinId,
            String vendor,
            String product,
            String classification,
            String vendorSeverity,
            Instant releaseDate,
            boolean superseded,
            String infoUrl,
            Instant lastSeenAt
    ) {}

    public record Control(String controlType, String scopeDescription, String verificationMethod, String residualRisk) {}

    public record AssetState(
            UUID assetId,
            String assetName,
            String assetIdentifier,
            String provider,
            String status,
            String deploymentName,
            Instant scheduledAt,
            Instant deadlineAt,
            Instant installedAt,
            String errorCode,
            Instant lastReportedAt
    ) {}
}
