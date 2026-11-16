package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;

public record InventoryComponentResponse(
        UUID id,
        UUID assetId,
        String assetName,
        String assetIdentifier,
        String assetType,
        String componentStatus,
        String ecosystem,
        String packageName,
        String packageGroup,
        String license,
        String scope,
        String version,
        String normalizedName,
        String normalizedVersion,
        String purl,
        String componentDigest,
        String softwareIdentity,
        int cveCount,
        int impactedCveCount,
        List<String> cveIds,
        String sourceSystem,
        String sourceType,
        String sourceReference,
        Instant uploadedAt,
        Instant lastObservedAt,
        Instant retiredAt,
        boolean needsReview,
        int reviewItemCount,
        boolean reviewMissingVersion,
        boolean reviewUnmappedSoftware,
        boolean reviewLowConfidenceAlias,
        boolean reviewDiscoveryModel,
        String eolSlug,
        String eolCycle,
        LocalDate eolDate,
        Boolean isEol,
        Integer eolDaysRemaining,
        /** Resolved owner of the component's occurrence (Phase 0B §3.7); null unless CLOUD_BOM inventory reads are canonical. */
        com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary ownership
) {
}
