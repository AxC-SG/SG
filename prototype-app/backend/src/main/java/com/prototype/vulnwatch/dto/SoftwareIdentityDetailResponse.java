package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

public record SoftwareIdentityDetailResponse(
        UUID id,
        String displayName,
        String canonicalKey,
        String vendor,
        String product,
        String normalizedKey,
        String purl,
        String cpe23,
        List<String> assetTypes,
        List<String> ecosystems,
        List<String> sourceSystems,
        String eolSlug,
        boolean mappingConfirmed,
        boolean needsEolMapping,
        long assetCount,
        long componentCount,
        long versionCount,
        long eolComponentCount,
        long nearEolComponentCount,
        long unknownEolComponentCount,
        long openFindingCount,
        long openVulnerabilityCount,
        Instant lastObservedAt,
        BomEvidenceSummaryResponse bomEvidence,
        List<SoftwareIdentityVersionResponse> versions,
        List<SoftwareIdentityAssetResponse> assets,
        /** Owner-team coverage of this identity's occurrences (Phase 0B §3.7); null unless CLOUD_BOM inventory reads are canonical. */
        com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.IdentityCoverage ownershipCoverage
) {
}
