package com.prototype.vulnwatch.dto;

import java.util.List;

public record HostAssetDetailResponse(
        HostAssetSummaryResponse host,
        BomEvidenceSummaryResponse bomEvidence,
        List<HostAliasResponse> aliases,
        List<HostSoftwareInstanceResponse> software,
        List<HostFindingResponse> findings,
        List<HostApplicableCveResponse> applicableCves,
        /** Resolved ownership envelope; null while inventory ownership is not canonical (see {@link AssetResponse#ownership}). */
        com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary ownership
) {
}
