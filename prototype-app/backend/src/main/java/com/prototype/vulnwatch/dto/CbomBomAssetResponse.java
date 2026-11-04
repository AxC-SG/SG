package com.prototype.vulnwatch.dto;

import java.util.List;

/** One cryptographic asset reported by a CBOM document, with the findings raised against it. */
public record CbomBomAssetResponse(
        CbomComponentResponse asset,
        List<CbomRiskFindingResponse> findings
) {}
