package com.prototype.vulnwatch.dto;

import java.util.List;

public record CloudResourcePageResponse(
        List<CloudResourceResponse> items,
        int page,
        int size,
        long totalItems,
        int totalPages,
        Facets facets
) {
    public record FacetValue(String value, long count) {}

    public record Facets(
            List<FacetValue> providers,
            List<FacetValue> accounts,
            List<FacetValue> regions,
            List<FacetValue> resourceTypes,
            List<FacetValue> states
    ) {}
}
