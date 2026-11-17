package com.prototype.vulnwatch.dto;

import java.util.List;
import java.util.UUID;

public record PlatformObservationPageResponse(
        List<Item> items,
        int size,
        boolean hasMore,
        UUID nextAfterId
) {
    public record Item(UUID id, PlatformVulnIntelDetailResponse.SourceObservation observation) {}
}
