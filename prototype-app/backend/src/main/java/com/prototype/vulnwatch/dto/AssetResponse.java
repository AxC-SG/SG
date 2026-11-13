package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record AssetResponse(
        UUID id,
        String type,
        String name,
        String identifier,
        String serviceName,
        String environment,
        String ownerTeam,
        String ownerEmail,
        String businessCriticality,
        String state,
        Instant lastInventoryAt,
        Instant lastCmdbSyncAt,
        /**
         * Resolved ownership envelope (ownership plan §7.5, §9.3), separate from the raw {@code ownerTeam}/{@code ownerEmail}
         * source evidence above. Null while no ownership domain is canonical for inventory; then the legacy fields apply.
         */
        com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary ownership
) {
}
