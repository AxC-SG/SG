package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

public record BomInventoryItemResponse(
        UUID id,
        UUID assetId,
        String bomType,
        String format,
        String formatVersion,
        String specFamily,
        String documentFormat,
        String serialNumber,
        String supplier,
        String sourceMethod,
        String sourceType,
        String sourceSystem,
        String sourceUrl,
        String supportLevel,
        boolean supported,
        int componentCount,
        long evidenceCount,
        long vulnerabilityLinkCount,
        long correlatedComponentCount,
        String status,
        Instant ingestedAt,
        String ingestedBy,
        // A pipeline push's build ("build:<id>") and correlator; null for other ingestion paths.
        String sourceLabel,
        String sourceReference
) {}
