package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.UUID;

/** State of one pushed BOM document: ACTIVE, SUPERSEDED, or FAILED. */
public record BomIngestStatusResponse(
        UUID bomId,
        UUID sourceId,
        String bomType,
        String state,
        int componentCount,
        String format,
        String formatVersion,
        String pipeline,
        String build,
        String correlator,
        Instant ingestedAt,
        UUID supersededBy
) {}
