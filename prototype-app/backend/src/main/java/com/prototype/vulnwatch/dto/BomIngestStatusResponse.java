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
        UUID supersededBy,
        /** Present only when the request carries this document's gate token. */
        com.prototype.vulnwatch.service.cbom.CbomGateService.GateStatus gate
) {
    public BomIngestStatusResponse(UUID bomId, UUID sourceId, String bomType, String state, int componentCount, String format,
            String formatVersion, String pipeline, String build, String correlator, Instant ingestedAt, UUID supersededBy) {
        this(bomId, sourceId, bomType, state, componentCount, format, formatVersion, pipeline, build, correlator, ingestedAt,
                supersededBy, null);
    }

    public BomIngestStatusResponse withGate(com.prototype.vulnwatch.service.cbom.CbomGateService.GateStatus value) {
        return new BomIngestStatusResponse(bomId, sourceId, bomType, state, componentCount, format, formatVersion, pipeline, build,
                correlator, ingestedAt, supersededBy, value);
    }
}
