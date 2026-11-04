package com.prototype.vulnwatch.dto;

import java.util.List;
import java.util.UUID;

/**
 * Result of a pipeline push. {@code action} is CREATED, REPLACED, or UNCHANGED when the same
 * document was already the source's current version (a retried pipeline step).
 */
public record BomIngestResponse(
        UUID bomId,
        UUID assetId,
        UUID sourceId,
        String bomType,
        String format,
        String formatVersion,
        String documentFormat,
        boolean supported,
        List<String> warnings,
        int componentCount,
        int findingsGenerated,
        String status,
        String action,
        String statusUrl,
        /** Single-job CI gate token for a CBOM push; returned once, read only with this document's status. */
        String gateToken,
        String gateEnvironment
) {
    public BomIngestResponse(UUID bomId, UUID assetId, UUID sourceId, String bomType, String format, String formatVersion,
            String documentFormat, boolean supported, List<String> warnings, int componentCount, int findingsGenerated,
            String status, String action, String statusUrl) {
        this(bomId, assetId, sourceId, bomType, format, formatVersion, documentFormat, supported, warnings, componentCount,
                findingsGenerated, status, action, statusUrl, null, null);
    }

    public BomIngestResponse withGate(String token, String environment) {
        return new BomIngestResponse(bomId, assetId, sourceId, bomType, format, formatVersion, documentFormat, supported, warnings,
                componentCount, findingsGenerated, status, action, statusUrl, token, environment);
    }
}
