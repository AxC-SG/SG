package com.prototype.vulnwatch.dto;

import java.util.List;
import java.util.UUID;
import com.prototype.vulnwatch.service.CatalogPolicyEvaluator.Facts;

public final class CatalogPolicyPreview {
    private CatalogPolicyPreview() {}
    public record Request(CatalogPolicy policy, UUID afterId, Long expectedGeneration, String expectedOverrideState, String expectedSourceState) {
        public Request(CatalogPolicy policy, UUID afterId, Long expectedGeneration) {
            this(policy, afterId, expectedGeneration, null, null);
        }
    }
    public record Snapshot(long generation, String overrideState, String sourceState) {}
    /** Counts are per batch, never a claim of complete corpus coverage. */
    public record Response(long generation, int scanned, int matched, UUID nextAfterId,
                           boolean complete, List<Match> matches, String overrideState, String sourceState) {}
    /** Current-row provenance only; a payload fingerprint is not immutable source-version history. */
    public record FactEvidence(UUID observationId, String sourceSystem, String sourceRecordId,
                               String payloadHash, String cvssVersion) {}
    public record Attribution(FactEvidence publicationYear, FactEvidence cvss,
                              FactEvidence epss, FactEvidence cisaKev, FactEvidence sourcePresence) {}
    public record Match(UUID id, String externalId, Facts facts, String reason, Attribution attribution) {}
}
