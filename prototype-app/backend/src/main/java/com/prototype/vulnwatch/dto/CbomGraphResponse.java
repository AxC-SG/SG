package com.prototype.vulnwatch.dto;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

public record CbomGraphResponse(List<Node> nodes, List<Edge> edges, boolean truncated, int depth) {
    /** label/kind/openFindings/highestSeverity are filled for COMPONENT and ASSET nodes the tenant owns. */
    public record Node(String type, UUID id, int distance, String label, String kind, int openFindings, String highestSeverity) {
        public Node(String type, UUID id, int distance) { this(type, id, distance, null, null, 0, null); }
    }
    public record Edge(UUID id, String sourceType, UUID sourceId, String targetType, UUID targetId,
                       String relationshipType, String evidenceKind, BigDecimal confidence,
                       String evidenceSummary, Instant validUntil, boolean stale) {}

    /** Blast radius of one cryptographic asset: what a weakness in it can reach within the bounded graph. */
    public record BlastRadius(UUID componentId, CbomGraphResponse graph, List<AffectedApplication> applications,
            int affectedComponents, int openFindings, Map<String, Integer> openFindingsBySeverity) {}
    public record AffectedApplication(UUID assetId, String name, String environment, int distance) {}
}
