package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.service.AuditEventService;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * Contradiction review (plan Milestone 4). Two active CBOMs for the same asset that declare the
 * same cryptographic asset (same bom-ref) with different important claims are contradictory:
 * both claims are marked CONFLICTING and an analyst decides which source is right, or dismisses
 * the contradiction. Nothing is guessed, and contradictions whose components are no longer active
 * become OBSOLETE.
 */
@Service
public class CbomContradictionService {

    /** Important claims compared across documents: column -> claim-path leaf recorded by assessment. */
    static final Map<String, String> CLAIMS = Map.of(
            "primitive", "primitive", "key_size", "keySize", "curve", "curve", "protocol_version", "protocolVersion",
            "not_after", "notAfter", "storage_location", "storageLocation");

    public record Contradiction(UUID id, UUID assetId, String assetName, String identity, String claim, UUID componentAId,
            String documentA, String valueA, UUID componentBId, String documentB, String valueB, String status,
            Instant detectedAt, String reviewedBy, Instant reviewedAt, String reviewNote, long version) { }

    public record ReviewRequest(String decision, String note, Long version) { }

    private final JdbcTemplate jdbc;
    private final AuditEventService audit;

    public CbomContradictionService(JdbcTemplate jdbc, AuditEventService audit) { this.jdbc = jdbc; this.audit = audit; }

    /** Detects contradictions involving one CBOM's active components; runs in the caller's tenant transaction. */
    public int detect(UUID tenantId, UUID bomId) {
        jdbc.update("""
                UPDATE cbom_contradictions x SET status = 'OBSOLETE'
                 WHERE x.status = 'OPEN' AND EXISTS (SELECT 1 FROM cbom_components c
                        WHERE c.id IN (x.component_a_id, x.component_b_id) AND NOT c.active)
                """);
        int detected = 0;
        for (var claim : CLAIMS.entrySet()) {
            String column = claim.getKey();
            detected += jdbc.update("""
                    INSERT INTO cbom_contradictions (id, tenant_id, asset_id, identity, claim, component_a_id, component_b_id, value_a, value_b)
                    SELECT gen_random_uuid(), ?, mine.asset_id, 'bom-ref:' || mine.bom_ref, ?,
                           least(mine.id, other.id), greatest(mine.id, other.id),
                           CASE WHEN mine.id < other.id THEN mine.%1$s::text ELSE other.%1$s::text END,
                           CASE WHEN mine.id < other.id THEN other.%1$s::text ELSE mine.%1$s::text END
                      FROM cbom_components mine
                      JOIN cbom_components other ON other.asset_id = mine.asset_id AND other.bom_ref = mine.bom_ref
                       AND other.source_bom_id <> mine.source_bom_id AND other.active
                      JOIN bom_ingestion_records ob ON ob.id = other.source_bom_id AND ob.status = 'ACTIVE'
                     WHERE mine.source_bom_id = ? AND mine.active AND mine.bom_ref IS NOT NULL
                       AND mine.%1$s IS NOT NULL AND other.%1$s IS NOT NULL AND mine.%1$s IS DISTINCT FROM other.%1$s
                    ON CONFLICT (component_a_id, component_b_id, claim) DO NOTHING
                    """.formatted(column), tenantId, claim.getValue(), bomId);
        }
        jdbc.update("""
                UPDATE cbom_claim_assurances a SET assurance_level = 'CONFLICTING', evidence_state = 'CONFLICTING'
                  FROM cbom_contradictions x
                 WHERE x.status = 'OPEN' AND a.cbom_component_id IN (x.component_a_id, x.component_b_id)
                   AND a.claim_path LIKE '%/' || x.claim
                   AND a.assessment_run_id = (SELECT r.id FROM cbom_assessment_runs r JOIN cbom_components c ON c.source_bom_id = r.bom_id
                                               WHERE c.id = a.cbom_component_id AND r.status IN ('SUCCEEDED', 'RUNNING')
                                               ORDER BY r.created_at DESC LIMIT 1)
                """);
        return detected;
    }

    @Transactional(readOnly = true)
    public List<Contradiction> list(String status, int limit) {
        String normalized = status == null || status.isBlank() ? "OPEN" : status.trim().toUpperCase(Locale.ROOT);
        if (!List.of("OPEN", "ACCEPTED_A", "ACCEPTED_B", "DISMISSED", "OBSOLETE", "ALL").contains(normalized)) {
            throw new IllegalArgumentException("Unsupported contradiction status: " + status);
        }
        return jdbc.query(SELECT + (normalized.equals("ALL") ? "" : " WHERE x.status = ?")
                + " ORDER BY x.detected_at DESC LIMIT ?", (rs, row) -> row(rs),
                normalized.equals("ALL") ? new Object[] {Math.max(1, Math.min(500, limit))}
                        : new Object[] {normalized, Math.max(1, Math.min(500, limit))});
    }

    /** Records an analyst decision with optimistic concurrency and restores the accepted claim's assurance. */
    @Transactional
    public Contradiction review(UUID id, ReviewRequest request, String actor) {
        if (request == null || request.decision() == null) throw new IllegalArgumentException("decision is required");
        String decision = request.decision().trim().toUpperCase(Locale.ROOT);
        if (!List.of("ACCEPTED_A", "ACCEPTED_B", "DISMISSED").contains(decision)) {
            throw new IllegalArgumentException("decision must be ACCEPTED_A, ACCEPTED_B or DISMISSED");
        }
        if (request.note() == null || request.note().isBlank()) throw new IllegalArgumentException("note is required");
        Contradiction current = jdbc.query(SELECT + " WHERE x.id = ? FOR UPDATE OF x", (rs, row) -> row(rs), id).stream().findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Contradiction not found"));
        if (request.version() != null && request.version() != current.version()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "The contradiction changed since it was loaded; reload and review again");
        }
        if (!"OPEN".equals(current.status())) throw new ResponseStatusException(HttpStatus.CONFLICT, "Only open contradictions can be reviewed");
        jdbc.update("""
                UPDATE cbom_contradictions SET status = ?, reviewed_by = ?, reviewed_at = now(), review_note = ?, version = version + 1
                 WHERE id = ?
                """, decision, actor, request.note().trim(), id);
        List<UUID> restored = switch (decision) {
            case "ACCEPTED_A" -> List.of(current.componentAId());
            case "ACCEPTED_B" -> List.of(current.componentBId());
            default -> List.of(current.componentAId(), current.componentBId());
        };
        for (UUID component : restored) {
            jdbc.update("""
                    UPDATE cbom_claim_assurances SET assurance_level = 'DECLARED', evidence_state = 'SUPPORTED'
                     WHERE cbom_component_id = ? AND claim_path LIKE '%/' || ? AND assurance_level = 'CONFLICTING'
                       AND NOT EXISTS (SELECT 1 FROM cbom_contradictions o WHERE o.status = 'OPEN' AND o.claim = ?
                                        AND ? IN (o.component_a_id, o.component_b_id))
                    """, component, current.claim(), current.claim(), component);
        }
        audit.record("cbom.contradiction.reviewed", "cbom_contradiction", id.toString(),
                "{\"decision\":\"" + decision + "\",\"claim\":\"" + current.claim() + "\"}");
        return jdbc.query(SELECT + " WHERE x.id = ?", (rs, row) -> row(rs), id).get(0);
    }

    private static final String SELECT = """
            SELECT x.id, x.asset_id, a.name, x.identity, x.claim, x.component_a_id, ba.document_name, x.value_a,
                   x.component_b_id, bb.document_name, x.value_b, x.status, x.detected_at, x.reviewed_by, x.reviewed_at,
                   x.review_note, x.version
              FROM cbom_contradictions x
              LEFT JOIN assets a ON a.id = x.asset_id
              JOIN cbom_components ca ON ca.id = x.component_a_id LEFT JOIN bom_ingestion_records ba ON ba.id = ca.source_bom_id
              JOIN cbom_components cb ON cb.id = x.component_b_id LEFT JOIN bom_ingestion_records bb ON bb.id = cb.source_bom_id""";

    private static Contradiction row(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new Contradiction(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getString(3), rs.getString(4),
                rs.getString(5), rs.getObject(6, UUID.class), rs.getString(7), rs.getString(8), rs.getObject(9, UUID.class),
                rs.getString(10), rs.getString(11), rs.getString(12), rs.getTimestamp(13).toInstant(), rs.getString(14),
                rs.getTimestamp(15) == null ? null : rs.getTimestamp(15).toInstant(), rs.getString(16), rs.getLong(17));
    }
}
