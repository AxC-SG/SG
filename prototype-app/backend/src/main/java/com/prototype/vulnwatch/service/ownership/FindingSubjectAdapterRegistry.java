package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.Domain;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.State;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The finding-adapter registry (Phase 0B §3.5, §3.6): maps each finding kind to its adapter and is the only writer of
 * {@code findings.ownership_subject_id}.
 *
 * <ul>
 *   <li>{@code VULNERABILITY} v1 ({@code CORE}): the affected asset's subject.</li>
 *   <li>{@code VULNERABILITY} v2 ({@code CORE} + {@code CLOUD_BOM}): the active occurrence subject of
 *       {@code findings.component_id} when that component sits on the finding's asset; otherwise v1.</li>
 *   <li>{@code CRYPTO} v1 ({@code CLOUD_BOM}): the active occurrence subject of the CBOM component named in the
 *       finding's evidence; {@code UNOWNED}/{@code SUBJECT_PENDING} without one, never a package or identity.</li>
 *   <li>AI kinds have no adapter in Release 2 and keep legacy ownership.</li>
 * </ul>
 *
 * Nothing here writes an occurrence subject while {@code CLOUD_BOM} is not CANONICAL; in DARK v2 only feeds the
 * comparison report. Selection is deterministic, so every write is idempotent and no adapter version is stored.
 */
@Service
public class FindingSubjectAdapterRegistry {

    public enum Outcome { CANONICAL_SUBJECT, UNOWNED }

    public record Selection(String findingKind, String adapter, Outcome outcome, UUID subjectId, String reason) { }

    /** The §3.6 dark comparison: v2 must change no effective owner before the CLOUD_BOM switch. */
    public record DarkReport(String cloudBomState, long vulnerabilityFindings, long wouldMoveToOccurrence, Map<String, Long> stayOnAsset,
                             long effectiveOwnerChanges, long cryptoFindings, long cryptoWithSubject, long cryptoSubjectPending) {
        public boolean passed() {
            return effectiveOwnerChanges == 0;
        }
    }

    /** v2's target for a VULNERABILITY finding {@code f}: the component's active occurrence on the same asset, else the asset. */
    private static final String V2_TARGET = """
            COALESCE((SELECT s.id FROM inventory_components ic JOIN ownership_subject s ON s.id = ic.ownership_subject_id
                       WHERE ic.id = f.component_id AND ic.asset_id = f.asset_id AND s.lifecycle_status = 'ACTIVE'),
                     (SELECT a.ownership_subject_id FROM assets a WHERE a.id = f.asset_id))""";

    /** CRYPTO v1's target for finding {@code f}: the CBOM component's active occurrence, or null. */
    private static final String CRYPTO_TARGET = """
            (SELECT s.id FROM cbom_components cc JOIN ownership_subject s ON s.id = cc.ownership_subject_id
              WHERE cc.id = NULLIF(f.evidence ->> 'cbomComponentId', '')::uuid AND s.lifecycle_status = 'ACTIVE')""";

    private final JdbcTemplate jdbc;
    private final InventorySubjectAdapter assets;
    private final OwnershipAuthorityService authority;
    private final OwnershipEvents events;

    public FindingSubjectAdapterRegistry(JdbcTemplate jdbc, InventorySubjectAdapter assets, OwnershipAuthorityService authority,
                                         OwnershipEvents events) {
        this.jdbc = jdbc;
        this.assets = assets;
        this.authority = authority;
        this.events = events;
    }

    /** The adapter's selection for one finding, without writing. */
    @Transactional(readOnly = true)
    public Selection select(UUID findingId) {
        List<Map<String, Object>> rows = jdbc.queryForList("SELECT finding_kind, asset_id FROM findings WHERE id = ?", findingId);
        if (rows.isEmpty()) return new Selection(null, null, Outcome.UNOWNED, null, "FINDING_NOT_FOUND");
        String kind = (String) rows.get(0).get("finding_kind");
        boolean cloudBom = authority.stateFor(Domain.CLOUD_BOM) == State.CANONICAL;
        return switch (kind) {
            case "VULNERABILITY" -> {
                UUID asset = (UUID) rows.get(0).get("asset_id");
                if (asset == null) yield new Selection(kind, "vulnerability-v1", Outcome.UNOWNED, null, "NO_ASSET");
                if (cloudBom) {
                    UUID target = jdbc.queryForObject("SELECT " + V2_TARGET + " FROM findings f WHERE f.id = ?", UUID.class, findingId);
                    if (target != null) yield new Selection(kind, "vulnerability-v2", Outcome.CANONICAL_SUBJECT, target, null);
                }
                Optional<UUID> subject = assets.subjectForAsset(asset);
                yield subject.map(s -> new Selection(kind, "vulnerability-v1", Outcome.CANONICAL_SUBJECT, s, null))
                        .orElseGet(() -> new Selection(kind, "vulnerability-v1", Outcome.UNOWNED, null, "NO_ASSET_SUBJECT"));
            }
            case "CRYPTO" -> {
                if (!cloudBom) yield new Selection(kind, "crypto-v1", Outcome.UNOWNED, null, "LEGACY_PENDING_MIGRATION");
                UUID target = jdbc.queryForObject("SELECT " + CRYPTO_TARGET + " FROM findings f WHERE f.id = ?", UUID.class, findingId);
                yield target == null ? new Selection(kind, "crypto-v1", Outcome.UNOWNED, null, "SUBJECT_PENDING")
                        : new Selection(kind, "crypto-v1", Outcome.CANONICAL_SUBJECT, target, null);
            }
            default -> new Selection(kind, null, Outcome.UNOWNED, null, "NO_ADAPTER");
        };
    }

    /**
     * The finding's canonical subject, linked on first use. VULNERABILITY findings link in DARK and CANONICAL (v1 until
     * CLOUD_BOM is CANONICAL); CRYPTO findings link only once CLOUD_BOM is CANONICAL.
     */
    @Transactional
    public Optional<UUID> subjectForFinding(UUID findingId) {
        List<UUID> linked = jdbc.queryForList("SELECT ownership_subject_id FROM findings WHERE id = ?", UUID.class, findingId);
        if (!linked.isEmpty() && linked.get(0) != null) return Optional.of(linked.get(0));
        Selection selection = select(findingId);
        if (selection.outcome() != Outcome.CANONICAL_SUBJECT) return Optional.empty();
        jdbc.update("UPDATE findings SET ownership_subject_id = ? WHERE id = ? AND ownership_subject_id IS NULL", selection.subjectId(), findingId);
        return Optional.of(selection.subjectId());
    }

    /** Populate step (plan §15.2): links up to {@code limit} unlinked VULNERABILITY findings to their asset's subject (v1). */
    @Transactional
    public int linkBatch(int limit) {
        return jdbc.update("""
                UPDATE findings f SET ownership_subject_id = a.ownership_subject_id FROM assets a
                 WHERE f.id IN (SELECT f2.id FROM findings f2 JOIN assets a2 ON a2.id = f2.asset_id
                                 WHERE f2.ownership_subject_id IS NULL AND a2.ownership_subject_id IS NOT NULL
                                   AND f2.finding_kind = 'VULNERABILITY' ORDER BY f2.id LIMIT ?)
                   AND a.id = f.asset_id
                """, limit);
    }

    /**
     * §3.6 step 3 and step 5, once CLOUD_BOM is CANONICAL: moves up to {@code limit} VULNERABILITY findings to their
     * v2 target and gives CRYPTO findings their occurrence subject, keyed by finding ID and guarded by the current value,
     * so a rerun changes nothing. One event per batch. Also keeps findings current afterwards, e.g. when a component is
     * registered later or an occurrence retires (back to the asset, or to no subject for CRYPTO).
     */
    @Transactional
    public int switchBatch(int limit) {
        if (authority.stateFor(Domain.CLOUD_BOM) != State.CANONICAL) return 0;
        int vulnerabilities = moveTo(V2_TARGET, "f.finding_kind = 'VULNERABILITY' AND f.asset_id IS NOT NULL", false, limit);
        int crypto = moveTo(CRYPTO_TARGET, "f.finding_kind = 'CRYPTO'", true, limit);
        if (vulnerabilities + crypto > 0) {
            events.record("FINDING_SUBJECTS_SWITCHED", null, null, null, "finding-adapter-registry",
                    "vulnerabilityFindings", vulnerabilities, "cryptoFindings", crypto);
        }
        return vulnerabilities + crypto;
    }

    /**
     * Sets up to {@code limit} findings matching {@code where} to {@code target}, only where the value differs. A null
     * target is written only when {@code nullable} (CRYPTO without an occurrence is unowned, never another subject).
     */
    private int moveTo(String target, String where, boolean nullable, int limit) {
        return jdbc.update("UPDATE findings u SET ownership_subject_id = t.target FROM ("
                + " SELECT x.id, x.target FROM (SELECT f.id, f.ownership_subject_id AS current, " + target + " AS target"
                + "   FROM findings f WHERE " + where + ") x"
                + "  WHERE x.current IS DISTINCT FROM x.target" + (nullable ? "" : " AND x.target IS NOT NULL")
                + "  ORDER BY x.id LIMIT ?) t WHERE u.id = t.id", limit);
    }

    /** §3.6 step 1: what v2 and the CRYPTO adapter would do, without writing. */
    @Transactional(readOnly = true)
    public DarkReport darkReport() {
        Map<String, Object> v = jdbc.queryForMap("""
                SELECT count(*) AS total,
                       count(*) FILTER (WHERE f.component_id IS NULL) AS no_component,
                       count(*) FILTER (WHERE f.component_id IS NOT NULL AND ic.id IS NULL) AS component_missing,
                       count(*) FILTER (WHERE ic.id IS NOT NULL AND ic.asset_id IS DISTINCT FROM f.asset_id) AS asset_mismatch,
                       count(*) FILTER (WHERE ic.id IS NOT NULL AND ic.asset_id = f.asset_id AND ic.ownership_subject_id IS NULL) AS not_registered,
                       count(*) FILTER (WHERE ic.asset_id = f.asset_id AND s.lifecycle_status = 'RETIRED') AS subject_retired,
                       count(*) FILTER (WHERE ic.asset_id = f.asset_id AND s.lifecycle_status = 'ACTIVE'
                                          AND s.id IS DISTINCT FROM f.ownership_subject_id) AS would_move,
                       count(*) FILTER (WHERE ic.asset_id = f.asset_id AND s.lifecycle_status = 'ACTIVE'
                                          AND s.id IS DISTINCT FROM a.ownership_subject_id
                                          AND (eo.ownership_status, eo.owner_team_id) IS DISTINCT FROM (ea.ownership_status, ea.owner_team_id)) AS owner_changes
                  FROM findings f
                  LEFT JOIN assets a ON a.id = f.asset_id
                  LEFT JOIN inventory_components ic ON ic.id = f.component_id
                  LEFT JOIN ownership_subject s ON s.id = ic.ownership_subject_id
                  LEFT JOIN ownership_effective_assignment ea ON ea.subject_id = a.ownership_subject_id
                  LEFT JOIN ownership_effective_assignment eo ON eo.subject_id = s.id
                 WHERE f.finding_kind = 'VULNERABILITY' AND f.asset_id IS NOT NULL
                """);
        Map<String, Object> c = jdbc.queryForMap("SELECT count(*) AS total, count(" + CRYPTO_TARGET + ") AS with_subject FROM findings f WHERE f.finding_kind = 'CRYPTO'");
        Map<String, Long> stay = new LinkedHashMap<>();
        stay.put("NO_COMPONENT", number(v, "no_component"));
        stay.put("COMPONENT_MISSING", number(v, "component_missing"));
        stay.put("ASSET_MISMATCH", number(v, "asset_mismatch"));
        stay.put("NOT_REGISTERED", number(v, "not_registered"));
        stay.put("SUBJECT_RETIRED", number(v, "subject_retired"));
        long cryptoTotal = number(c, "total");
        long cryptoWith = number(c, "with_subject");
        return new DarkReport(authority.stateFor(Domain.CLOUD_BOM).name(), number(v, "total"), number(v, "would_move"), stay,
                number(v, "owner_changes"), cryptoTotal, cryptoWith, cryptoTotal - cryptoWith);
    }

    private static long number(Map<String, Object> row, String key) {
        Object value = row.get(key);
        return value == null ? 0L : ((Number) value).longValue();
    }
}
