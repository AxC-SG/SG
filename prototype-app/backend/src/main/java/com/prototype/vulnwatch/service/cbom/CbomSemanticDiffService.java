package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.CbomFindingStatus;
import com.prototype.vulnwatch.domain.CbomRiskFinding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.CbomComponentRepository;
import com.prototype.vulnwatch.repo.CbomRiskFindingRepository;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Semantic CBOM diff (plan section 5.6) between a CBOM and its predecessor or a requested baseline.
 *
 * <p>Components match on cross-version identity: the declared {@code bom-ref}, otherwise asset
 * type + name + primitive + serial number. An identity that occurs more than once in either
 * document is reported as AMBIGUOUS and never guessed. Finding outcomes keep remediation,
 * omission, withdrawal and accepted risk distinct:
 * <ul>
 *   <li>REMEDIATED: the component is still declared and the rule no longer fires.</li>
 *   <li>NOT_OBSERVED: the new document omitted the component.</li>
 *   <li>WITHDRAWN: the current evidence was superseded or deleted.</li>
 *   <li>ACCEPTED_RISK: the condition remains under a canonical suppression.</li>
 *   <li>PERSISTING / INTRODUCED: still open, or new in this document.</li>
 * </ul>
 */
@Service
public class CbomSemanticDiffService {

    public record FieldChange(String field, String category, String before, String after) { }
    public record ComponentChange(String changeType, String identity, String name, String assetType, UUID baselineComponentId,
            UUID currentComponentId, List<FieldChange> fields, BigDecimal riskBefore, BigDecimal riskAfter) { }
    public record AssuranceChange(String identity, String claim, String before, String after, String direction) { }
    public record FindingOutcome(String outcome, String identity, String componentName, String ruleId, String title,
            String severityBefore, String severityAfter, UUID baselineFindingId, UUID currentFindingId, String canonicalStatus) { }
    public record Ambiguity(String identity, int baselineMatches, int currentMatches) { }
    public record PostureMovement(int openBefore, int openAfter, BigDecimal riskBefore, BigDecimal riskAfter) { }
    public record SemanticDiff(UUID bomId, UUID baselineBomId, String baselineSource, String currentStatus,
            Map<String, Integer> componentSummary, Map<String, Integer> findingSummary, List<ComponentChange> componentChanges,
            List<AssuranceChange> assuranceChanges, List<FindingOutcome> findingOutcomes, List<Ambiguity> ambiguous,
            PostureMovement posture) { }

    private static final Set<CbomFindingStatus> LIVE = Set.of(CbomFindingStatus.OPEN, CbomFindingStatus.ACCEPTED);
    private static final Map<String, Integer> ASSURANCE_RANK = Map.of(
            "UNKNOWN", 0, "CONFLICTING", 1, "DECLARED", 2, "CORROBORATED", 3, "VERIFIED", 4);

    private final BomIngestionRecordRepository boms;
    private final CbomComponentRepository components;
    private final CbomRiskFindingRepository findings;
    private final JdbcTemplate jdbc;

    public CbomSemanticDiffService(BomIngestionRecordRepository boms, CbomComponentRepository components,
            CbomRiskFindingRepository findings, JdbcTemplate jdbc) {
        this.boms = boms; this.components = components; this.findings = findings; this.jdbc = jdbc;
    }

    @Transactional(readOnly = true)
    public SemanticDiff diff(Tenant tenant, UUID bomId, UUID requestedBaseline) {
        BomIngestionRecord current = requireCbom(tenant, bomId);
        UUID baselineId = requestedBaseline != null ? requestedBaseline : current.getPreviousBomId();
        String baselineSource = requestedBaseline != null ? "REQUESTED" : baselineId != null ? "PREDECESSOR" : "NONE";
        if (baselineId != null && baselineId.equals(bomId)) throw new IllegalArgumentException("A CBOM cannot be compared with itself");
        if (baselineId != null) requireCbom(tenant, baselineId);

        List<CbomComponent> after = components.findByTenant_IdAndSourceBom_IdOrderByNameAsc(tenant.getId(), bomId);
        List<CbomComponent> before = baselineId == null ? List.of()
                : components.findByTenant_IdAndSourceBom_IdOrderByNameAsc(tenant.getId(), baselineId);
        Map<String, List<CbomComponent>> beforeById = group(before);
        Map<String, List<CbomComponent>> afterById = group(after);

        List<Ambiguity> ambiguous = new ArrayList<>();
        Map<String, CbomComponent> beforeUnique = new LinkedHashMap<>();
        Map<String, CbomComponent> afterUnique = new LinkedHashMap<>();
        Set<String> identities = new java.util.TreeSet<>(beforeById.keySet());
        identities.addAll(afterById.keySet());
        for (String identity : identities) {
            int b = beforeById.getOrDefault(identity, List.of()).size();
            int a = afterById.getOrDefault(identity, List.of()).size();
            if (b > 1 || a > 1) { ambiguous.add(new Ambiguity(identity, b, a)); continue; }
            if (b == 1) beforeUnique.put(identity, beforeById.get(identity).get(0));
            if (a == 1) afterUnique.put(identity, afterById.get(identity).get(0));
        }

        List<ComponentChange> changes = new ArrayList<>();
        if (baselineId != null) {
            for (var entry : beforeUnique.entrySet()) {
                CbomComponent next = afterUnique.get(entry.getKey());
                CbomComponent prior = entry.getValue();
                if (next == null) {
                    changes.add(change("NOT_OBSERVED", entry.getKey(), prior, null, List.of()));
                } else {
                    List<FieldChange> fields = fields(prior, next);
                    if (!fields.isEmpty()) changes.add(change("CHANGED", entry.getKey(), prior, next, fields));
                }
            }
            for (var entry : afterUnique.entrySet()) {
                if (!beforeUnique.containsKey(entry.getKey())) changes.add(change("ADDED", entry.getKey(), null, entry.getValue(), List.of()));
            }
        }
        changes.sort(Comparator.comparing(ComponentChange::changeType).thenComparing(ComponentChange::identity));

        Map<UUID, String> identityOf = new HashMap<>();
        beforeUnique.forEach((identity, c) -> identityOf.put(c.getId(), identity));
        afterUnique.forEach((identity, c) -> identityOf.put(c.getId(), identity));
        Set<String> ambiguousIds = new java.util.HashSet<>();
        ambiguous.forEach(a -> ambiguousIds.add(a.identity()));

        List<CbomRiskFinding> beforeFindings = baselineId == null ? List.of() : findings.findBySourceBomId(baselineId);
        List<CbomRiskFinding> afterFindings = findings.findBySourceBomId(bomId);
        Map<String, String> canonical = canonicalStatuses(bomId);
        Map<String, CbomRiskFinding> afterByKey = new LinkedHashMap<>();
        for (CbomRiskFinding f : afterFindings) {
            String identity = identityOf.get(f.getComponent().getId());
            if (identity != null) afterByKey.putIfAbsent(identity + "#" + f.getRuleId(), f);
        }
        List<FindingOutcome> outcomes = new ArrayList<>();
        Set<String> matched = new java.util.HashSet<>();
        for (CbomRiskFinding prior : beforeFindings) {
            if (!LIVE.contains(prior.getStatus())) continue;
            String identity = identityOf.get(prior.getComponent().getId());
            if (identity == null) {
                outcomes.add(outcome("AMBIGUOUS", identity(prior.getComponent()), prior, null, null));
                continue;
            }
            CbomComponent next = afterUnique.get(identity);
            String key = identity + "#" + prior.getRuleId();
            CbomRiskFinding now = afterByKey.get(key);
            if (next == null) {
                outcomes.add(outcome("NOT_OBSERVED", identity, prior, null, null));
            } else if (now == null) {
                outcomes.add(outcome("REMEDIATED", identity, prior, null, null));
            } else {
                matched.add(key);
                outcomes.add(outcome(classifyLive(now, canonical), identity, prior, now, canonical.get(now.getId().toString())));
            }
        }
        for (var entry : afterByKey.entrySet()) {
            CbomRiskFinding now = entry.getValue();
            if (matched.contains(entry.getKey()) || !LIVE.contains(now.getStatus())) continue;
            String identity = entry.getKey().substring(0, entry.getKey().lastIndexOf('#'));
            String outcome = baselineId == null ? classifyLive(now, canonical)
                    : "WITHDRAWN".equals(classifyLive(now, canonical)) ? "WITHDRAWN" : "INTRODUCED";
            outcomes.add(outcome(outcome, identity, null, now, canonical.get(now.getId().toString())));
        }
        for (CbomRiskFinding now : afterFindings) {
            if (identityOf.containsKey(now.getComponent().getId()) || !LIVE.contains(now.getStatus())) continue;
            outcomes.add(outcome("AMBIGUOUS", identity(now.getComponent()), null, now, canonical.get(now.getId().toString())));
        }
        outcomes.sort(Comparator.comparing(FindingOutcome::outcome).thenComparing(o -> Objects.toString(o.identity(), ""))
                .thenComparing(o -> Objects.toString(o.ruleId(), "")));

        List<AssuranceChange> assurance = baselineId == null ? List.of()
                : assuranceChanges(baselineId, bomId, identityOf, ambiguousIds);
        return new SemanticDiff(bomId, baselineId, baselineSource, current.getStatus().name(),
                counts(changes, ComponentChange::changeType), counts(outcomes, FindingOutcome::outcome),
                changes, assurance, outcomes, ambiguous,
                new PostureMovement(open(beforeFindings), open(afterFindings), risk(before), risk(after)));
    }

    private String classifyLive(CbomRiskFinding finding, Map<String, String> canonical) {
        if (finding.getEvidenceState() == com.prototype.vulnwatch.domain.BomEvidenceState.WITHDRAWN) return "WITHDRAWN";
        String status = canonical.get(finding.getId().toString());
        if ("SUPPRESSED".equals(status) || finding.getStatus() == CbomFindingStatus.ACCEPTED) return "ACCEPTED_RISK";
        return "PERSISTING";
    }

    /** Canonical CRYPTO finding status for the current document's CBOM findings, keyed by CBOM finding id. */
    private Map<String, String> canonicalStatuses(UUID bomId) {
        Map<String, String> statuses = new HashMap<>();
        jdbc.query("""
                SELECT substring(f.fingerprint from 6), f.status FROM findings f
                 WHERE f.finding_kind = 'CRYPTO' AND f.fingerprint IN (
                    SELECT 'cbom:' || r.id::text FROM cbom_risk_findings r
                      JOIN cbom_components c ON c.id = r.cbom_component_id WHERE c.source_bom_id = ?)
                """, rs -> { statuses.put(rs.getString(1), rs.getString(2)); }, bomId);
        return statuses;
    }

    private List<AssuranceChange> assuranceChanges(UUID baselineId, UUID bomId, Map<UUID, String> identityOf, Set<String> ambiguous) {
        Map<String, String> before = claims(baselineId, identityOf);
        Map<String, String> after = claims(bomId, identityOf);
        List<AssuranceChange> result = new ArrayList<>();
        for (var entry : after.entrySet()) {
            String prior = before.get(entry.getKey());
            if (prior == null || prior.equals(entry.getValue())) continue;
            String identity = entry.getKey().substring(0, entry.getKey().indexOf('|'));
            if (ambiguous.contains(identity)) continue;
            int delta = ASSURANCE_RANK.getOrDefault(entry.getValue(), 0) - ASSURANCE_RANK.getOrDefault(prior, 0);
            result.add(new AssuranceChange(identity, entry.getKey().substring(entry.getKey().indexOf('|') + 1), prior,
                    entry.getValue(), delta > 0 ? "INCREASED" : delta < 0 ? "DECREASED" : "CHANGED"));
        }
        result.sort(Comparator.comparing(AssuranceChange::identity).thenComparing(AssuranceChange::claim));
        return result;
    }

    /** identity|claim -> assurance level from the latest successful run. Claim paths are index-based, so key by the leaf. */
    private Map<String, String> claims(UUID bomId, Map<UUID, String> identityOf) {
        Map<String, String> values = new HashMap<>();
        jdbc.query("""
                SELECT a.cbom_component_id, a.claim_path, a.assurance_level FROM cbom_claim_assurances a
                 WHERE a.assessment_run_id = (SELECT r.id FROM cbom_assessment_runs r WHERE r.bom_id = ? AND r.status = 'SUCCEEDED'
                                               ORDER BY r.completed_at DESC NULLS LAST LIMIT 1)
                """, rs -> {
                    String identity = identityOf.get(rs.getObject(1, UUID.class));
                    if (identity == null) return;
                    String path = rs.getString(2);
                    values.put(identity + "|" + path.substring(path.lastIndexOf('/') + 1), rs.getString(3));
                }, bomId);
        return values;
    }

    private BomIngestionRecord requireCbom(Tenant tenant, UUID id) {
        return boms.findById(id).filter(v -> v.getTenant().getId().equals(tenant.getId()) && v.getBomType() == BomType.CBOM)
                .orElseThrow(() -> new IllegalArgumentException("CBOM artifact not found"));
    }

    private static Map<String, List<CbomComponent>> group(List<CbomComponent> values) {
        Map<String, List<CbomComponent>> grouped = new LinkedHashMap<>();
        for (CbomComponent value : values) grouped.computeIfAbsent(identity(value), key -> new ArrayList<>()).add(value);
        return grouped;
    }

    static String identity(CbomComponent c) {
        if (c.getBomRef() != null && !c.getBomRef().isBlank()) return "bom-ref:" + c.getBomRef().trim();
        return "natural:" + (c.getAssetType() == null ? "UNKNOWN" : c.getAssetType().name()) + "|" + lower(c.getName())
                + "|" + lower(c.getPrimitive()) + "|" + lower(c.getSerialNumber());
    }

    private static List<FieldChange> fields(CbomComponent a, CbomComponent b) {
        List<FieldChange> out = new ArrayList<>();
        field(out, "primitive", "ALGORITHM", a.getPrimitive(), b.getPrimitive());
        field(out, "parameterSetIdentifier", "ALGORITHM", a.getParameterSetIdentifier(), b.getParameterSetIdentifier());
        field(out, "keySize", "ALGORITHM", a.getKeySize(), b.getKeySize());
        field(out, "curve", "ALGORITHM", a.getCurve(), b.getCurve());
        field(out, "padding", "ALGORITHM", a.getPadding(), b.getPadding());
        field(out, "protocolVersion", "PROTOCOL", a.getProtocolVersion(), b.getProtocolVersion());
        field(out, "notAfter", "CERTIFICATE", a.getNotAfter(), b.getNotAfter());
        field(out, "signatureAlgorithm", "CERTIFICATE", a.getSignatureAlgorithm(), b.getSignatureAlgorithm());
        field(out, "issuer", "CERTIFICATE", a.getIssuer(), b.getIssuer());
        field(out, "storageLocation", "CUSTODY_USAGE", a.getStorageLocation(), b.getStorageLocation());
        field(out, "usedIn", "CUSTODY_USAGE", a.getUsedIn(), b.getUsedIn());
        field(out, "transmission", "CUSTODY_USAGE", a.getTransmission(), b.getTransmission());
        field(out, "state", "STATE", a.getState(), b.getState());
        field(out, "sensitivity", "STATE", a.getSensitivity(), b.getSensitivity());
        return out;
    }

    private static void field(List<FieldChange> out, String name, String category, Object a, Object b) {
        if (!Objects.equals(a, b)) out.add(new FieldChange(name, category, a == null ? null : a.toString(), b == null ? null : b.toString()));
    }

    private static ComponentChange change(String type, String identity, CbomComponent before, CbomComponent after, List<FieldChange> fields) {
        CbomComponent shown = after == null ? before : after;
        return new ComponentChange(type, identity, shown.getName(), shown.getAssetType() == null ? null : shown.getAssetType().name(),
                before == null ? null : before.getId(), after == null ? null : after.getId(), fields,
                before == null ? null : before.getRiskScore(), after == null ? null : after.getRiskScore());
    }

    private static FindingOutcome outcome(String outcome, String identity, CbomRiskFinding before, CbomRiskFinding after, String canonical) {
        CbomRiskFinding shown = after == null ? before : after;
        return new FindingOutcome(outcome, identity, shown.getComponent().getName(), shown.getRuleId(), shown.getTitle(),
                before == null ? null : before.getSeverity().name(), after == null ? null : after.getSeverity().name(),
                before == null ? null : before.getId(), after == null ? null : after.getId(), canonical);
    }

    private static <T> Map<String, Integer> counts(List<T> values, Function<T, String> key) {
        Map<String, Integer> result = new java.util.TreeMap<>();
        for (T value : values) result.merge(key.apply(value), 1, Integer::sum);
        return result;
    }

    private static int open(List<CbomRiskFinding> values) {
        return (int) values.stream().filter(f -> f.getStatus() == CbomFindingStatus.OPEN
                && f.getEvidenceState() != com.prototype.vulnwatch.domain.BomEvidenceState.WITHDRAWN).count();
    }

    private static BigDecimal risk(List<CbomComponent> values) {
        return values.stream().map(CbomComponent::getRiskScore).filter(Objects::nonNull).reduce(BigDecimal.ZERO, BigDecimal::add);
    }

    private static String lower(String value) { return value == null ? "" : value.trim().toLowerCase(Locale.ROOT); }
}
