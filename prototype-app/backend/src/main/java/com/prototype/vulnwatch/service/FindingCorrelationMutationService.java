package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCreationSource;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class FindingCorrelationMutationService {

    private final CorrelationCandidateService correlationCandidateService;
    private final ImpactEvaluationService impactEvaluationService;
    private final VexAssertionMatchService vexAssertionMatchService;
    private final FindingSlaService findingSlaService;
    private final OwnershipRuleService ownershipRuleService;
    private final ObjectMapper objectMapper;

    public FindingCorrelationMutationService(
            CorrelationCandidateService correlationCandidateService,
            ImpactEvaluationService impactEvaluationService,
            VexAssertionMatchService vexAssertionMatchService,
            FindingSlaService findingSlaService,
            OwnershipRuleService ownershipRuleService,
            ObjectMapper objectMapper
    ) {
        this.correlationCandidateService = correlationCandidateService;
        this.impactEvaluationService = impactEvaluationService;
        this.vexAssertionMatchService = vexAssertionMatchService;
        this.findingSlaService = findingSlaService;
        this.ownershipRuleService = ownershipRuleService;
        this.objectMapper = objectMapper;
    }

    public void setEvidenceWithVex(Finding finding, String evidence) {
        finding.setEvidence(evidence);
        VexFilterEvidence vex = parseVexFilterEvidence(finding);
        finding.setVexStatus(vex.status());
        finding.setVexFreshness(vex.freshness());
        finding.setVexProvider(vex.provider());
        finding.setMatchedVexAssertionId(parseVexAssertionId(finding.getEvidence()));
    }

    public ImpactEvaluationService.VexOverlayOutcome resolveVexOverlay(
            InventoryComponent component,
            UUID vulnerabilityId,
            String sourceKey,
            List<CorrelationCandidateService.CandidateMatch> candidateMatches,
            RiskPolicy policy
    ) {
        if (component == null || component.getId() == null || vulnerabilityId == null) {
            return ImpactEvaluationService.VexOverlayOutcome.none();
        }

        List<CorrelationCandidateService.CandidateMatch> resolvedCandidates = candidateMatches == null
                ? correlationCandidateService.candidatesForComponent(
                        component,
                        correlationCandidateService.buildCandidateBundle(List.of(component)))
                : candidateMatches;
        return vexAssertionMatchService.resolve(component, vulnerabilityId, sourceKey, resolvedCandidates, policy);
    }

    public String withVexOverlayEvidence(String evidence, ImpactEvaluationService.VexOverlayOutcome overlay) {
        if (overlay == null || !overlay.applied()) {
            return evidence;
        }
        Map<String, Object> payload = readEvidencePayload(evidence);
        Map<String, Object> overlayPayload = new LinkedHashMap<>();
        overlayPayload.put("state", overlay.finalState().name());
        overlayPayload.put("status", overlay.status());
        overlayPayload.put("provider", overlay.provider());
        overlayPayload.put("freshness", overlay.freshness());
        overlayPayload.put("reason", overlay.reason());
        overlayPayload.put("source", overlay.source());
        overlayPayload.put("assertionId", overlay.assertionId());
        overlayPayload.put("targetId", overlay.targetId());
        overlayPayload.put("targetUpdatedAt", overlay.targetUpdatedAt() == null ? null : overlay.targetUpdatedAt().toString());
        payload.put("vexOverlay", overlayPayload);
        return toJson(payload);
    }

    public void upsertComponentVulnerabilityState(
            Tenant tenant,
            InventoryComponent component,
            Vulnerability vulnerability,
            PrecedenceResolverService.CandidateDecision selected,
            PrecedenceResolverService.PrecedenceResolution resolution,
            ImpactEvaluationService.VexOverlayOutcome vexOverlay,
            ImpactEvaluationService.ImpactAssessment impactAssessment,
            Instant now,
            Map<UUID, ComponentVulnerabilityState> existingStateByVulnerability,
            List<ComponentVulnerabilityState> stateRowsToPersist
    ) {
        if (tenant == null || component == null || vulnerability == null || vulnerability.getId() == null) {
            return;
        }

        ComponentVulnerabilityState state = existingStateByVulnerability.get(vulnerability.getId());
        boolean created = false;
        if (state == null) {
            state = new ComponentVulnerabilityState();
            state.setTenant(tenant);
            state.setComponent(component);
            state.setVulnerability(vulnerability);
            created = true;
        }

        String newVexStatus = vexOverlay == null ? "UNKNOWN" : defaultString(vexOverlay.status(), "UNKNOWN");
        String newVexProvider = vexOverlay == null ? "unknown" : defaultString(vexOverlay.provider(), "unknown");
        String newVexFreshness = vexOverlay == null ? "UNKNOWN" : defaultString(vexOverlay.freshness(), "UNKNOWN");
        String newVexSource = vexOverlay == null ? null : vexOverlay.source();
        UUID newMatchedVexAssertionId = vexOverlay == null ? null : vexOverlay.assertionId();
        String newSelectedTargetSource = selected == null || selected.target() == null
                ? null
                : selected.target().getSource();

        boolean stateChanged = created
                || state.getApplicabilityState() != impactAssessment.applicabilityState()
                || state.getImpactState() != impactAssessment.impactState()
                || !Objects.equals(state.getApplicabilityReason(), impactAssessment.applicabilityReason())
                || !Objects.equals(state.getVexStatus(), newVexStatus)
                || !Objects.equals(state.getVexProvider(), newVexProvider)
                || !Objects.equals(state.getVexFreshness(), newVexFreshness)
                || !Objects.equals(state.getVexSource(), newVexSource)
                || !Objects.equals(state.getMatchedVexAssertionId(), newMatchedVexAssertionId)
                || !Objects.equals(state.getImpactReason(), impactAssessment.impactReason())
                || !Objects.equals(state.getPrecedenceReason(), resolution == null ? "unknown" : resolution.reason())
                || !Objects.equals(state.getMatchedBy(), selected == null ? null : selected.matchedBy())
                || !Objects.equals(state.getSelectedTargetSource(), newSelectedTargetSource)
                || !Objects.equals(state.getConfidenceScore(), selected == null ? null : selected.confidence())
                || !Objects.equals(state.getApplicabilityReasonDetail(), impactAssessment.applicabilityReasonDetail())
                || !Objects.equals(state.getImpactReasonDetail(), impactAssessment.impactReasonDetail());
        if (!stateChanged) {
            return;
        }

        state.setApplicabilityState(impactAssessment.applicabilityState());
        state.setApplicabilityReason(impactAssessment.applicabilityReason());
        state.setApplicabilityReasonDetail(impactAssessment.applicabilityReasonDetail());
        state.setImpactState(impactAssessment.impactState());
        state.setImpactReason(impactAssessment.impactReason());
        state.setImpactReasonDetail(impactAssessment.impactReasonDetail());
        state.setVexStatus(newVexStatus);
        state.setVexProvider(newVexProvider);
        state.setVexFreshness(newVexFreshness);
        state.setVexSource(newVexSource);
        state.setMatchedVexAssertionId(newMatchedVexAssertionId);
        state.setVexTargetId(vexOverlay == null ? null : vexOverlay.targetId());
        state.setPrecedenceReason(resolution == null ? "unknown" : resolution.reason());
        state.setMatchedBy(selected == null ? null : selected.matchedBy());
        state.setSelectedTargetSource(newSelectedTargetSource);
        state.setConfidenceScore(selected == null ? null : selected.confidence());
        state.setEligibleForFinding(impactAssessment.findingEligible());
        state.setLastEvaluatedAt(now);
        state.setStateChangedAt(now);
        state.setTraceJson(toJson(buildStateTrace(selected, resolution, vexOverlay, impactAssessment)));
        state.touch();
        existingStateByVulnerability.put(vulnerability.getId(), state);
        stateRowsToPersist.add(state);
    }

    public Finding createFinding(
            Tenant tenant,
            Asset asset,
            InventoryComponent component,
            Vulnerability vulnerability,
            PrecedenceResolverService.CandidateDecision selected,
            PrecedenceResolverService.PrecedenceResolution resolution,
            double riskScore,
            String evidence,
            Instant now,
            RiskPolicy policy
    ) {
        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setAsset(asset);
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        finding.setCreationSource(FindingCreationSource.AUTOMATIC);
        finding.setMatchedBy(selected.matchedBy());
        finding.setRiskScore(riskScore);
        finding.setConfidenceScore(selected.confidence());
        finding.setFirstObservedAt(now);
        finding.setLastObservedAt(now);
        finding.setDueAt(findingSlaService.deriveDueAt(now, riskScore, asset, policy));
        setEvidenceWithVex(finding, evidence);
        finding.setPrecedenceTrace(toJson(resolution.precedenceTrace()));
        ownershipRuleService.applyOwnerGroupToFinding(finding);
        finding.touch();
        return finding;
    }

    private VexFilterEvidence parseVexFilterEvidence(Finding finding) {
        if (finding == null || !hasText(finding.getEvidence())) {
            return new VexFilterEvidence("UNKNOWN", "UNKNOWN", "unknown");
        }
        try {
            JsonNode root = objectMapper.readTree(finding.getEvidence());
            JsonNode overlay = root.path("vexOverlay");
            String overlayStatus = impactEvaluationService.normalizeStatus(overlay.path("status").asText(""));
            String overlayFreshness = impactEvaluationService.normalizeFreshness(overlay.path("freshness").asText(""));
            String overlayProvider = impactEvaluationService.normalizeProvider(overlay.path("provider").asText(""));
            if (!"UNKNOWN".equals(overlayStatus) || !"UNKNOWN".equals(overlayFreshness) || !"unknown".equals(overlayProvider)) {
                return new VexFilterEvidence(overlayStatus, overlayFreshness, overlayProvider);
            }
            JsonNode trace = root.path("applicabilityTrace");
            String status = impactEvaluationService.normalizeStatus(traceValue(trace, "vexStatus"));
            String freshness = impactEvaluationService.normalizeFreshness(traceValue(trace, "vexFreshnessOutcome"));
            String provider = impactEvaluationService.normalizeProvider(traceValue(trace, "vexProvider"));
            return new VexFilterEvidence(status, freshness, provider);
        } catch (Exception ignored) {
            return new VexFilterEvidence("UNKNOWN", "UNKNOWN", "unknown");
        }
    }

    private UUID parseVexAssertionId(String evidence) {
        if (!hasText(evidence)) {
            return null;
        }
        try {
            JsonNode root = objectMapper.readTree(evidence);
            String value = root.path("vexOverlay").path("assertionId").asText("");
            return hasText(value) ? UUID.fromString(value.trim()) : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private String traceValue(JsonNode trace, String key) {
        if (trace == null || trace.isMissingNode() || trace.isNull() || key == null) {
            return null;
        }
        String direct = trace.path(key).asText("");
        if (hasText(direct)) {
            return direct.trim();
        }
        JsonNode base = trace.path("baseApplicability");
        String nested = base.path(key).asText("");
        if (hasText(nested)) {
            return nested.trim();
        }
        return null;
    }

    private Map<String, Object> readEvidencePayload(String evidence) {
        if (!hasText(evidence)) {
            return new LinkedHashMap<>();
        }
        try {
            JsonNode node = objectMapper.readTree(evidence);
            return objectMapper.convertValue(node, new com.fasterxml.jackson.core.type.TypeReference<>() {
            });
        } catch (Exception ignored) {
            return new LinkedHashMap<>();
        }
    }

    private Map<String, Object> buildStateTrace(
            PrecedenceResolverService.CandidateDecision selected,
            PrecedenceResolverService.PrecedenceResolution resolution,
            ImpactEvaluationService.VexOverlayOutcome vexOverlay,
            ImpactEvaluationService.ImpactAssessment impactAssessment
    ) {
        Map<String, Object> trace = new LinkedHashMap<>();
        trace.put("matchedBy", selected == null ? null : selected.matchedBy());
        trace.put("selectedTargetSource", selected == null || selected.target() == null ? null : selected.target().getSource());
        trace.put("confidence", selected == null ? null : selected.confidence());
        trace.put("precedenceReason", resolution == null ? null : resolution.reason());
        trace.put("applicabilityState", impactAssessment.applicabilityState().name());
        trace.put("applicabilityReason", impactAssessment.applicabilityReason());
        trace.put("applicabilityReasonDetail", impactAssessment.applicabilityReasonDetail());
        trace.put("impactState", impactAssessment.impactState().name());
        trace.put("impactReason", impactAssessment.impactReason());
        trace.put("impactReasonDetail", impactAssessment.impactReasonDetail());
        if (vexOverlay != null) {
            trace.put("vexStatus", vexOverlay.status());
            trace.put("vexProvider", vexOverlay.provider());
            trace.put("vexFreshness", vexOverlay.freshness());
            trace.put("vexSource", vexOverlay.source());
            trace.put("vexAssertionId", vexOverlay.assertionId());
            trace.put("vexTargetId", vexOverlay.targetId());
            trace.put("vexReason", vexOverlay.reason());
        }
        return trace;
    }

    private String defaultString(String value, String fallback) {
        return hasText(value) ? value : fallback;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private record VexFilterEvidence(
            String status,
            String freshness,
            String provider
    ) {
    }
}
