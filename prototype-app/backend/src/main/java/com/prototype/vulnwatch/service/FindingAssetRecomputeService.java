package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingAssetRecomputeService {

    private static final Logger LOG = LoggerFactory.getLogger(FindingAssetRecomputeService.class);

    private final FindingRepository findingRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final CorrelationCandidateService correlationCandidateService;
    private final RiskPolicyService riskPolicyService;
    private final FindingsScoreService findingsScoreService;
    private final FindingWorkflowService findingWorkflowService;
    private final ImpactEvaluationService impactEvaluationService;
    private final FindingEvidenceService findingEvidenceService;
    private final PrecedenceResolverService precedenceResolverService;
    private final OrgCveRecordService orgCveRecordService;
    private final FindingSlaService findingSlaService;
    private final FindingCorrelationAnalysisService findingCorrelationAnalysisService;
    private final FindingCorrelationMutationService findingCorrelationMutationService;
    private final FindingUpsertService findingUpsertService;
    private CanonicalSuppressionMutationService suppressionMutations;

    public FindingAssetRecomputeService(
            FindingRepository findingRepository,
            InventoryComponentRepository inventoryComponentRepository,
            CorrelationCandidateService correlationCandidateService,
            RiskPolicyService riskPolicyService,
            FindingsScoreService findingsScoreService,
            FindingWorkflowService findingWorkflowService,
            ImpactEvaluationService impactEvaluationService,
            FindingEvidenceService findingEvidenceService,
            PrecedenceResolverService precedenceResolverService,
            OrgCveRecordService orgCveRecordService,
            FindingSlaService findingSlaService,
            FindingCorrelationAnalysisService findingCorrelationAnalysisService,
            FindingCorrelationMutationService findingCorrelationMutationService,
            FindingUpsertService findingUpsertService
    ) {
        this.findingRepository = findingRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.correlationCandidateService = correlationCandidateService;
        this.riskPolicyService = riskPolicyService;
        this.findingsScoreService = findingsScoreService;
        this.findingWorkflowService = findingWorkflowService;
        this.impactEvaluationService = impactEvaluationService;
        this.findingEvidenceService = findingEvidenceService;
        this.precedenceResolverService = precedenceResolverService;
        this.orgCveRecordService = orgCveRecordService;
        this.findingSlaService = findingSlaService;
        this.findingCorrelationAnalysisService = findingCorrelationAnalysisService;
        this.findingCorrelationMutationService = findingCorrelationMutationService;
        this.findingUpsertService = findingUpsertService;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setSuppressionMutations(CanonicalSuppressionMutationService suppressionMutations) {
        this.suppressionMutations = suppressionMutations;
    }

    @Transactional
    public int recomputeForAsset(Tenant tenant, Asset asset) {
        List<InventoryComponent> components = inventoryComponentRepository.findByAssetAndComponentStatus(
                asset,
                InventoryComponentStatus.ACTIVE
        );
        RiskPolicy policy = riskPolicyService.getOrCreate(tenant);
        List<Finding> existing = findingRepository.findByAsset(asset);

        if (asset.getState() != AssetState.ACTIVE) {
            for (Finding finding : existing) {
                if (finding.getStatus() != FindingStatus.RESOLVED && finding.getStatus() != FindingStatus.AUTO_CLOSED) {
                    FindingStatus previousStatus = finding.getStatus();
                    finding.setStatus(FindingStatus.RESOLVED);
                    finding.setDecisionState(FindingDecisionState.NOT_AFFECTED);
                    suppressionMutations.clearMetadata(finding, "system", "SUPPRESSION_CLEARED_ASSET_INACTIVE",
                            "Suppression metadata cleared because asset is inactive");
                    finding.touch();
                    findingWorkflowService.appendEvent(
                            finding,
                            "AUTO_RESOLVED_ASSET_INACTIVE",
                            "system",
                            "Finding auto-resolved because asset is not active",
                            Map.of(
                                    "assetState", asset.getState().name(),
                                    "fromStatus", previousStatus.name(),
                                    "toStatus", FindingStatus.RESOLVED.name()
                            )
                    );
                }
            }
            if (!existing.isEmpty()) {
                findingRepository.saveAll(existing);
            }
            return 0;
        }

        Map<String, Finding> existingByKey = new HashMap<>();
        for (Finding finding : existing) {
            existingByKey.put(exposureKey(finding.getComponent().getId(), finding.getVulnerability().getId()), finding);
        }

        CorrelationCandidateService.CandidateBundle candidateBundle =
                correlationCandidateService.buildCandidateBundle(components);
        Set<String> activeKeys = new HashSet<>();
        Instant now = Instant.now();
        List<Finding> toPersist = new ArrayList<>();
        List<Finding> createdFindings = new ArrayList<>();
        Map<String, Long> precedenceReasonCounts = new LinkedHashMap<>();
        long staleSuppressionSignals = 0;
        long underInvestigationSignals = 0;

        for (InventoryComponent component : components) {
            List<CorrelationCandidateService.CandidateMatch> candidates =
                    correlationCandidateService.candidatesForComponent(component, candidateBundle);
            Map<UUID, List<PrecedenceResolverService.CandidateDecision>> candidateDecisionsByVulnerability =
                    findingCorrelationAnalysisService.buildCandidateDecisionsByVulnerability(component, candidates, policy);

            List<UUID> vulnerabilityIds = new ArrayList<>(candidateDecisionsByVulnerability.keySet());
            vulnerabilityIds.sort(UUID::compareTo);
            for (UUID vulnerabilityId : vulnerabilityIds) {
                List<PrecedenceResolverService.CandidateDecision> decisions =
                        candidateDecisionsByVulnerability.get(vulnerabilityId);
                if (decisions == null || decisions.isEmpty()) {
                    continue;
                }
                PrecedenceResolverService.PrecedenceResolution resolution = precedenceResolverService.resolve(decisions);
                precedenceReasonCounts.merge(resolution.reason(), 1L, Long::sum);
                if (resolution.primary() != null && resolution.primary().applicabilityDecision() != null) {
                    String applicabilityReason = resolution.primary().applicabilityDecision().reason();
                    if (applicabilityReason != null) {
                        String normalized = applicabilityReason.toLowerCase(Locale.ROOT);
                        if (normalized.contains("stale_or_untrusted")) {
                            staleSuppressionSignals++;
                        }
                        if (normalized.contains("under_investigation")) {
                            underInvestigationSignals++;
                        }
                    }
                }
                ImpactEvaluationService.VexOverlayOutcome vexOverlay =
                        findingCorrelationMutationService.resolveVexOverlay(component, vulnerabilityId, null, candidates, policy);
                ImpactEvaluationService.ImpactAssessment impactAssessment =
                        impactEvaluationService.evaluate(resolution, resolution.primary(), vexOverlay);
                if (resolution.finalState() != PrecedenceResolverService.FinalState.AFFECTED
                        || resolution.primary() == null
                        || resolution.primary().applicabilityDecision() == null
                        || !resolution.primary().applicabilityDecision().isAffected()) {
                    continue;
                }
                if (!impactAssessment.findingEligible()) {
                    PrecedenceResolverService.CandidateDecision selected = resolution.primary();
                    VulnerabilityTarget target = selected.target();
                    Vulnerability vulnerability = target.getVulnerability();
                    String key = exposureKey(component.getId(), vulnerability.getId());
                    Finding existingFinding = existingByKey.get(key);

                    if (existingFinding != null
                            && existingFinding.getStatus() != FindingStatus.RESOLVED
                            && existingFinding.getStatus() != FindingStatus.AUTO_CLOSED) {
                        existingFinding.setStatus(FindingStatus.RESOLVED);
                        existingFinding.setDecisionState(impactAssessment.findingDecisionState());
                        findingCorrelationMutationService.setEvidenceWithVex(
                                existingFinding,
                                findingCorrelationMutationService.withVexOverlayEvidence(existingFinding.getEvidence(), vexOverlay)
                        );
                        existingFinding.setLastObservedAt(now);
                        existingFinding.touch();

                        findingWorkflowService.appendEvent(
                                existingFinding,
                                "EXACT_IMPACT_RESOLVED",
                                "system",
                                impactAssessment.impactReasonDetail(),
                                Map.of(
                                        "vexProvider", vexOverlay.provider(),
                                        "vexStatus", vexOverlay.status(),
                                        "vexFreshness", vexOverlay.freshness(),
                                        "impactState", impactAssessment.impactState().name(),
                                        "impactReason", impactAssessment.impactReason(),
                                        "previousStatus", existingFinding.getStatus().name(),
                                        "previousDecisionState",
                                        existingFinding.getDecisionState() != null
                                                ? existingFinding.getDecisionState().name()
                                                : "UNKNOWN",
                                        "vexSource", vexOverlay.source() != null ? vexOverlay.source() : "unknown",
                                        "resolvedAt", now.toString()
                                )
                        );

                        LOG.info(
                                "Resolved finding {} for component {} and vulnerability {} using canonical impact state {}",
                                existingFinding.getId(),
                                component.getId(),
                                vulnerability.getExternalId(),
                                impactAssessment.impactState()
                        );
                    }
                    continue;
                }

                PrecedenceResolverService.CandidateDecision selected = resolution.primary();
                String key = exposureKey(component.getId(), vulnerabilityId);
                Finding finding = existingByKey.get(key);
                PrecedenceResolverService.CandidateDecision findingSelected = selected;
                if (finding == null) {
                    findingSelected = findingCorrelationAnalysisService.selectAutomaticFindingCandidate(resolution, decisions);
                    if (findingSelected == null) {
                        continue;
                    }
                }
                VulnerabilityTarget target = findingSelected.target();
                Vulnerability vulnerability = target.getVulnerability();
                if (finding == null && orgCveRecordService.isActivelySuppressed(tenant, vulnerability, now)) {
                    continue;
                }

                String existingSeverityOverride = finding != null ? finding.getSeverityOverride() : null;
                double riskScore = findingsScoreService.computeFromParts(
                        policy.getFindingsScoreConfig(), vulnerability, asset, component, existingSeverityOverride);
                String evidence = findingEvidenceService.buildEvidence(
                        component,
                        vulnerability,
                        target,
                        findingSelected,
                        resolution,
                        null
                );
                evidence = findingCorrelationMutationService.withVexOverlayEvidence(evidence, vexOverlay);
                final PrecedenceResolverService.CandidateDecision selectedForUpsert = findingSelected;
                final String evidenceForUpsert = evidence;
                final double riskScoreForUpsert = riskScore;

                if (finding == null && !isAutomaticFindingGenerationEnabled(policy)) {
                    continue;
                }
                Finding candidate = findingCorrelationMutationService.createFinding(
                        tenant,
                        asset,
                        component,
                        vulnerability,
                        findingSelected,
                        resolution,
                        riskScoreForUpsert,
                        evidenceForUpsert,
                        now,
                        policy
                );
                String nextPrecedenceTrace = toJson(resolution.precedenceTrace());
                FindingUpsertService.UpsertResult upsertResult = findingUpsertService.upsert(candidate, existingFinding -> {
                    boolean reopened = false;
                    boolean changed = false;

                    if (existingFinding.getStatus() == FindingStatus.AUTO_CLOSED) {
                        suppressionMutations.clearMetadata(existingFinding, "system", "SUPPRESSION_CLEARED_REOPEN",
                                "Suppression metadata cleared during recompute reopen");
                        existingFinding.setStatus(FindingStatus.OPEN);
                        reopened = true;
                        changed = true;
                    } else if (existingFinding.getStatus() != FindingStatus.SUPPRESSED || isSuppressionExpired(existingFinding, now)) {
                        if (existingFinding.getStatus() != FindingStatus.OPEN) {
                            reopened = existingFinding.getStatus() == FindingStatus.RESOLVED;
                            changed = true;
                        }
                        existingFinding.setStatus(FindingStatus.OPEN);
                        if (isSuppressionExpired(existingFinding, now)) {
                            suppressionMutations.clearMetadata(existingFinding, "system", "SUPPRESSION_EXPIRED",
                                    "Suppression expired during recompute");
                            findingWorkflowService.appendEvent(
                                    existingFinding,
                                    "SUPPRESSION_EXPIRED",
                                    "system",
                                    "Suppression expired and finding reopened during recompute",
                                    Map.of("reopenedAt", now)
                            );
                            changed = true;
                            reopened = true;
                        }
                    }

                    if (existingFinding.getDecisionState() != impactAssessment.findingDecisionState()) {
                        changed = true;
                    }
                    if (!java.util.Objects.equals(existingFinding.getMatchedBy(), selectedForUpsert.matchedBy())) {
                        changed = true;
                    }
                    if (Double.compare(existingFinding.getRiskScore(), riskScoreForUpsert) != 0) {
                        changed = true;
                    }
                    Instant nextDueAt = findingSlaService.deriveDueAt(existingFinding.getFirstObservedAt(), riskScoreForUpsert, asset, policy);
                    if (!java.util.Objects.equals(existingFinding.getDueAt(), nextDueAt)) {
                        changed = true;
                    }
                    if (Double.compare(existingFinding.getConfidenceScore(), selectedForUpsert.confidence()) != 0) {
                        changed = true;
                    }
                    if (!java.util.Objects.equals(existingFinding.getEvidence(), evidenceForUpsert)) {
                        changed = true;
                    }
                    if (!java.util.Objects.equals(existingFinding.getPrecedenceTrace(), nextPrecedenceTrace)) {
                        changed = true;
                    }

                    if (!changed) {
                        return FindingUpsertService.UpsertAction.UNCHANGED;
                    }
                    existingFinding.setDecisionState(impactAssessment.findingDecisionState());
                    existingFinding.setMatchedBy(selectedForUpsert.matchedBy());
                    existingFinding.setRiskScore(riskScoreForUpsert);
                    existingFinding.setDueAt(nextDueAt);
                    existingFinding.setConfidenceScore(selectedForUpsert.confidence());
                    findingCorrelationMutationService.setEvidenceWithVex(existingFinding, evidenceForUpsert);
                    existingFinding.setPrecedenceTrace(nextPrecedenceTrace);
                    existingFinding.setLastObservedAt(now);
                    existingFinding.touch();
                    return reopened ? FindingUpsertService.UpsertAction.REOPENED : FindingUpsertService.UpsertAction.UPDATED;
                });
                finding = upsertResult.finding();
                existingByKey.put(key, finding);
                activeKeys.add(key);
                if (upsertResult.action() == FindingUpsertService.UpsertAction.CREATED) {
                    createdFindings.add(finding);
                }
            }
        }

        for (Finding finding : existing) {
            String key = exposureKey(finding.getComponent().getId(), finding.getVulnerability().getId());
            if (!activeKeys.contains(key)
                    && finding.getStatus() != FindingStatus.RESOLVED
                    && finding.getStatus() != FindingStatus.AUTO_CLOSED) {
                FindingStatus previousStatus = finding.getStatus();
                finding.setStatus(FindingStatus.RESOLVED);
                finding.setDecisionState(FindingDecisionState.NOT_AFFECTED);
                suppressionMutations.clearMetadata(finding, "system", "SUPPRESSION_CLEARED_NOT_OBSERVED",
                        "Suppression metadata cleared because finding is no longer observed");
                finding.touch();
                findingWorkflowService.appendEvent(
                        finding,
                        "AUTO_RESOLVED_NOT_OBSERVED",
                        "system",
                        "Finding auto-resolved because it is not observed in latest inventory correlation",
                        Map.of(
                                "fromStatus", previousStatus.name(),
                                "toStatus", FindingStatus.RESOLVED.name()
                        )
                );
                toPersist.add(finding);
            }
        }

        if (!toPersist.isEmpty()) {
            findingRepository.saveAll(toPersist);
        }
        for (Finding finding : createdFindings) {
            findingWorkflowService.appendEvent(
                    finding,
                    "CREATED_BY_CORRELATION",
                    "system",
                    "Finding created from deterministic inventory-to-vulnerability correlation",
                    Map.of(
                            "matchedBy", finding.getMatchedBy(),
                            "riskScore", finding.getRiskScore(),
                            "confidenceScore", finding.getConfidenceScore()
                    )
            );
        }
        LOG.info(
                "Correlation diagnostics tenant={} asset={} activeFindings={} staleSuppressionSignals={} underInvestigationSignals={} precedenceReasons={}",
                tenant.getName(),
                asset.getIdentifier(),
                activeKeys.size(),
                staleSuppressionSignals,
                underInvestigationSignals,
                precedenceReasonCounts
        );
        return activeKeys.size();
    }

    @Transactional
    public int recomputeForAssets(List<Asset> assets) {
        int total = 0;
        for (Asset asset : assets) {
            total += recomputeForAsset(asset.getTenant(), asset);
        }
        return total;
    }

    private String exposureKey(UUID componentId, UUID vulnerabilityId) {
        return componentId + "::" + vulnerabilityId;
    }

    private String toJson(Object value) {
        try {
            return new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private boolean isAutomaticFindingGenerationEnabled(RiskPolicy policy) {
        return policy != null && policy.getFindingGenerationMode() == RiskPolicy.FindingGenerationMode.AUTO;
    }

    private boolean isSuppressionExpired(Finding finding, Instant now) {
        return finding.getStatus() == FindingStatus.SUPPRESSED
                && finding.getSuppressedUntil() != null
                && finding.getSuppressedUntil().isBefore(now);
    }
}
