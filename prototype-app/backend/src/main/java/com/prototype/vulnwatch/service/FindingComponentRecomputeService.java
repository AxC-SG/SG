package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelSummarySourceRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.FlushModeType;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingComponentRecomputeService {

    private final FindingRepository findingRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final CorrelationCandidateService correlationCandidateService;
    private final RiskPolicyService riskPolicyService;
    private final FindingsScoreService findingsScoreService;
    private final FindingWorkflowService findingWorkflowService;
    private final FindingEvidenceService findingEvidenceService;
    private final PrecedenceResolverService precedenceResolverService;
    private final ImpactEvaluationService impactEvaluationService;
    private final OrgCveRecordService orgCveRecordService;
    private final EntityManager entityManager;
    private final FindingCorrelationAnalysisService findingCorrelationAnalysisService;
    private final FindingCorrelationMutationService findingCorrelationMutationService;
    private final FindingSlaService findingSlaService;
    private final VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService;
    private final VulnerabilityIntelSummarySourceRepository vulnerabilityIntelSummarySourceRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final FindingUpsertService findingUpsertService;

    public FindingComponentRecomputeService(
            FindingRepository findingRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            InventoryComponentRepository inventoryComponentRepository,
            CorrelationCandidateService correlationCandidateService,
            RiskPolicyService riskPolicyService,
            FindingsScoreService findingsScoreService,
            FindingWorkflowService findingWorkflowService,
            FindingEvidenceService findingEvidenceService,
            PrecedenceResolverService precedenceResolverService,
            ImpactEvaluationService impactEvaluationService,
            OrgCveRecordService orgCveRecordService,
            EntityManager entityManager,
            FindingCorrelationAnalysisService findingCorrelationAnalysisService,
            FindingCorrelationMutationService findingCorrelationMutationService,
            FindingSlaService findingSlaService,
            VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService,
            VulnerabilityIntelSummarySourceRepository vulnerabilityIntelSummarySourceRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            FindingUpsertService findingUpsertService
    ) {
        this.findingRepository = findingRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.correlationCandidateService = correlationCandidateService;
        this.riskPolicyService = riskPolicyService;
        this.findingsScoreService = findingsScoreService;
        this.findingWorkflowService = findingWorkflowService;
        this.findingEvidenceService = findingEvidenceService;
        this.precedenceResolverService = precedenceResolverService;
        this.impactEvaluationService = impactEvaluationService;
        this.orgCveRecordService = orgCveRecordService;
        this.entityManager = entityManager;
        this.findingCorrelationAnalysisService = findingCorrelationAnalysisService;
        this.findingCorrelationMutationService = findingCorrelationMutationService;
        this.findingSlaService = findingSlaService;
        this.vulnerabilitySourceFilterConfigService = vulnerabilitySourceFilterConfigService;
        this.vulnerabilityIntelSummarySourceRepository = vulnerabilityIntelSummarySourceRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.findingUpsertService = findingUpsertService;
    }

    private TenantApprovedIntelligenceService approvedIntelligence;
    private IntelligenceEvaluationFence evaluationFence;
    @org.springframework.beans.factory.annotation.Autowired
    void configureIntelligence(TenantApprovedIntelligenceService approvedIntelligence,IntelligenceEvaluationFence evaluationFence) {
        this.approvedIntelligence=approvedIntelligence;this.evaluationFence=evaluationFence;
    }

    @Transactional
    public int recomputeOnSoftwareDelta(UUID tenantId, UUID componentId) {
        if (tenantId == null || componentId == null) {
            return 0;
        }
        return recomputeOnSoftwareDeltaBatch(tenantId, List.of(componentId));
    }

    @Transactional
    public int recomputeOnSoftwareDeltaBatch(UUID tenantId, Collection<UUID> componentIds) {
        if (tenantId == null || componentIds == null || componentIds.isEmpty()) {
            return 0;
        }
        var intelligenceScope=evaluationFence.open(tenantId);
        FlushModeType previousFlushMode = entityManager.getFlushMode();
        // Flush any pending writes from the caller's transaction before switching to COMMIT mode,
        // otherwise queries inside this method won't observe entities that the caller just persisted
        // (notably affects @Transactional integration tests that share the EM with the recompute call).
        entityManager.flush();
        entityManager.setFlushMode(FlushModeType.COMMIT);
        try {
            List<InventoryComponent> components = inventoryComponentRepository.findAllById(componentIds).stream()
                    .filter(component -> component.getTenant() != null
                            && component.getTenant().getId() != null
                            && tenantId.equals(component.getTenant().getId()))
                    .sorted(Comparator.comparing(InventoryComponent::getId))
                    .toList();
            if (components.isEmpty()) {
                return 0;
            }
            RiskPolicy policy = riskPolicyService.getOrCreate(components.get(0).getTenant());
            CorrelationCandidateService.CandidateBundle candidateBundle =
                    correlationCandidateService.buildCandidateBundle(components);
            Set<UUID> scopedComponentIds = components.stream()
                    .map(InventoryComponent::getId)
                    .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
            Map<UUID, List<Finding>> existingFindingsByComponentId = new HashMap<>();
            findingRepository.findByComponent_IdIn(scopedComponentIds).forEach(finding -> {
                if (finding.getComponent() == null || finding.getComponent().getId() == null) {
                    return;
                }
                existingFindingsByComponentId
                        .computeIfAbsent(finding.getComponent().getId(), ignored -> new ArrayList<>())
                        .add(finding);
            });
            Map<UUID, List<ComponentVulnerabilityState>> existingStatesByComponentId = new HashMap<>();
            componentVulnerabilityStateRepository.findByComponent_IdIn(scopedComponentIds).forEach(state -> {
                if (state.getTenant() == null || state.getTenant().getId() == null || !tenantId.equals(state.getTenant().getId())) {
                    return;
                }
                if (state.getComponent() == null || state.getComponent().getId() == null) {
                    return;
                }
                existingStatesByComponentId
                        .computeIfAbsent(state.getComponent().getId(), ignored -> new ArrayList<>())
                        .add(state);
            });
            Instant now = Instant.now();
            int total = 0;
            Set<UUID> touchedVulnerabilityIds = new LinkedHashSet<>();
            for (InventoryComponent component : components) {
                ComponentRecomputeResult result = recomputeForComponent(
                        component.getTenant(),
                        component,
                        policy,
                        now,
                        candidateBundle,
                        existingFindingsByComponentId.getOrDefault(component.getId(), List.of()),
                        existingStatesByComponentId.getOrDefault(component.getId(), List.of())
                );
                total += result.activeFindingCount();
                touchedVulnerabilityIds.addAll(result.touchedVulnerabilityIds());
            }
            entityManager.flush();
            if (!touchedVulnerabilityIds.isEmpty()) {
                orgCveRecordService.refreshForTenantAndVulnerabilities(tenantId, touchedVulnerabilityIds);
            }
            return total;
        } finally {
            entityManager.setFlushMode(previousFlushMode);
            intelligenceScope.close();
        }
    }

    private ComponentRecomputeResult recomputeForComponent(
            Tenant tenant,
            InventoryComponent component,
            RiskPolicy policy,
            Instant now,
            CorrelationCandidateService.CandidateBundle candidateBundle,
            List<Finding> prefetchedFindings,
            List<ComponentVulnerabilityState> prefetchedStates
    ) {
        List<Finding> existing = prefetchedFindings == null ? findingRepository.findByComponent(component) : prefetchedFindings;
        List<ComponentVulnerabilityState> existingStates = prefetchedStates == null
                ? tenantSchemaExecutionService.run(tenant, () -> componentVulnerabilityStateRepository.findByComponent(component))
                : prefetchedStates;
        Set<UUID> touchedVulnerabilityIds = collectTouchedVulnerabilityIds(existing, existingStates);
        if (component.getAsset() == null
                || component.getAsset().getState() != AssetState.ACTIVE
                || component.getComponentStatus() != InventoryComponentStatus.ACTIVE) {
            resolveInactiveComponentAssessments(existingStates, now);
            resolveInactiveComponentFindings(existing, policy, component, now);
            return new ComponentRecomputeResult(0, touchedVulnerabilityIds);
        }

        CorrelationCandidateService.CandidateBundle bundle = candidateBundle == null
                ? correlationCandidateService.buildCandidateBundle(List.of(component))
                : candidateBundle;
        Set<String> enabledSources=vulnerabilitySourceFilterConfigService.enabledSourcesForCorrelation(tenant);
        List<CorrelationCandidateService.CandidateMatch> allCandidates=correlationCandidateService.candidatesForComponent(component,bundle);
        List<CorrelationCandidateService.CandidateMatch> candidates=allCandidates.stream()
                .filter(match -> IntelligenceSourceRegistry.enabled(match.target().getSource(),enabledSources)).toList();
        Map<UUID, List<PrecedenceResolverService.CandidateDecision>> decisionsByVulnerability =
                findingCorrelationAnalysisService.buildCandidateDecisionsByVulnerability(component, allCandidates, policy);
        Set<UUID> candidateVulnerabilityIdsBeforeSourceFilter = new HashSet<>(decisionsByVulnerability.keySet());
        decisionsByVulnerability = filterByEnabledSources(tenant, decisionsByVulnerability);
        Set<UUID> sourceDisabledVulnerabilityIds = new HashSet<>(candidateVulnerabilityIdsBeforeSourceFilter);
        sourceDisabledVulnerabilityIds.removeAll(decisionsByVulnerability.keySet());

        consolidateFindingIdentities(existing);
        Map<UUID, Finding> existingByVulnerability = new HashMap<>();
        for (Finding finding : existing) {
            if (finding.getIntelligenceMergedIntoId()==null && finding.getVulnerability() != null && finding.getVulnerability().getId() != null) {
                existingByVulnerability.put(finding.getVulnerability().getId(), finding);
            }
        }
        Map<UUID, ComponentVulnerabilityState> existingStateByVulnerability = new HashMap<>();
        for (ComponentVulnerabilityState state : existingStates) {
            if (state.getVulnerability() != null && state.getVulnerability().getId() != null) {
                existingStateByVulnerability.put(state.getVulnerability().getId(), state);
            }
        }
        touchedVulnerabilityIds.addAll(existingByVulnerability.keySet());
        touchedVulnerabilityIds.addAll(existingStateByVulnerability.keySet());
        touchedVulnerabilityIds.addAll(decisionsByVulnerability.keySet());

        Set<UUID> activeVulnerabilityIds = new HashSet<>();
        Set<UUID> evaluatedVulnerabilityIds = new HashSet<>();
        List<Finding> toPersist = new ArrayList<>();
        List<Finding> createdFindings = new ArrayList<>();
        List<ComponentVulnerabilityState> stateRowsToPersist = new ArrayList<>();
        List<UUID> sortedVulnerabilityIds = new ArrayList<>(decisionsByVulnerability.keySet());
        sortedVulnerabilityIds.sort(UUID::compareTo);

        for (UUID vulnerabilityId : sortedVulnerabilityIds) {
            List<PrecedenceResolverService.CandidateDecision> decisions = decisionsByVulnerability.get(vulnerabilityId);
            if (decisions == null || decisions.isEmpty()) {
                continue;
            }
            evaluatedVulnerabilityIds.add(vulnerabilityId);

            PrecedenceResolverService.PrecedenceResolution resolution = precedenceResolverService.resolve(decisions);
            PrecedenceResolverService.CandidateDecision selected = resolution.primary();
            if (selected == null || selected.target() == null || selected.target().getVulnerability() == null) {
                continue;
            }
            Vulnerability vulnerability = selected.target().getVulnerability();
            if (vulnerability.getId() == null) {
                continue;
            }

            ImpactEvaluationService.VexOverlayOutcome vexOverlay =
                    findingCorrelationMutationService.resolveVexOverlay(component, vulnerabilityId, null, candidates, policy);
            ImpactEvaluationService.ImpactAssessment impactAssessment =
                    impactEvaluationService.evaluate(resolution, selected, vexOverlay);
            findingCorrelationMutationService.upsertComponentVulnerabilityState(
                    tenant,
                    component,
                    vulnerability,
                    selected,
                    resolution,
                    vexOverlay,
                    impactAssessment,
                    now,
                    existingStateByVulnerability,
                    stateRowsToPersist
            );
            if (!impactAssessment.findingEligible()) {
                continue;
            }

            Finding finding = existingByVulnerability.get(vulnerability.getId());
            PrecedenceResolverService.CandidateDecision findingSelected = selected;
            if (finding == null) {
                findingSelected = findingCorrelationAnalysisService.selectAutomaticFindingCandidate(resolution, decisions);
                if (findingSelected == null) {
                    continue;
                }
            }

            Vulnerability effective=approvedIntelligence.resolve(vulnerability,enabledSources);
            String existingSeverityOverride = finding != null ? finding.getSeverityOverride() : null;
            double riskScore = findingsScoreService.computeFromParts(
                    policy.getFindingsScoreConfig(), effective, component.getAsset(), component, existingSeverityOverride);
            VulnerabilityTarget target = findingSelected.target();
            String evidence = findingEvidenceService.buildEvidence(
                    component,
                    effective,
                    target,
                    findingSelected,
                    resolution,
                    null
            );
            evidence = findingCorrelationMutationService.withVexOverlayEvidence(evidence, vexOverlay);
            final PrecedenceResolverService.CandidateDecision selectedForUpsert = findingSelected;
            final String evidenceForUpsert = evidence;
            final double riskScoreForUpsert = riskScore;

            Finding candidate = findingCorrelationMutationService.createFinding(
                    tenant,
                    component.getAsset(),
                    component,
                    vulnerability,
                    selectedForUpsert,
                    resolution,
                    riskScoreForUpsert,
                    evidenceForUpsert,
                    now,
                    policy
            );
            candidate.setIntelligenceSeverity(effective.getSeverity());
            candidate.setIntelligenceEpss(effective.getEpssScore());
            candidate.setIntelligenceInKev(effective.isInKev());
            evaluationFence.stamp(candidate);
            String nextPrecedenceTrace = toJson(resolution.precedenceTrace());
            FindingUpsertService.UpsertResult upsertResult = findingUpsertService.upsert(candidate, existingFinding -> {
                boolean returningToEligibility=!"ELIGIBLE".equals(existingFinding.getIntelligenceEligibility());
                boolean reopened = !returningToEligibility && (existingFinding.getStatus() == FindingStatus.RESOLVED
                        || existingFinding.getStatus() == FindingStatus.AUTO_CLOSED);
                boolean changed = reopened || returningToEligibility;
                existingFinding.setIntelligenceEligibility("ELIGIBLE");
                existingFinding.setIntelligenceSeverity(effective.getSeverity());
                existingFinding.setIntelligenceEpss(effective.getEpssScore());
                existingFinding.setIntelligenceInKev(effective.isInKev());
                evaluationFence.stamp(existingFinding);
                if (reopened) {
                    findingWorkflowService.reopenByObservation(existingFinding, now, null);
                } else {
                    if (existingFinding.getConsecutiveMisses() != 0 || existingFinding.getAutoCloseEligibleAt() != null) {
                        changed = true;
                    }
                    findingWorkflowService.markObserved(existingFinding, now, null);
                }

                FindingDecisionState nextDecisionState = impactAssessment.findingDecisionState();
                if (existingFinding.getDecisionState() != nextDecisionState) {
                    changed = true;
                }
                String nextMatchedBy = selectedForUpsert.matchedBy();
                if (!Objects.equals(existingFinding.getMatchedBy(), nextMatchedBy)) {
                    changed = true;
                }
                if (Double.compare(existingFinding.getRiskScore(), riskScoreForUpsert) != 0) {
                    changed = true;
                }
                Instant nextDueAt = findingSlaService.deriveDueAt(existingFinding.getFirstObservedAt(), riskScoreForUpsert, component.getAsset(), policy);
                if (!Objects.equals(existingFinding.getDueAt(), nextDueAt)) {
                    changed = true;
                }
                if (Double.compare(existingFinding.getConfidenceScore(), selectedForUpsert.confidence()) != 0) {
                    changed = true;
                }
                if (!Objects.equals(existingFinding.getEvidence(), evidenceForUpsert)) {
                    changed = true;
                }
                if (!Objects.equals(existingFinding.getPrecedenceTrace(), nextPrecedenceTrace)) {
                    changed = true;
                }

                if (!changed) {
                    return FindingUpsertService.UpsertAction.UNCHANGED;
                }
                existingFinding.setDecisionState(nextDecisionState);
                existingFinding.setMatchedBy(nextMatchedBy);
                existingFinding.setRiskScore(riskScoreForUpsert);
                existingFinding.setDueAt(nextDueAt);
                existingFinding.setConfidenceScore(selectedForUpsert.confidence());
                findingCorrelationMutationService.setEvidenceWithVex(existingFinding, evidenceForUpsert);
                existingFinding.setPrecedenceTrace(nextPrecedenceTrace);
                existingFinding.touch();
                return reopened ? FindingUpsertService.UpsertAction.REOPENED : FindingUpsertService.UpsertAction.UPDATED;
            });
            finding = upsertResult.finding();
            existingByVulnerability.put(vulnerability.getId(), finding);
            activeVulnerabilityIds.add(vulnerability.getId());
            if (upsertResult.action() == FindingUpsertService.UpsertAction.CREATED) {
                createdFindings.add(finding);
            }
        }

        for (Finding finding : existing) {
            if(finding.getIntelligenceMergedIntoId()!=null) continue;
            UUID vulnerabilityId = finding.getVulnerability() == null ? null : finding.getVulnerability().getId();
            if (vulnerabilityId!=null && !activeVulnerabilityIds.contains(vulnerabilityId)) {
                String eligibility=sourceDisabledVulnerabilityIds.contains(vulnerabilityId) ? "SOURCE_DISABLED"
                        : evaluationFence.hasApprovedApplicability(vulnerabilityId) ? "ELIGIBLE" : "INTELLIGENCE_WITHDRAWN";
                finding.setIntelligenceEligibility(eligibility);
                evaluationFence.stamp(finding);
                toPersist.add(finding);
                if(!"ELIGIBLE".equals(eligibility)) continue;
            }
            if (vulnerabilityId != null
                    && !activeVulnerabilityIds.contains(vulnerabilityId)
                    && finding.getStatus() != FindingStatus.RESOLVED
                    && finding.getStatus() != FindingStatus.AUTO_CLOSED) {
                FindingCloseReason reason = sourceDisabledVulnerabilityIds.contains(vulnerabilityId)
                        ? FindingCloseReason.AUTO_SOURCE_DISABLED
                        : FindingCloseReason.AUTO_NOT_OBSERVED;
                markMissingOrAutoClose(finding, policy, reason, now);
                finding.touch();
                toPersist.add(finding);
            }
        }

        for (ComponentVulnerabilityState state : existingStateByVulnerability.values()) {
            if (state.getVulnerability() == null || state.getVulnerability().getId() == null) {
                continue;
            }
            UUID vulnerabilityId = state.getVulnerability().getId();
            if (evaluatedVulnerabilityIds.contains(vulnerabilityId)) {
                continue;
            }
            if (state.getApplicabilityState() == ApplicabilityState.NOT_APPLICABLE
                    && state.getImpactState() == ImpactState.NOT_IMPACTED) {
                continue;
            }
            state.setApplicabilityState(ApplicabilityState.NOT_APPLICABLE);
            state.setApplicabilityReason("component_not_observed");
            state.setImpactState(ImpactState.NOT_IMPACTED);
            state.setImpactReason("component_not_observed");
            state.setVexStatus("UNKNOWN");
            state.setVexProvider("unknown");
            state.setVexFreshness("UNKNOWN");
            state.setVexSource(null);
            state.setVexTargetId(null);
            state.setMatchedVexAssertionId(null);
            state.setMatchedBy("not-observed");
            state.setSelectedTargetSource(null);
            state.setPrecedenceReason("component_not_observed");
            state.setConfidenceScore(0.0);
            state.setEligibleForFinding(false);
            state.setTraceJson("{\"reason\":\"component_not_observed\"}");
            state.setLastEvaluatedAt(now);
            state.setStateChangedAt(now);
            state.touch();
            stateRowsToPersist.add(state);
        }

        if (!stateRowsToPersist.isEmpty()) {
            componentVulnerabilityStateRepository.saveAll(stateRowsToPersist);
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
        return new ComponentRecomputeResult(activeVulnerabilityIds.size(), touchedVulnerabilityIds);
    }

    private int resolveInactiveComponentFindings(
            List<Finding> existing,
            RiskPolicy policy,
            InventoryComponent component,
            Instant now
    ) {
        if (existing.isEmpty()) {
            return 0;
        }
        List<Finding> toPersist = new ArrayList<>();
        for (Finding finding : existing) {
            if (finding.getStatus() == FindingStatus.RESOLVED || finding.getStatus() == FindingStatus.AUTO_CLOSED) {
                continue;
            }
            FindingCloseReason reason = component.getAsset() != null && component.getAsset().getState() != AssetState.ACTIVE
                    ? FindingCloseReason.AUTO_ASSET_RETIRED
                    : FindingCloseReason.AUTO_COMPONENT_REMOVED;
            boolean enabled = reason == FindingCloseReason.AUTO_ASSET_RETIRED
                    ? isAutoCloseEnabled(policy) && policy.isAutoCloseAssetRetiredEnabled()
                    : isAutoCloseEnabled(policy) && policy.isAutoCloseComponentRemovedEnabled();
            if (!enabled || finding.getStatus() != FindingStatus.OPEN) {
                continue;
            }
            findingWorkflowService.autoCloseFinding(
                    finding,
                    reason,
                    reason == FindingCloseReason.AUTO_ASSET_RETIRED
                            ? "Finding auto-closed because the asset is no longer active"
                            : "Finding auto-closed because the component is no longer active",
                    Map.of(
                            "assetState", component.getAsset() == null ? "" : component.getAsset().getState().name(),
                            "componentStatus", component.getComponentStatus().name()
                    ),
                    now);
            finding.setLastObservedAt(now);
            finding.touch();
            toPersist.add(finding);
        }
        if (!toPersist.isEmpty()) {
            findingRepository.saveAll(toPersist);
        }
        return 0;
    }

    private void markMissingOrAutoClose(
            Finding finding,
            RiskPolicy policy,
            FindingCloseReason reason,
            Instant now
    ) {
        if (finding.getStatus() != FindingStatus.OPEN) {
            return;
        }
        int consecutiveMisses = finding.getConsecutiveMisses() + 1;
        finding.setConsecutiveMisses(consecutiveMisses);
        if (finding.getAutoCloseEligibleAt() == null) {
            finding.setAutoCloseEligibleAt(now.plus(java.time.Duration.ofDays(autoCloseGraceDays(policy))));
        }
        if (!isAutoCloseEnabled(policy)
                || !isAutoCloseReasonEnabled(policy, reason)
                || consecutiveMisses < policy.getAutoCloseRequiredConsecutiveMisses()
                || finding.getAutoCloseEligibleAt().isAfter(now)) {
            return;
        }
        findingWorkflowService.autoCloseFinding(
                finding,
                reason,
                reason == FindingCloseReason.AUTO_SOURCE_DISABLED
                        ? "Finding auto-closed because its vulnerability source is disabled"
                        : "Finding auto-closed because it was not observed in recent scans",
                Map.of(
                        "consecutiveMisses", consecutiveMisses,
                        "requiredConsecutiveMisses", policy.getAutoCloseRequiredConsecutiveMisses(),
                        "autoCloseEligibleAt", finding.getAutoCloseEligibleAt()
                ),
                now);
    }

    private void resolveInactiveComponentAssessments(List<ComponentVulnerabilityState> existingStates, Instant now) {
        if (existingStates == null || existingStates.isEmpty()) {
            return;
        }
        List<ComponentVulnerabilityState> toPersist = new ArrayList<>();
        for (ComponentVulnerabilityState state : existingStates) {
            if (state.getApplicabilityState() == ApplicabilityState.NOT_APPLICABLE
                    && state.getImpactState() == ImpactState.NOT_IMPACTED) {
                continue;
            }
            state.setApplicabilityState(ApplicabilityState.NOT_APPLICABLE);
            state.setApplicabilityReason("component_inactive");
            state.setImpactState(ImpactState.NOT_IMPACTED);
            state.setImpactReason("component_inactive");
            state.setVexStatus("UNKNOWN");
            state.setVexProvider("unknown");
            state.setVexFreshness("UNKNOWN");
            state.setVexSource(null);
            state.setVexTargetId(null);
            state.setMatchedVexAssertionId(null);
            state.setMatchedBy("component-inactive");
            state.setSelectedTargetSource(null);
            state.setPrecedenceReason("component_inactive");
            state.setConfidenceScore(0.0);
            state.setEligibleForFinding(false);
            state.setTraceJson("{\"reason\":\"component_inactive\"}");
            state.setLastEvaluatedAt(now);
            state.setStateChangedAt(now);
            state.touch();
            toPersist.add(state);
        }
        if (!toPersist.isEmpty()) {
            componentVulnerabilityStateRepository.saveAll(toPersist);
        }
    }

    private Set<UUID> collectTouchedVulnerabilityIds(
            List<Finding> existingFindings,
            List<ComponentVulnerabilityState> existingStates
    ) {
        Set<UUID> vulnerabilityIds = new LinkedHashSet<>();
        if (existingFindings != null) {
            for (Finding finding : existingFindings) {
                UUID vulnerabilityId = finding.getVulnerability() == null ? null : finding.getVulnerability().getId();
                if (vulnerabilityId != null) {
                    vulnerabilityIds.add(vulnerabilityId);
                }
            }
        }
        if (existingStates != null) {
            for (ComponentVulnerabilityState state : existingStates) {
                UUID vulnerabilityId = state.getVulnerability() == null ? null : state.getVulnerability().getId();
                if (vulnerabilityId != null) {
                    vulnerabilityIds.add(vulnerabilityId);
                }
            }
        }
        return vulnerabilityIds;
    }

    private void consolidateFindingIdentities(List<Finding> findings) {
        Map<UUID,List<Finding>> groups=new HashMap<>();
        for(Finding finding:findings) {
            if(finding.getVulnerability()==null || finding.getIntelligenceMergedIntoId()!=null) continue;
            UUID canonical=evaluationFence.canonical(finding.getVulnerability().getId());
            groups.computeIfAbsent(canonical,ignored -> new ArrayList<>()).add(finding);
        }
        groups.forEach((canonical,group) -> {
            Finding master=group.stream().filter(finding -> canonical.equals(finding.getVulnerability().getId())).findFirst()
                    .orElseGet(() -> group.stream().min(Comparator.comparing(Finding::getId)).orElseThrow());
            boolean identityChanged=group.size()>1 || !canonical.equals(master.getVulnerability().getId());
            if(identityChanged) master.setIntelligenceEligibility("INTELLIGENCE_WITHDRAWN");
            for(Finding duplicate:group) {
                if(duplicate==master) continue;
                duplicate.setIntelligenceMergedIntoId(master.getId());duplicate.setIntelligenceEligibility("INTELLIGENCE_WITHDRAWN");
                evaluationFence.stamp(duplicate);
                if(duplicate.getStatus()==FindingStatus.SUPPRESSED && master.getStatus()==FindingStatus.OPEN) {
                    master.setStatus(FindingStatus.SUPPRESSED);master.setSuppressionReason(duplicate.getSuppressionReason());master.setSuppressedUntil(duplicate.getSuppressedUntil());
                } else if(duplicate.getStatus()==FindingStatus.RESOLVED && master.getStatus()==FindingStatus.OPEN) {
                    master.setStatus(FindingStatus.RESOLVED);master.setClosedAt(duplicate.getClosedAt());master.setClosedBy(duplicate.getClosedBy());master.setClosedReason(duplicate.getClosedReason());
                }
            }
            if(!canonical.equals(master.getVulnerability().getId())) master.setVulnerability(entityManager.getReference(Vulnerability.class,canonical));
        });
    }

    private Map<UUID, List<PrecedenceResolverService.CandidateDecision>> filterByEnabledSources(
            Tenant tenant,
            Map<UUID, List<PrecedenceResolverService.CandidateDecision>> decisionsByVulnerability
    ) {
        if (tenant == null || decisionsByVulnerability.isEmpty()) {
            return decisionsByVulnerability;
        }
        Set<String> enabledSources = vulnerabilitySourceFilterConfigService.enabledSourcesForCorrelation(tenant).stream()
                .map(source -> source.toLowerCase(java.util.Locale.ROOT))
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        if (enabledSources.isEmpty()) {
            return Map.of();
        }

        Map<UUID,List<PrecedenceResolverService.CandidateDecision>> filtered=new HashMap<>();
        decisionsByVulnerability.forEach((id,decisions) -> {
            var eligible=decisions.stream().filter(decision -> decision.target()!=null
                    && IntelligenceSourceRegistry.applicable(decision.target().getSource())
                    && IntelligenceSourceRegistry.enabled(decision.target().getSource(),enabledSources)).toList();
            if(!eligible.isEmpty()) filtered.put(id,eligible);
        });
        return filtered;
    }

    private record ComponentRecomputeResult(
            int activeFindingCount,
            Set<UUID> touchedVulnerabilityIds
    ) {
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

    private boolean isAutoCloseEnabled(RiskPolicy policy) {
        return policy != null && policy.isAutoCloseEnabled();
    }

    private boolean isAutoCloseReasonEnabled(RiskPolicy policy, FindingCloseReason reason) {
        if (policy == null) {
            return false;
        }
        return switch (reason) {
            case AUTO_SOURCE_DISABLED -> policy.isAutoCloseSourceDisabledEnabled();
            case AUTO_NOT_OBSERVED -> policy.isAutoCloseNotObservedEnabled();
            case AUTO_COMPONENT_REMOVED -> policy.isAutoCloseComponentRemovedEnabled();
            case AUTO_ASSET_RETIRED -> policy.isAutoCloseAssetRetiredEnabled();
            case AUTO_DUPLICATE -> policy.isAutoCloseDuplicateEnabled();
            default -> false;
        };
    }

    private int autoCloseGraceDays(RiskPolicy policy) {
        return policy == null ? 0 : Math.max(0, policy.getAutoCloseAfterDays());
    }
}
