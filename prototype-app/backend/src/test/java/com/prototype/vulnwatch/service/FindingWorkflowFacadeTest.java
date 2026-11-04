package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyDouble;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.prototype.vulnwatch.domain.AnalystDisposition;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class FindingWorkflowFacadeTest {

    @Mock private FindingRepository findingRepository;
    @Mock private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    @Mock private InventoryComponentRepository inventoryComponentRepository;
    @Mock private RiskPolicyService riskPolicyService;
    @Mock private FindingsScoreService findingsScoreService;
    @Mock private FindingWorkflowService findingWorkflowService;
    @Mock private OrgCveRecordService orgCveRecordService;
    @Mock private FindingSlaService findingSlaService;
    @Mock private OwnershipRuleService ownershipRuleService;
    @Mock private TenantSchemaExecutionService tenantSchemaExecutionService;
    private FindingWorkflowFacade facade;
    private Tenant tenant;
    private UUID tenantId;
    private Vulnerability vulnerability;
    private UUID vulnerabilityId;

    @BeforeEach
    void setUp() {
        facade = new FindingWorkflowFacade(
                findingRepository,
                componentVulnerabilityStateRepository,
                inventoryComponentRepository,
                riskPolicyService,
                findingsScoreService,
                findingWorkflowService,
                orgCveRecordService,
                findingSlaService,
                ownershipRuleService,
                new ObjectMapper().registerModule(new JavaTimeModule()),
                tenantSchemaExecutionService,
                new FindingUpsertService(findingRepository)
        );
        facade.setSuppressionMutations(TestSuppressionMutations.create());
        doAnswer(invocation -> invocation.getArgument(1, java.util.function.Supplier.class).get())
                .when(tenantSchemaExecutionService)
                .run(org.mockito.ArgumentMatchers.nullable(Tenant.class), org.mockito.ArgumentMatchers.<java.util.function.Supplier<Object>>any());
        tenantId = UUID.randomUUID();
        tenant = new Tenant();
        tenant.setId(tenantId);
        vulnerability = new Vulnerability();
        vulnerabilityId = UUID.randomUUID();
        setField(vulnerability, "id", vulnerabilityId);
    }

    // -------------------------------------------------------------------------
    // createManualFindingsForVulnerability — guards
    // -------------------------------------------------------------------------

    @Test
    void createManual_nullTenant_returnsZeroResultAndNoOp() {
        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                null, vulnerability, "j", "u", List.of(), Map.of(), Map.of());
        assertResult(r, 0, 0, 0, 0);
        verifyNoInteractions(findingRepository, componentVulnerabilityStateRepository, orgCveRecordService);
    }

    @Test
    void createManual_tenantWithNullId_returnsZeroResult() {
        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                new Tenant(), vulnerability, "j", "u", List.of(), Map.of(), Map.of());
        assertResult(r, 0, 0, 0, 0);
    }

    @Test
    void createManual_nullVulnerability_returnsZeroResult() {
        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, null, "j", "u", List.of(), Map.of(), Map.of());
        assertResult(r, 0, 0, 0, 0);
    }

    @Test
    void createManual_vulnerabilityWithNullId_returnsZeroResult() {
        Vulnerability v = new Vulnerability();
        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, v, "j", "u", List.of(), Map.of(), Map.of());
        assertResult(r, 0, 0, 0, 0);
    }

    // -------------------------------------------------------------------------
    // Eligibility filter
    // -------------------------------------------------------------------------

    @Test
    void createManual_stateEligibleForFinding_treatedAsEligible() {
        ComponentVulnerabilityState state = aState(true, ApplicabilityState.UNKNOWN, AnalystDisposition.UNKNOWN);
        wireForCreate(List.of(state), List.of());

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        assertResult(r, 1, 1, 0, 0);
    }

    @Test
    void createManual_analystOverrideToApplicableAndImpacted_eligibleEvenWhenNotEligibleByDefault() {
        ComponentVulnerabilityState state = aState(false, ApplicabilityState.NOT_APPLICABLE, AnalystDisposition.NOT_IMPACTED);
        UUID componentId = state.getComponent().getId();
        Map<UUID, ApplicabilityState> appOverride = Map.of(componentId, ApplicabilityState.APPLICABLE);
        Map<UUID, AnalystDisposition> dispOverride = Map.of(componentId, AnalystDisposition.IMPACTED);
        wireForCreate(List.of(state), List.of());

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), appOverride, dispOverride);

        assertResult(r, 1, 1, 0, 0);
        // The created finding's evidence JSON records the analyst override
        ArgumentCaptor<Finding> saved = ArgumentCaptor.forClass(Finding.class);
        verify(findingRepository).saveAndFlush(saved.capture());
        String evidence = saved.getValue().getEvidence();
        assertTrue(evidence.contains("\"analystOverrideApplied\":true"),
                "evidence should record override, got: " + evidence);
        verify(findingWorkflowService).appendEvent(any(), eq("CREATED_BY_MANUAL_CVE_REVIEW"), eq("u"), any(), any());
    }

    @Test
    void createManual_overrideOnlyApplicabilityNotDisposition_notEligible() {
        ComponentVulnerabilityState state = aState(false, ApplicabilityState.NOT_APPLICABLE, AnalystDisposition.NOT_IMPACTED);
        UUID id = state.getComponent().getId();
        wireForCreate(List.of(state), List.of());

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(),
                Map.of(id, ApplicabilityState.APPLICABLE), Map.of());

        assertResult(r, 0, 0, 0, 0);
    }

    @Test
    void createManual_componentNotActive_skipped() {
        ComponentVulnerabilityState state = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED);
        state.getComponent().setComponentStatus(InventoryComponentStatus.RETIRED);
        wireForCreate(List.of(state), List.of());

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        assertResult(r, 0, 0, 0, 0);
    }

    @Test
    void createManual_componentWithoutAsset_skipped() {
        ComponentVulnerabilityState state = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED);
        state.getComponent().setAsset(null);
        wireForCreate(List.of(state), List.of());

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        assertResult(r, 0, 0, 0, 0);
    }

    @Test
    void createManual_componentWithoutId_skipped() {
        ComponentVulnerabilityState state = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED);
        setField(state.getComponent(), "id", null);
        wireForCreate(List.of(state), List.of());

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        assertResult(r, 0, 0, 0, 0);
    }

    // -------------------------------------------------------------------------
    // Selection by component id
    // -------------------------------------------------------------------------

    @Test
    void createManual_selectedIdsRestrictToMatchingComponents() {
        ComponentVulnerabilityState s1 = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED, "asset-a", "pkg-a", "1.0");
        ComponentVulnerabilityState s2 = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED, "asset-b", "pkg-b", "2.0");
        wireForCreate(List.of(s1, s2), List.of());

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u",
                List.of(s2.getComponent().getId()),
                Map.of(), Map.of());

        assertResult(r, 1, 1, 0, 0);
    }

    @Test
    void createManual_emptySelectedIdsTreatsAllAsCandidates() {
        ComponentVulnerabilityState s1 = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED, "asset-a", "pkg-a", "1.0");
        ComponentVulnerabilityState s2 = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED, "asset-b", "pkg-b", "2.0");
        wireForCreate(List.of(s1, s2), List.of());

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        assertResult(r, 2, 2, 0, 0);
    }

    @Test
    void createManual_nullSelectedIdsTreatsAllAsCandidates() {
        ComponentVulnerabilityState s = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED);
        wireForCreate(List.of(s), List.of());

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", null, Map.of(), Map.of());

        assertResult(r, 1, 1, 0, 0);
    }

    // -------------------------------------------------------------------------
    // Existing finding handling: alreadyOpen / reopen / create
    // -------------------------------------------------------------------------

    @Test
    void createManual_existingOpenFinding_incrementsAlreadyOpenAndDoesNotPersist() {
        ComponentVulnerabilityState state = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED);
        Finding existing = newFinding(state.getComponent(), FindingStatus.OPEN);
        wireForCreate(List.of(state), List.of(existing));

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        assertResult(r, 1, 0, 0, 1);
        verify(findingRepository, never()).saveAndFlush(any(Finding.class));
        verify(findingRepository, never()).save(any(Finding.class));
        verify(findingWorkflowService, never()).appendEvent(any(), any(), any(), any(), any());
    }

    @Test
    void createManual_existingResolvedFinding_isReopened() {
        ComponentVulnerabilityState state = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED);
        Finding existing = newFinding(state.getComponent(), FindingStatus.RESOLVED);
        existing.setSuppressionReason("old-reason");
        existing.setSuppressedUntil(Instant.now());
        wireForCreate(List.of(state), List.of(existing));

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        assertResult(r, 1, 0, 1, 0);
        assertEquals(FindingStatus.OPEN, existing.getStatus());
        assertNull(existing.getSuppressionReason());
        assertNull(existing.getSuppressedUntil());
        verify(findingWorkflowService).appendEvent(eq(existing), eq("REOPENED_BY_MANUAL_CVE_REVIEW"), eq("u"), any(), any());
    }

    @Test
    void createManual_existingAutoClosedFinding_isReopened() {
        ComponentVulnerabilityState state = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED);
        Finding existing = newFinding(state.getComponent(), FindingStatus.AUTO_CLOSED);
        wireForCreate(List.of(state), List.of(existing));

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        assertResult(r, 1, 0, 1, 0);
        assertEquals(FindingStatus.OPEN, existing.getStatus());
        verify(findingWorkflowService).appendEvent(any(), eq("REOPENED_BY_MANUAL_CVE_REVIEW"), any(), any(), any());
    }

    @Test
    void createManual_existingSuppressedFinding_isAlreadyOpen_notReopened() {
        ComponentVulnerabilityState state = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED);
        Finding existing = newFinding(state.getComponent(), FindingStatus.SUPPRESSED);
        wireForCreate(List.of(state), List.of(existing));

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        assertResult(r, 1, 0, 0, 1);
    }

    @Test
    void createManual_noExistingFinding_createsNewWithExpectedFieldsAndEvent() {
        ComponentVulnerabilityState state = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED);
        state.setMatchedBy("cpe-match");
        state.setConfidenceScore(0.85);
        wireForCreate(List.of(state), List.of());

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "  needed urgently  ", "alice", List.of(), Map.of(), Map.of());

        assertResult(r, 1, 1, 0, 0);
        ArgumentCaptor<Finding> savedCaptor = ArgumentCaptor.forClass(Finding.class);
        verify(findingRepository).saveAndFlush(savedCaptor.capture());
        Finding saved = savedCaptor.getValue();
        assertEquals(FindingStatus.OPEN, saved.getStatus());
        assertEquals("cpe-match", saved.getMatchedBy());
        assertEquals(7.5, saved.getRiskScore(), 0.0001);

        ArgumentCaptor<Map> meta = ArgumentCaptor.forClass(Map.class);
        verify(findingWorkflowService).appendEvent(eq(saved), eq("CREATED_BY_MANUAL_CVE_REVIEW"), eq("alice"), any(), meta.capture());
        // Justification trimmed on the way into the event
        assertEquals("needed urgently", meta.getValue().get("justification"));
        assertEquals("cpe-match", meta.getValue().get("matchedBy"));
        assertNotNull(saved.getDisplayId());
        assertTrue(saved.getDisplayId().startsWith("F-"));
        // analystOverride is computed via JSON round-trip; verify the source flag in evidence instead
        assertTrue(saved.getEvidence().contains("\"analystOverrideApplied\":false"));
    }

    @Test
    void createManual_stateWithoutMatchedBy_falsBackToDefaultLabel() {
        ComponentVulnerabilityState state = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED);
        state.setMatchedBy(null);
        wireForCreate(List.of(state), List.of());

        facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        ArgumentCaptor<Finding> saved = ArgumentCaptor.forClass(Finding.class);
        verify(findingRepository).saveAndFlush(saved.capture());
        assertEquals("manual-org-cve-review", saved.getValue().getMatchedBy());
    }

    @Test
    void createManual_alwaysCallsOrgCveRefresh_evenWhenNothingPersisted() {
        ComponentVulnerabilityState state = aState(false, ApplicabilityState.NOT_APPLICABLE, AnalystDisposition.NOT_IMPACTED);
        wireForCreate(List.of(state), List.of());

        facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        verify(orgCveRecordService).refreshForTenantAndVulnerabilities(eq(tenant), eq(List.of(vulnerabilityId)));
        verify(findingRepository, never()).saveAndFlush(any(Finding.class));
        verify(findingRepository, never()).save(any(Finding.class));
    }

    // -------------------------------------------------------------------------
    // Phase 2 — manually-added / uncorrelated components (no existing
    // ComponentVulnerabilityState) confirmed Applicable+Impacted via Investigation.
    // Regression coverage: this path must persist a ComponentVulnerabilityState so
    // org_cve_records (rolled up exclusively from that table) reflects the CVE as
    // Applicable, not just create a Finding.
    // -------------------------------------------------------------------------

    @Test
    void createManual_uncorrelatedComponentConfirmedApplicableAndImpacted_persistsComponentVulnerabilityState() {
        vulnerability.setExternalId("CVE-2099-0001");
        InventoryComponent component = uncorrelatedComponent();
        UUID componentId = component.getId();

        wireForCreate(List.of(), List.of());
        when(inventoryComponentRepository.findAllById(List.of(componentId))).thenReturn(List.of(component));
        when(componentVulnerabilityStateRepository.findByTenant_IdAndVulnerability_ExternalIdAndComponent_Id(
                tenantId, vulnerability.getExternalId(), componentId))
                .thenReturn(Optional.empty());

        ManualFindingCreationResult r = facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "investigation confirmed impact", "analyst1",
                List.of(componentId),
                Map.of(componentId, ApplicabilityState.APPLICABLE),
                Map.of(componentId, AnalystDisposition.IMPACTED));

        assertResult(r, 1, 1, 0, 0);

        ArgumentCaptor<ComponentVulnerabilityState> cvsCaptor = ArgumentCaptor.forClass(ComponentVulnerabilityState.class);
        verify(componentVulnerabilityStateRepository).save(cvsCaptor.capture());
        ComponentVulnerabilityState saved = cvsCaptor.getValue();
        assertEquals(ApplicabilityState.APPLICABLE, saved.getApplicabilityState());
        assertEquals(ImpactState.IMPACTED, saved.getImpactState());
        assertTrue(saved.isEligibleForFinding());
        assertEquals("manual-org-cve-review", saved.getMatchedBy());
        assertEquals(AnalystDisposition.IMPACTED, saved.getAnalystDisposition());
        assertEquals("analyst1", saved.getAnalystUpdatedBy());
        assertEquals(component, saved.getComponent());
        assertEquals(tenant, saved.getTenant());

        ArgumentCaptor<Finding> findingCaptor = ArgumentCaptor.forClass(Finding.class);
        verify(findingRepository).saveAndFlush(findingCaptor.capture());
        assertEquals(FindingStatus.OPEN, findingCaptor.getValue().getStatus());
        assertEquals("manual-org-cve-review", findingCaptor.getValue().getMatchedBy());

        verify(orgCveRecordService).refreshForTenantAndVulnerabilities(eq(tenant), eq(List.of(vulnerabilityId)));
    }

    @Test
    void createManual_uncorrelatedComponentWithExistingState_updatesInPlaceRatherThanDuplicating() {
        vulnerability.setExternalId("CVE-2099-0002");
        InventoryComponent component = uncorrelatedComponent();
        UUID componentId = component.getId();
        ComponentVulnerabilityState existingState = new ComponentVulnerabilityState();
        existingState.setComponent(component);
        existingState.setVulnerability(vulnerability);
        existingState.setTenant(tenant);
        existingState.setApplicabilityState(ApplicabilityState.UNKNOWN);
        existingState.setEligibleForFinding(false);

        // No CVS rows are returned by the bulk lookup (this component is uncorrelated for
        // Phase 1 purposes), but a prior manual-review row already exists for this exact
        // tenant/CVE/component tuple — re-running "Create Findings" must update it in place.
        wireForCreate(List.of(), List.of());
        when(inventoryComponentRepository.findAllById(List.of(componentId))).thenReturn(List.of(component));
        when(componentVulnerabilityStateRepository.findByTenant_IdAndVulnerability_ExternalIdAndComponent_Id(
                tenantId, vulnerability.getExternalId(), componentId))
                .thenReturn(Optional.of(existingState));

        facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "re-confirmed", "analyst1",
                List.of(componentId),
                Map.of(componentId, ApplicabilityState.APPLICABLE),
                Map.of(componentId, AnalystDisposition.IMPACTED));

        ArgumentCaptor<ComponentVulnerabilityState> cvsCaptor = ArgumentCaptor.forClass(ComponentVulnerabilityState.class);
        verify(componentVulnerabilityStateRepository).save(cvsCaptor.capture());
        assertEquals(existingState, cvsCaptor.getValue(), "must reuse and update the existing row, not create a duplicate");
        assertEquals(ApplicabilityState.APPLICABLE, existingState.getApplicabilityState());
        assertEquals(ImpactState.IMPACTED, existingState.getImpactState());
        assertTrue(existingState.isEligibleForFinding());
    }

    // -------------------------------------------------------------------------
    // confirmApplicabilityForComponents — Investigation-time applicability flip
    // (persists ComponentVulnerabilityState only; does NOT create a Finding, since
    // Create Findings remains a distinct, explicit step).
    // -------------------------------------------------------------------------

    @Test
    void confirmApplicability_realImpactedComponent_persistsApplicableStateWithoutCreatingFinding() {
        vulnerability.setExternalId("CVE-2099-0003");
        InventoryComponent component = uncorrelatedComponent();
        UUID componentId = component.getId();

        when(inventoryComponentRepository.findAllById(List.of(componentId))).thenReturn(List.of(component));
        when(componentVulnerabilityStateRepository.findByTenant_IdAndVulnerability_ExternalIdAndComponent_Id(
                tenantId, vulnerability.getExternalId(), componentId))
                .thenReturn(Optional.empty());

        int confirmedCount = facade.confirmApplicabilityForComponents(
                tenant, vulnerability, List.of(componentId), "investigation confirmed impact", "analyst1");

        assertEquals(1, confirmedCount);

        ArgumentCaptor<ComponentVulnerabilityState> cvsCaptor = ArgumentCaptor.forClass(ComponentVulnerabilityState.class);
        verify(componentVulnerabilityStateRepository).save(cvsCaptor.capture());
        ComponentVulnerabilityState saved = cvsCaptor.getValue();
        assertEquals(ApplicabilityState.APPLICABLE, saved.getApplicabilityState());
        assertEquals(ImpactState.IMPACTED, saved.getImpactState());
        assertTrue(saved.isEligibleForFinding());
        assertEquals("manual-org-cve-review", saved.getMatchedBy());
        assertEquals(AnalystDisposition.IMPACTED, saved.getAnalystDisposition());
        assertEquals("analyst1", saved.getAnalystUpdatedBy());
        assertEquals(component, saved.getComponent());
        assertEquals(tenant, saved.getTenant());

        verify(findingRepository, never()).saveAndFlush(any(Finding.class));
        verify(orgCveRecordService).refreshForTenantAndVulnerabilities(eq(tenant), eq(List.of(vulnerabilityId)));
    }

    @Test
    void confirmApplicability_inactiveComponent_isSkipped() {
        InventoryComponent component = uncorrelatedComponent();
        component.setComponentStatus(InventoryComponentStatus.RETIRED);
        UUID componentId = component.getId();
        when(inventoryComponentRepository.findAllById(List.of(componentId))).thenReturn(List.of(component));

        int confirmedCount = facade.confirmApplicabilityForComponents(
                tenant, vulnerability, List.of(componentId), "j", "u");

        assertEquals(0, confirmedCount);
        verify(componentVulnerabilityStateRepository, never()).save(any(ComponentVulnerabilityState.class));
        verifyNoInteractions(orgCveRecordService);
    }

    @Test
    void confirmApplicability_emptyComponentIds_isNoOp() {
        int confirmedCount = facade.confirmApplicabilityForComponents(tenant, vulnerability, List.of(), "j", "u");
        assertEquals(0, confirmedCount);
        verifyNoInteractions(componentVulnerabilityStateRepository, orgCveRecordService);
    }

    @Test
    void confirmApplicability_nullTenant_isNoOp() {
        int confirmedCount = facade.confirmApplicabilityForComponents(null, vulnerability, List.of(UUID.randomUUID()), "j", "u");
        assertEquals(0, confirmedCount);
        verifyNoInteractions(inventoryComponentRepository, componentVulnerabilityStateRepository, orgCveRecordService);
    }

    // -------------------------------------------------------------------------
    // suppressFindingsForVulnerability — guards and reason normalization
    // -------------------------------------------------------------------------

    @Test
    void suppress_nullTenant_returnsZero() {
        int n = facade.suppressFindingsForVulnerability(null, vulnerability, "r", "j", "u", null);
        assertEquals(0, n);
        verifyNoInteractions(findingWorkflowService);
    }

    @Test
    void suppress_tenantWithNullId_returnsZero() {
        int n = facade.suppressFindingsForVulnerability(new Tenant(), vulnerability, "r", "j", "u", null);
        assertEquals(0, n);
    }

    @Test
    void suppress_nullVulnerability_returnsZero() {
        assertEquals(0, facade.suppressFindingsForVulnerability(tenant, null, "r", "j", "u", null));
    }

    @Test
    void suppress_vulnerabilityWithNullId_returnsZero() {
        assertEquals(0, facade.suppressFindingsForVulnerability(tenant, new Vulnerability(), "r", "j", "u", null));
    }

    @Test
    void suppress_emptyFindings_returnsZeroWithoutBulkCall() {
        when(findingRepository.findByVulnerability_Id(vulnerabilityId)).thenReturn(List.of());

        int n = facade.suppressFindingsForVulnerability(tenant, vulnerability, "RISK", "j", "u", null);

        assertEquals(0, n);
        verify(findingWorkflowService, never()).updateWorkflowBulk(any(), any());
    }

    @Test
    void suppress_buildsBulkRequestAndJoinsReasonWithJustification() {
        Finding f = new Finding();
        Instant expires = Instant.parse("2026-12-01T00:00:00Z");
        when(findingRepository.findByVulnerability_Id(vulnerabilityId)).thenReturn(List.of(f));
        when(findingWorkflowService.updateWorkflowBulk(any(), any())).thenReturn(1);

        int n = facade.suppressFindingsForVulnerability(tenant, vulnerability, "RISK_ACCEPTED", "approved", "alice", expires);

        assertEquals(1, n);
        ArgumentCaptor<FindingWorkflowUpdateRequest> req = ArgumentCaptor.forClass(FindingWorkflowUpdateRequest.class);
        verify(findingWorkflowService).updateWorkflowBulk(eq(List.of(f)), req.capture());
        assertEquals(FindingStatus.SUPPRESSED.name(), req.getValue().status());
        assertEquals("RISK_ACCEPTED: approved", req.getValue().suppressionReason());
        assertEquals(expires, req.getValue().suppressedUntil());
        assertEquals("alice", req.getValue().actor());
    }

    @Test
    void suppress_blankReasonNormalizesToUnspecified() {
        Finding f = new Finding();
        when(findingRepository.findByVulnerability_Id(vulnerabilityId)).thenReturn(List.of(f));
        when(findingWorkflowService.updateWorkflowBulk(any(), any())).thenReturn(1);

        facade.suppressFindingsForVulnerability(tenant, vulnerability, "   ", "approved", "alice", null);

        ArgumentCaptor<FindingWorkflowUpdateRequest> req = ArgumentCaptor.forClass(FindingWorkflowUpdateRequest.class);
        verify(findingWorkflowService).updateWorkflowBulk(any(), req.capture());
        assertEquals("UNSPECIFIED: approved", req.getValue().suppressionReason());
    }

    @Test
    void suppress_blankJustificationOmitsColonSuffix() {
        Finding f = new Finding();
        when(findingRepository.findByVulnerability_Id(vulnerabilityId)).thenReturn(List.of(f));
        when(findingWorkflowService.updateWorkflowBulk(any(), any())).thenReturn(1);

        facade.suppressFindingsForVulnerability(tenant, vulnerability, "RISK_ACCEPTED", "  ", "alice", null);

        ArgumentCaptor<FindingWorkflowUpdateRequest> req = ArgumentCaptor.forClass(FindingWorkflowUpdateRequest.class);
        verify(findingWorkflowService).updateWorkflowBulk(any(), req.capture());
        assertEquals("RISK_ACCEPTED", req.getValue().suppressionReason());
    }

    @Test
    void suppress_nullReasonAndJustification_normalizesToUnspecifiedOnly() {
        Finding f = new Finding();
        when(findingRepository.findByVulnerability_Id(vulnerabilityId)).thenReturn(List.of(f));
        when(findingWorkflowService.updateWorkflowBulk(any(), any())).thenReturn(1);

        facade.suppressFindingsForVulnerability(tenant, vulnerability, null, null, "alice", null);

        ArgumentCaptor<FindingWorkflowUpdateRequest> req = ArgumentCaptor.forClass(FindingWorkflowUpdateRequest.class);
        verify(findingWorkflowService).updateWorkflowBulk(any(), req.capture());
        assertEquals("UNSPECIFIED", req.getValue().suppressionReason());
    }

    @Test
    void suppress_trimsReasonAndJustification() {
        Finding f = new Finding();
        when(findingRepository.findByVulnerability_Id(vulnerabilityId)).thenReturn(List.of(f));
        when(findingWorkflowService.updateWorkflowBulk(any(), any())).thenReturn(1);

        facade.suppressFindingsForVulnerability(
                tenant, vulnerability, "  RISK  ", "  reviewed  ", "alice", null);

        ArgumentCaptor<FindingWorkflowUpdateRequest> req = ArgumentCaptor.forClass(FindingWorkflowUpdateRequest.class);
        verify(findingWorkflowService).updateWorkflowBulk(any(), req.capture());
        assertEquals("RISK: reviewed", req.getValue().suppressionReason());
    }

    // -------------------------------------------------------------------------
    // Sort order — alphabetic on asset/package/version, case insensitive
    // -------------------------------------------------------------------------

    @Test
    void createManual_sortsByAssetThenPackageThenVersion() {
        ComponentVulnerabilityState s1 = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED, "Beta", "pkg", "1.0");
        ComponentVulnerabilityState s2 = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED, "alpha", "zzz", "1.0");
        ComponentVulnerabilityState s3 = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED, "alpha", "aaa", "9.0");
        ComponentVulnerabilityState s4 = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED, "alpha", "aaa", "1.0");
        wireForCreate(List.of(s1, s2, s3, s4), List.of());

        facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        ArgumentCaptor<Finding> saved = ArgumentCaptor.forClass(Finding.class);
        verify(findingRepository, times(4)).saveAndFlush(saved.capture());
        // Expected order: alpha/aaa/1.0, alpha/aaa/9.0, alpha/zzz/1.0, Beta/pkg/1.0
        List<Finding> findings = saved.getAllValues();
        assertEquals(4, findings.size());
        assertEquals(s4.getComponent().getId(), findings.get(0).getComponent().getId());
        assertEquals(s3.getComponent().getId(), findings.get(1).getComponent().getId());
        assertEquals(s2.getComponent().getId(), findings.get(2).getComponent().getId());
        assertEquals(s1.getComponent().getId(), findings.get(3).getComponent().getId());
    }

    // -------------------------------------------------------------------------
    // Reopen wipes suppression and applies fresh evidence
    // -------------------------------------------------------------------------

    @Test
    void createManual_reopen_clearsSuppressionFieldsAndSetsAffected() {
        ComponentVulnerabilityState state = aState(true, ApplicabilityState.APPLICABLE, AnalystDisposition.IMPACTED);
        Finding existing = newFinding(state.getComponent(), FindingStatus.RESOLVED);
        existing.setSuppressionReason("had-a-reason");
        existing.setSuppressedUntil(Instant.now().plusSeconds(3600));
        wireForCreate(List.of(state), List.of(existing));

        facade.createManualFindingsForVulnerability(
                tenant, vulnerability, "j", "u", List.of(), Map.of(), Map.of());

        // Inspect entity mutated in-place
        assertEquals(FindingStatus.OPEN, existing.getStatus());
        assertEquals(FindingDecisionState.AFFECTED, existing.getDecisionState());
        assertNull(existing.getSuppressionReason());
        assertNull(existing.getSuppressedUntil());
        assertNotNull(existing.getEvidence());
    }

    // -------------------------------------------------------------------------
    // Helpers / fixtures
    // -------------------------------------------------------------------------

    private void wireForCreate(List<ComponentVulnerabilityState> states, List<Finding> existing) {
        when(componentVulnerabilityStateRepository.findByVulnerability_Id(vulnerabilityId))
                .thenReturn(states);
        when(findingRepository.findByVulnerability_Id(vulnerabilityId))
                .thenReturn(existing);
        when(findingRepository.findFirstByComponent_IdAndVulnerability_Id(any(), any())).thenAnswer(invocation -> {
            UUID componentId = invocation.getArgument(0);
            UUID scopedVulnerabilityId = invocation.getArgument(1);
            return existing.stream()
                    .filter(finding -> finding.getComponent() != null
                            && Objects.equals(finding.getComponent().getId(), componentId)
                            && finding.getVulnerability() != null
                            && Objects.equals(finding.getVulnerability().getId(), scopedVulnerabilityId))
                    .findFirst();
        });
        when(findingRepository.saveAndFlush(any(Finding.class))).thenAnswer(invocation -> persistLikeJpa(invocation.getArgument(0)));
        when(findingRepository.save(any(Finding.class))).thenAnswer(invocation -> persistLikeJpa(invocation.getArgument(0)));
        when(riskPolicyService.getOrCreate(tenant)).thenReturn(new RiskPolicy());
        when(findingsScoreService.computeFromParts(anyString(), any(), any(), any(), any())).thenReturn(7.5);
        when(findingSlaService.deriveDueAt(any(), anyDouble(), any(), any())).thenReturn(Instant.now().plusSeconds(86400));
    }

    private Finding persistLikeJpa(Finding finding) {
        try {
            var method = Finding.class.getDeclaredMethod("ensureIdentifiers");
            method.setAccessible(true);
            method.invoke(finding);
            return finding;
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }

    private ComponentVulnerabilityState aState(
            boolean eligibleForFinding,
            ApplicabilityState applicability,
            AnalystDisposition disposition
    ) {
        return aState(eligibleForFinding, applicability, disposition, "asset-x", "pkg-x", "1.0.0");
    }

    private ComponentVulnerabilityState aState(
            boolean eligibleForFinding,
            ApplicabilityState applicability,
            AnalystDisposition disposition,
            String assetName,
            String packageName,
            String version
    ) {
        Asset asset = new Asset();
        asset.setName(assetName);
        InventoryComponent component = new InventoryComponent();
        setField(component, "id", UUID.randomUUID());
        component.setAsset(asset);
        component.setPackageName(packageName);
        component.setVersion(version);
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);

        ComponentVulnerabilityState state = new ComponentVulnerabilityState();
        state.setComponent(component);
        state.setVulnerability(vulnerability);
        state.setTenant(tenant);
        state.setApplicabilityState(applicability);
        state.setAnalystDisposition(disposition);
        state.setEligibleForFinding(eligibleForFinding);
        state.setMatchedBy("cpe");
        state.setConfidenceScore(1.0);
        return state;
    }

    private InventoryComponent uncorrelatedComponent() {
        Asset asset = new Asset();
        asset.setName("manual-asset");
        InventoryComponent component = new InventoryComponent();
        setField(component, "id", UUID.randomUUID());
        component.setAsset(asset);
        component.setPackageName("manual-pkg");
        component.setVersion("2.0.0");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        return component;
    }

    private Finding newFinding(InventoryComponent component, FindingStatus status) {
        Finding f = new Finding();
        f.setTenant(tenant);
        f.setAsset(component.getAsset());
        f.setComponent(component);
        f.setVulnerability(vulnerability);
        f.setStatus(status);
        f.setFirstObservedAt(Instant.now().minusSeconds(86400));
        return f;
    }

    private static void setField(Object obj, String name, Object value) {
        try {
            Field f = findField(obj.getClass(), name);
            f.setAccessible(true);
            f.set(obj, value);
        } catch (ReflectiveOperationException ex) {
            throw new RuntimeException(ex);
        }
    }

    private static Field findField(Class<?> type, String name) throws NoSuchFieldException {
        Class<?> current = type;
        while (current != null) {
            try {
                return current.getDeclaredField(name);
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            }
        }
        throw new NoSuchFieldException(name);
    }

    private static void assertResult(ManualFindingCreationResult r, int eligible, int created, int reopened, int alreadyOpen) {
        assertEquals(eligible, r.eligibleComponentCount(), "eligible");
        assertEquals(created, r.createdCount(), "created");
        assertEquals(reopened, r.reopenedCount(), "reopened");
        assertEquals(alreadyOpen, r.alreadyOpenCount(), "alreadyOpen");
    }

    @SuppressWarnings("unused")
    private static void unused(boolean v) {
        assertTrue(true);
    }
}
