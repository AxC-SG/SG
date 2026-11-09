package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.FindingResponse;
import com.prototype.vulnwatch.dto.FindingFilterValuesResponse;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class FindingQueryServiceTest {

    @Mock
    private FindingRepository findingRepository;
    @Mock
    private FindingsScoreService findingsScoreService;
    @Mock
    private RiskPolicyService riskPolicyService;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;
    @Mock
    private FindingListProjectionService findingListProjectionService;
    @Mock
    private AiBomAffectedResourceSummaryService affectedResourceSummaryService;

    @Test
    void historicalRuntimeFindingDoesNotResolveThroughCustomerDetailLookup() {
        Tenant tenant = new Tenant();
        UUID id = UUID.randomUUID();
        Finding runtime = new Finding();
        runtime.setFindingKind("AI_RUNTIME");
        when(findingRepository.findAllById(List.of(id))).thenReturn(List.of(runtime));
        doAnswer(call -> call.getArgument(1, java.util.function.Supplier.class).get())
                .when(tenantSchemaExecutionService).run(any(Tenant.class),
                        org.mockito.ArgumentMatchers.<java.util.function.Supplier<Object>>any());
        FindingQueryService service = new FindingQueryService(findingRepository, new ObjectMapper(),
                findingsScoreService, riskPolicyService, tenantSchemaExecutionService,
                findingListProjectionService, affectedResourceSummaryService);
        assertTrue(service.listEntitiesByTenantAndIds(tenant, List.of(id)).isEmpty());
    }

    @Test
    void listAvailableFiltersNormalizesRepositoryValuesAndAppliesPreferredOrdering() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        when(findingRepository.findDistinctSeveritiesByTenant(tenant)).thenReturn(List.of("medium", "critical"));
        when(findingRepository.findDistinctStatusesByTenant(tenant)).thenReturn(List.of(FindingStatus.RESOLVED, FindingStatus.OPEN));
        when(findingRepository.findDistinctDecisionStatesByTenant(tenant)).thenReturn(List.of(
                FindingDecisionState.UNDER_INVESTIGATION,
                FindingDecisionState.AFFECTED
        ));
        when(findingRepository.findDistinctMatchMethodsByTenant(tenant)).thenReturn(List.of("CPE", "package"));
        when(findingRepository.findDistinctVexStatusesByTenant(tenant)).thenReturn(List.of("not_affected"));
        when(findingRepository.findDistinctVexFreshnessByTenant(tenant)).thenReturn(List.of("stale"));
        when(findingRepository.findDistinctVexProvidersByTenant(tenant)).thenReturn(List.of("microsoft"));
        doAnswer(invocation -> invocation.getArgument(1, java.util.function.Supplier.class).get())
                .when(tenantSchemaExecutionService)
                .run(any(Tenant.class), org.mockito.ArgumentMatchers.<java.util.function.Supplier<Object>>any());

        FindingQueryService service = new FindingQueryService(
                findingRepository, new ObjectMapper(), findingsScoreService, riskPolicyService, tenantSchemaExecutionService, findingListProjectionService, affectedResourceSummaryService);

        FindingFilterValuesResponse filters = service.listAvailableFilters(tenant);

        assertEquals(List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"), filters.severities());
        assertEquals(List.of("OPEN", "RESOLVED", "SUPPRESSED", "AUTO_CLOSED"), filters.statuses());
        assertEquals(
                List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "UNDER_INVESTIGATION", "NEEDS_REVIEW"),
                filters.decisionStates()
        );
        assertEquals(List.of("cpe", "package"), filters.matchMethods());
        assertEquals(
                List.of("AFFECTED", "NOT_AFFECTED", "FIXED", "NO_PATCH", "UNDER_INVESTIGATION", "UNKNOWN"),
                filters.vexStatuses()
        );
        assertEquals(List.of("FRESH", "STALE", "UNKNOWN"), filters.vexFreshness());
        assertTrue(filters.vexProviders().contains("microsoft"));
        assertTrue(filters.vexProviders().contains("unknown"));
    }

    @Test
    void toResponseDoesNotFailWhenLegacyFindingAssociationsAreMissing() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());

        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId("CVE-2026-1234");
        vulnerability.setSeverity("HIGH");

        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setVulnerability(vulnerability);
        finding.setRiskScore(8.4);
        finding.setConfidenceScore(0.72);
        finding.setMatchedBy("package");
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        finding.setEvidence("{\"impactReason\":\"reachable\"}");

        when(riskPolicyService.getFindingsScoreConfig(tenant)).thenReturn("{}");
        when(findingsScoreService.compute("{}", finding)).thenThrow(new NullPointerException("missing relations"));

        FindingQueryService service = new FindingQueryService(
                findingRepository, new ObjectMapper(), findingsScoreService, riskPolicyService, tenantSchemaExecutionService, findingListProjectionService, affectedResourceSummaryService);

        FindingResponse response = service.toResponse(finding);

        assertEquals("CVE-2026-1234", response.vulnerabilityId());
        assertEquals("HIGH", response.severity());
        assertEquals(8.4, response.riskScore());
        assertEquals(8.4, response.findingsScore());
        assertEquals("reachable", response.impactReason());
        assertNull(response.componentId());
        assertNull(response.assetName());
        assertNull(response.assetType());
        assertNull(response.source());
    }

    @Test
    void canonicalOwnershipMapFillsTheExistingDisplayKeysFromTheEffectiveAssignment() {
        UUID team = UUID.randomUUID();
        UUID subject = UUID.randomUUID();
        com.prototype.vulnwatch.domain.Asset asset = new com.prototype.vulnwatch.domain.Asset();
        asset.setOwnerTeam("Legacy Ops");
        asset.setSupportGroup("SN-NET-OPS");
        var owned = new com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary(UUID.randomUUID(), "CORE", "CANONICAL",
                subject, team, "Payments", "OWNED", subject, UUID.randomUUID(), "SERVICENOW", java.time.Instant.EPOCH, false, 0, null);

        var map = FindingQueryService.canonicalOwnershipMap(owned, asset);
        assertEquals("Payments", map.get("displayName"));
        assertEquals("Payments", map.get("ownerTeam"));
        assertEquals(team.toString(), map.get("ownerTeamId"));
        assertEquals("OWNED", map.get("ownershipStatus"));
        assertEquals("CANONICAL", map.get("authorityState"));
        assertEquals("SERVICENOW", map.get("sourceSystem"));
        // The raw CMDB support group stays visible as evidence, but the legacy owner_team label is gone.
        assertEquals("SN-NET-OPS", map.get("supportGroup"));
        assertTrue(map.values().stream().noneMatch("Legacy Ops"::equals));

        var conflict = new com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary(UUID.randomUUID(), "CORE", "CANONICAL",
                subject, null, null, "CONFLICT", subject, UUID.randomUUID(), "SERVICENOW", null, null, 0, null);
        assertEquals("Ownership conflict", FindingQueryService.canonicalOwnershipMap(conflict, null).get("displayName"));
        assertNull(FindingQueryService.canonicalOwnershipMap(conflict, null).get("ownerTeam"));

        var unlinked = new com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary(UUID.randomUUID(), "CORE", "CANONICAL",
                null, null, null, "UNOWNED", null, null, null, null, null, null, null);
        assertEquals("Unowned", FindingQueryService.canonicalOwnershipMap(unlinked, null).get("displayName"));
    }

    @Test
    void legacyOwnershipMapKeepsThePreCutoverDisplayAndMarksItPendingMigration() {
        com.prototype.vulnwatch.domain.Asset asset = new com.prototype.vulnwatch.domain.Asset();
        asset.setOwnerEmail("owner@example.test");
        var map = FindingQueryService.legacyOwnershipMap(asset);
        assertEquals("owner@example.test", map.get("displayName"));
        assertEquals("", map.get("supportGroup"));
        assertEquals("LEGACY_PENDING_MIGRATION", map.get("authorityState"));
        assertEquals("Unassigned", FindingQueryService.legacyOwnershipMap(null).get("displayName"));
    }
}
