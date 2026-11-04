package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class FindingAssetRecomputeServiceTest {

    @Mock
    private FindingRepository findingRepository;

    @Mock
    private InventoryComponentRepository inventoryComponentRepository;

    @Mock
    private CorrelationCandidateService correlationCandidateService;

    @Mock
    private RiskPolicyService riskPolicyService;

    @Mock
    private FindingsScoreService findingsScoreService;

    @Mock
    private FindingWorkflowService findingWorkflowService;

    @Mock
    private ImpactEvaluationService impactEvaluationService;

    @Mock
    private FindingEvidenceService findingEvidenceService;

    @Mock
    private PrecedenceResolverService precedenceResolverService;

    @Mock
    private OrgCveRecordService orgCveRecordService;

    @Mock
    private FindingSlaService findingSlaService;

    @Mock
    private FindingCorrelationAnalysisService findingCorrelationAnalysisService;

    @Mock
    private FindingCorrelationMutationService findingCorrelationMutationService;

    @Mock
    private FindingUpsertService findingUpsertService;

    private FindingAssetRecomputeService findingAssetRecomputeService;

    @BeforeEach
    void setUp() {
        findingAssetRecomputeService = new FindingAssetRecomputeService(
                findingRepository,
                inventoryComponentRepository,
                correlationCandidateService,
                riskPolicyService,
                findingsScoreService,
                findingWorkflowService,
                impactEvaluationService,
                findingEvidenceService,
                precedenceResolverService,
                orgCveRecordService,
                findingSlaService,
                findingCorrelationAnalysisService,
                findingCorrelationMutationService,
                findingUpsertService
        );
        findingAssetRecomputeService.setSuppressionMutations(TestSuppressionMutations.create());
    }

    @Test
    void recomputeForInactiveAssetResolvesActiveFindings() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("workspace");

        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setIdentifier("asset-1");
        asset.setState(AssetState.INACTIVE);

        Finding openFinding = new Finding();
        openFinding.setStatus(FindingStatus.OPEN);

        Finding autoClosedFinding = new Finding();
        autoClosedFinding.setStatus(FindingStatus.AUTO_CLOSED);

        List<Finding> existingFindings = new ArrayList<>(List.of(openFinding, autoClosedFinding));
        when(inventoryComponentRepository.findByAssetAndComponentStatus(asset, InventoryComponentStatus.ACTIVE))
                .thenReturn(List.of());
        when(riskPolicyService.getOrCreate(tenant)).thenReturn(new RiskPolicy());
        when(findingRepository.findByAsset(asset)).thenReturn(existingFindings);

        int active = findingAssetRecomputeService.recomputeForAsset(tenant, asset);

        assertEquals(0, active);
        assertEquals(FindingStatus.RESOLVED, openFinding.getStatus());
        assertEquals(FindingDecisionState.NOT_AFFECTED, openFinding.getDecisionState());
        assertEquals(FindingStatus.AUTO_CLOSED, autoClosedFinding.getStatus());
        verify(findingWorkflowService).appendEvent(
                eq(openFinding),
                eq("AUTO_RESOLVED_ASSET_INACTIVE"),
                eq("system"),
                eq("Finding auto-resolved because asset is not active"),
                anyMap()
        );
        verify(findingRepository).saveAll(existingFindings);
    }
}
