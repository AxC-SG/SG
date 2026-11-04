package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.repo.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CbomAssessmentServiceTest {
    @Mock BomIngestionRecordRepository boms; @Mock CbomComponentRepository components;
    @Mock CbomRiskFindingRepository findings; @Mock CbomAssessmentRunRepository runs;
    @Mock CbomValidationIssueRepository issues; @Mock CbomClaimAssuranceRepository assurances;
    @Mock CbomRulePackageService packages;

    @Test void persistsReproducibleProvenanceAndTreatsMissingEvidenceAsUnknownNotFailure(){
        Tenant tenant=new Tenant();UUID tenantId=UUID.randomUUID();tenant.setId(tenantId);
        BomIngestionRecord bom=new BomIngestionRecord();bom.setTenant(tenant);bom.setBomType(BomType.CBOM);bom.setChecksumSha256("sha256:artifact");
        org.springframework.test.util.ReflectionTestUtils.setField(bom,"id",UUID.randomUUID());
        CbomComponent component=new CbomComponent();component.setTenant(tenant);component.setSourceBom(bom);component.setAssetType(CbomAssetType.ALGORITHM);component.setName("Unspecified algorithm");
        org.springframework.test.util.ReflectionTestUtils.setField(component,"id",UUID.randomUUID());
        when(boms.findById(bom.getId())).thenReturn(Optional.of(bom));
        when(packages.effective(tenant)).thenReturn(new CbomRulePackageService.EffectivePackage("scoutgrid-baseline","1.0.0","sha256:rules","1.0","{}"));
        when(runs.findFirstByBom_IdAndRulePackageDigestAndEvaluatorVersionAndStatusOrderByCreatedAtDesc(any(),any(),any(),any())).thenReturn(Optional.empty());
        when(runs.save(any())).thenAnswer(call->call.getArgument(0));
        when(components.findByTenant_IdAndSourceBom_IdAndActiveTrueOrderByRiskScoreDescNameAsc(tenantId,bom.getId())).thenReturn(List.of(component));
        when(findings.findIdsBySourceBomId(bom.getId())).thenReturn(List.of());

        CbomAssessmentService service=new CbomAssessmentService(boms,components,findings,runs,issues,assurances,packages);
        var response=service.assess(tenant,bom.getId());

        assertThat(response.status()).isEqualTo("SUCCEEDED");
        assertThat(response.artifactChecksum()).isEqualTo("sha256:artifact");
        assertThat(response.rulePackageDigest()).isEqualTo("sha256:rules");
        assertThat(response.validationOutcome()).isEqualTo("VALID");
        assertThat(response.completenessScore()).isEqualByComparingTo("0.50000");
        @SuppressWarnings("unchecked") ArgumentCaptor<List<CbomClaimAssurance>> claims=ArgumentCaptor.forClass(List.class);
        verify(assurances).saveAllAndFlush(claims.capture());
        assertThat(claims.getValue()).extracting(CbomClaimAssurance::getAssuranceLevel).containsExactly("DECLARED","UNKNOWN");
    }

    @Test void assessmentPublishesCbomDeltasForTheArtifactFindingsWithoutATenantScan(){
        Tenant tenant=new Tenant();UUID tenantId=UUID.randomUUID();tenant.setId(tenantId);
        BomIngestionRecord bom=new BomIngestionRecord();bom.setTenant(tenant);bom.setBomType(BomType.CBOM);
        org.springframework.test.util.ReflectionTestUtils.setField(bom,"id",UUID.randomUUID());
        when(boms.findById(bom.getId())).thenReturn(Optional.of(bom));
        when(packages.effective(tenant)).thenReturn(new CbomRulePackageService.EffectivePackage("scoutgrid-baseline","1.0.0","sha256:rules","1.0","{}"));
        when(runs.findFirstByBom_IdAndRulePackageDigestAndEvaluatorVersionAndStatusOrderByCreatedAtDesc(any(),any(),any(),any())).thenReturn(Optional.empty());
        when(runs.save(any())).thenAnswer(call->call.getArgument(0));
        UUID findingId=UUID.randomUUID();
        when(findings.findIdsBySourceBomId(bom.getId())).thenReturn(List.of(findingId));
        CbomFindingMirrorService mirror=org.mockito.Mockito.mock(CbomFindingMirrorService.class);
        com.prototype.vulnwatch.service.FindingDeltaQueueService queue=org.mockito.Mockito.mock(com.prototype.vulnwatch.service.FindingDeltaQueueService.class);

        CbomAssessmentService service=new CbomAssessmentService(boms,components,findings,runs,issues,assurances,packages);
        service.setMirror(mirror);service.setDeltaQueue(queue);
        var response=service.assess(tenant,bom.getId());

        assertThat(response.findingCount()).isEqualTo(1);
        org.mockito.Mockito.verify(queue).enqueueCbomDeltas(tenantId,List.of(findingId),"cbom-assessment");
        org.mockito.Mockito.verify(mirror,org.mockito.Mockito.never()).syncTenant(any());
    }
}
