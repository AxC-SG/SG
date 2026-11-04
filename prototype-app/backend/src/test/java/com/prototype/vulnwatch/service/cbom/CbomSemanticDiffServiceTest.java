package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.BomEvidenceState;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.CbomAssetType;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.CbomFindingStatus;
import com.prototype.vulnwatch.domain.CbomRiskFinding;
import com.prototype.vulnwatch.domain.CbomRiskSeverity;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.CbomComponentRepository;
import com.prototype.vulnwatch.repo.CbomRiskFindingRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowCallbackHandler;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class CbomSemanticDiffServiceTest {
    @Mock BomIngestionRecordRepository boms;
    @Mock CbomComponentRepository components;
    @Mock CbomRiskFindingRepository findings;
    @Mock JdbcTemplate jdbc;
    Tenant tenant;
    UUID before = UUID.randomUUID();
    UUID after = UUID.randomUUID();
    CbomSemanticDiffService service;

    @BeforeEach
    void setUp() {
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        when(boms.findById(after)).thenReturn(Optional.of(bom(after, before)));
        when(boms.findById(before)).thenReturn(Optional.of(bom(before, null)));
        org.mockito.Mockito.lenient().doAnswer(inv -> null).when(jdbc).query(anyString(), any(RowCallbackHandler.class), any(Object[].class));
        service = new CbomSemanticDiffService(boms, components, findings, jdbc);
    }

    @Test
    void reportsDuplicateIdentitiesAsAmbiguousInsteadOfGuessing() {
        CbomComponent priorKey = component("key", "ref-key", 2048);
        CbomComponent duplicateA = component("key", "ref-key", 3072);
        CbomComponent duplicateB = component("key", "ref-key", 4096);
        when(components.findByTenant_IdAndSourceBom_IdOrderByNameAsc(tenant.getId(), before)).thenReturn(List.of(priorKey));
        when(components.findByTenant_IdAndSourceBom_IdOrderByNameAsc(tenant.getId(), after)).thenReturn(List.of(duplicateA, duplicateB));
        when(findings.findBySourceBomId(before)).thenReturn(List.of(finding(priorKey, "CBOM-RSA-SMALL-KEY", BomEvidenceState.SUPPORTED)));
        when(findings.findBySourceBomId(after)).thenReturn(List.of());

        var diff = service.diff(tenant, after, null);

        assertThat(diff.ambiguous()).singleElement().satisfies(a -> {
            assertThat(a.identity()).isEqualTo("bom-ref:ref-key");
            assertThat(a.baselineMatches()).isEqualTo(1);
            assertThat(a.currentMatches()).isEqualTo(2);
        });
        assertThat(diff.componentChanges()).isEmpty();
        assertThat(diff.findingSummary()).containsOnlyKeys("AMBIGUOUS");
    }

    @Test
    void distinguishesRemediationWithdrawalAndNaturalIdentityMatching() {
        CbomComponent priorRsa = component("rsa signer", null, 1024);
        CbomComponent nextRsa = component("RSA Signer", null, 3072);
        CbomComponent priorCert = component("edge cert", "cert", null);
        CbomComponent nextCert = component("edge cert", "cert", null);
        when(components.findByTenant_IdAndSourceBom_IdOrderByNameAsc(tenant.getId(), before)).thenReturn(List.of(priorRsa, priorCert));
        when(components.findByTenant_IdAndSourceBom_IdOrderByNameAsc(tenant.getId(), after)).thenReturn(List.of(nextRsa, nextCert));
        when(findings.findBySourceBomId(before)).thenReturn(List.of(
                finding(priorRsa, "CBOM-RSA-SMALL-KEY", BomEvidenceState.SUPPORTED),
                finding(priorCert, "CBOM-CERT-EXPIRING", BomEvidenceState.SUPPORTED)));
        when(findings.findBySourceBomId(after)).thenReturn(List.of(finding(nextCert, "CBOM-CERT-EXPIRING", BomEvidenceState.WITHDRAWN)));

        var diff = service.diff(tenant, after, null);

        assertThat(diff.findingSummary()).containsEntry("REMEDIATED", 1).containsEntry("WITHDRAWN", 1);
        assertThat(diff.componentChanges()).singleElement().satisfies(change -> {
            assertThat(change.changeType()).isEqualTo("CHANGED");
            assertThat(change.fields()).extracting(CbomSemanticDiffService.FieldChange::field).containsExactly("keySize");
        });
    }

    private BomIngestionRecord bom(UUID id, UUID previous) {
        BomIngestionRecord bom = new BomIngestionRecord();
        ReflectionTestUtils.setField(bom, "id", id);
        bom.setTenant(tenant);
        bom.setBomType(BomType.CBOM);
        bom.setStatus(BomStatus.ACTIVE);
        bom.setPreviousBomId(previous);
        return bom;
    }

    private CbomComponent component(String name, String bomRef, Integer keySize) {
        CbomComponent c = new CbomComponent();
        ReflectionTestUtils.setField(c, "id", UUID.randomUUID());
        c.setName(name);
        c.setBomRef(bomRef);
        c.setAssetType(CbomAssetType.ALGORITHM);
        c.setPrimitive("rsa");
        c.setKeySize(keySize);
        return c;
    }

    private CbomRiskFinding finding(CbomComponent component, String ruleId, BomEvidenceState evidence) {
        CbomRiskFinding f = new CbomRiskFinding();
        ReflectionTestUtils.setField(f, "id", UUID.randomUUID());
        f.setComponent(component);
        f.setRuleId(ruleId);
        f.setTitle(ruleId);
        f.setSeverity(CbomRiskSeverity.HIGH);
        f.setStatus(CbomFindingStatus.OPEN);
        f.setEvidenceState(evidence);
        return f;
    }
}
