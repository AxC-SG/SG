package com.prototype.vulnwatch.service.cbom;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.BomEvidenceState;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.CbomFindingStatus;
import com.prototype.vulnwatch.domain.CbomRiskFinding;
import com.prototype.vulnwatch.domain.CbomRiskSeverity;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.CbomRiskFindingRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.service.CanonicalSuppressionMutationService;
import com.prototype.vulnwatch.service.FindingListProjectionService;
import com.prototype.vulnwatch.service.FindingSlaService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.RiskPolicyService;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CbomFindingMirrorSuppressionPolicyTest {
    @Mock CbomRiskFindingRepository cbomFindings;
    @Mock FindingRepository findings;
    @Mock FindingWorkflowService workflow;
    @Mock FindingSlaService sla;
    @Mock RiskPolicyService policies;
    @Mock FindingListProjectionService projections;
    @Mock CanonicalSuppressionMutationService mutations;
    private CbomFindingMirrorService mirror;
    private Tenant tenant;
    private CbomRiskFinding source;
    private Finding canonical;

    @BeforeEach
    void setUp() {
        mirror = new CbomFindingMirrorService(cbomFindings, findings, workflow, sla, policies,
                projections, new ObjectMapper(), mutations);
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        CbomComponent component = org.mockito.Mockito.mock(CbomComponent.class);
        when(component.isActive()).thenReturn(true);
        when(component.getId()).thenReturn(UUID.randomUUID());
        when(component.getName()).thenReturn("TLS endpoint");
        source = org.mockito.Mockito.mock(CbomRiskFinding.class);
        when(source.getId()).thenReturn(UUID.randomUUID());
        when(source.getComponent()).thenReturn(component);
        when(source.getStatus()).thenReturn(CbomFindingStatus.OPEN);
        when(source.getEvidenceState()).thenReturn(BomEvidenceState.SUPPORTED);
        when(source.getTitle()).thenReturn("Weak cryptography");
        when(source.getLastSeenAt()).thenReturn(Instant.parse("2026-11-02T00:00:00Z"));
        canonical = new Finding();
        canonical.setTenant(tenant);
        canonical.setFindingKind("CRYPTO");
        canonical.setFingerprint("cbom:" + source.getId());
        canonical.setStatus(FindingStatus.SUPPRESSED);
        canonical.setSuppressedUntil(Instant.parse("2026-12-01T00:00:00Z"));
        canonical.setSeverityOverride("CRITICAL");
        when(cbomFindings.findByTenant_Id(tenant.getId())).thenReturn(List.of(source));
        when(findings.findByFingerprint(any())).thenReturn(Optional.of(canonical));
    }

    @Test
    void criticalToHighToCriticalReopensOnlyOnTheRiseBackToCritical() {
        AtomicReference<CbomRiskSeverity> severity = new AtomicReference<>(CbomRiskSeverity.HIGH);
        when(source.getSeverity()).thenAnswer(ignored -> severity.get());

        mirror.syncTenant(tenant);
        verify(mutations, never()).reopen(any(), any(), any(), any());

        severity.set(CbomRiskSeverity.CRITICAL);
        mirror.syncTenant(tenant);
        verify(mutations).reopen(eq(canonical), eq("cbom-delta"),
                eq("SUPPRESSION_REOPENED_SEVERITY_ESCALATION"), any());
    }
}
