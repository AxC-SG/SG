package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingEvent;
import com.prototype.vulnwatch.domain.FindingSuppressionRequest;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingSuppressionDecisionRequest;
import com.prototype.vulnwatch.repo.CbomTenantSettingsRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.FindingSuppressionRequestRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class FindingSuppressionRequestServiceTest {
    @Mock FindingRepository findings;
    @Mock FindingSuppressionRequestRepository requests;
    @Mock CbomTenantSettingsRepository settings;
    @Mock CryptoSuppressionPolicyGuard guard;
    @Mock CanonicalSuppressionMutationService mutations;
    @Mock RequestActorService actors;
    @Mock AuditEventService audit;
    @Mock TenantWorkRunner tenantWorkRunner;
    @Mock TenantMembershipRepository memberships;
    private FindingSuppressionRequestService service;
    private Tenant tenant;
    private Finding finding;
    private RequestActor approver;

    @BeforeEach
    void setUp() {
        service = new FindingSuppressionRequestService(findings, requests, settings, guard, mutations,
                actors, audit, tenantWorkRunner, memberships);
        tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        finding = new Finding();
        ReflectionTestUtils.setField(finding, "id", UUID.randomUUID());
        finding.setTenant(tenant);
        finding.setFindingKind("CRYPTO");
        finding.setStatus(FindingStatus.OPEN);
        finding.setSeverityOverride("CRITICAL");
        approver = new RequestActor("admin-2", false, tenant.getId(), "tenant", Set.of("TENANT_ADMIN"),
                TenantAccessMode.TENANT_MEMBERSHIP, null, null);
        when(actors.currentActor()).thenReturn(approver);
        when(settings.findById(tenant.getId())).thenReturn(Optional.empty());
        when(guard.canonicalSeverity(finding)).thenReturn("CRITICAL");
    }

    @Test
    void criticalRequesterCannotApproveOwnRequest() {
        FindingSuppressionRequest request = pending("admin-2");
        when(requests.findByIdAndTenant_Id(request.getId(), tenant.getId())).thenReturn(Optional.of(request));

        CryptoSuppressionPolicyException error = assertThrows(CryptoSuppressionPolicyException.class,
                () -> service.decide(request.getId(), new FindingSuppressionDecisionRequest("APPROVE", "ok")));

        assertEquals("DISTINCT_APPROVER_REQUIRED", error.getReasonCode());
        verify(mutations, never()).suppress(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void singleAdminTenantMustRemediateCriticalFinding() {
        FindingSuppressionRequest request = pending("analyst-1");
        when(requests.findByIdAndTenant_Id(request.getId(), tenant.getId())).thenReturn(Optional.of(request));
        when(memberships.countByTenantIdAndRoleAndStatus(tenant.getId(), "TENANT_ADMIN", "ACTIVE"))
                .thenReturn(1L);

        CryptoSuppressionPolicyException error = assertThrows(CryptoSuppressionPolicyException.class,
                () -> service.decide(request.getId(), new FindingSuppressionDecisionRequest("APPROVE", "ok")));

        assertEquals("CRITICAL_REMEDIATION_REQUIRED", error.getReasonCode());
        verify(mutations, never()).suppress(any(), any(), any(), any(), any(), any(), any());
    }

    @Test
    void twoAdminTenantCanApproveCriticalRequestFromDifferentActor() {
        FindingSuppressionRequest request = pending("admin-1");
        when(requests.findByIdAndTenant_Id(request.getId(), tenant.getId())).thenReturn(Optional.of(request));
        when(memberships.countByTenantIdAndRoleAndStatus(tenant.getId(), "TENANT_ADMIN", "ACTIVE"))
                .thenReturn(2L);
        FindingEvent event = new FindingEvent();
        UUID eventId = UUID.randomUUID();
        ReflectionTestUtils.setField(event, "id", eventId);
        when(mutations.suppress(any(), any(), any(), any(), any(), any(), any())).thenReturn(event);
        when(requests.save(request)).thenReturn(request);

        var response = service.decide(request.getId(), new FindingSuppressionDecisionRequest("APPROVE", "reviewed"));

        assertEquals("APPROVED", response.status());
        assertEquals(eventId, response.appliedEventId());
        verify(mutations).suppress(finding, "temporary exception", request.getProposedSuppressedUntil(), null, null,
                SuppressionMutationSource.APPROVED_REQUEST, "admin-2");
    }

    private FindingSuppressionRequest pending(String requestedBy) {
        FindingSuppressionRequest request = new FindingSuppressionRequest();
        request.setTenant(tenant);
        request.setFinding(finding);
        request.setFindingKind("CRYPTO");
        request.setSeverityAtRequest("CRITICAL");
        request.setRequestedBy(requestedBy);
        request.setRequestedAt(Instant.now().minusSeconds(60));
        request.setDecisionDueAt(Instant.now().plusSeconds(3600));
        request.setReason("temporary exception");
        request.setCompensatingControl("isolated network");
        request.setProposedSuppressedUntil(Instant.now().plusSeconds(86400));
        return request;
    }
}
