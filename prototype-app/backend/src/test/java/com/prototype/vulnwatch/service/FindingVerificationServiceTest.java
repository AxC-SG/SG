package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.dto.FindingVerificationRequest;
import com.prototype.vulnwatch.repo.FindingRepository;
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
class FindingVerificationServiceTest {
    @Mock FindingRepository findings;
    @Mock FindingWorkflowService workflow;
    @Mock RequestActorService actors;
    @Mock AuditEventService audit;
    FindingVerificationService service;
    Finding finding;

    @BeforeEach
    void setUp() {
        service = new FindingVerificationService(findings, workflow, actors, audit);
        finding = new Finding();
        ReflectionTestUtils.setField(finding, "id", UUID.randomUUID());
        finding.setFindingKind("CRYPTO");
        finding.setStatus(FindingStatus.OPEN);
        when(actors.currentActor()).thenReturn(new RequestActor("analyst", false, UUID.randomUUID(), "Tenant",
                Set.of("SECURITY_ANALYST"), TenantAccessMode.TENANT_MEMBERSHIP, null, null));
        org.mockito.Mockito.lenient().when(findings.findById(finding.getId())).thenReturn(Optional.of(finding));
        org.mockito.Mockito.lenient().when(findings.save(any())).thenAnswer(call -> call.getArgument(0));
    }

    @Test
    void requestsAndAcceptsVerificationThroughCanonicalFinding() {
        var requested = service.update(finding.getId(),
                new FindingVerificationRequest("REQUEST", "TLS 1.3 with approved cipher suites", null, null));
        UUID runId = UUID.randomUUID();
        var accepted = service.update(finding.getId(),
                new FindingVerificationRequest("ACCEPT", null, "Assessment confirms target state", runId));

        assertThat(requested.verificationStatus()).isEqualTo("REQUESTED");
        assertThat(accepted.verificationStatus()).isEqualTo("ACCEPTED");
        verify(workflow).resolveByVerifiedReassessment(finding, runId, finding.getVerificationCompletedAt(), runId);
    }

    @Test
    void rejectsAcceptanceWithoutAssessmentProvenance() {
        service.update(finding.getId(), new FindingVerificationRequest("REQUEST", "PQC-ready key", null, null));

        assertThatThrownBy(() -> service.update(finding.getId(),
                new FindingVerificationRequest("ACCEPT", null, "looks fixed", null)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("assessmentRunId");
        assertThat(finding.getVerificationStatus()).isEqualTo("REQUESTED");
    }

    @Test
    void excludesSupportSessionActors() {
        when(actors.currentActor()).thenReturn(new RequestActor("support", false, finding.getId(), "Tenant",
                Set.of("PLATFORM_OWNER"), TenantAccessMode.SUPPORT_WRITE_ENABLED, UUID.randomUUID(), null));

        assertThatThrownBy(() -> service.update(finding.getId(),
                new FindingVerificationRequest("REQUEST", "target", null, null)))
                .isInstanceOf(SecurityException.class);
    }
}
