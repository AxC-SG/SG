package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.dto.FindingVerificationRequest;
import com.prototype.vulnwatch.dto.FindingVerificationResponse;
import com.prototype.vulnwatch.repo.FindingRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingVerificationService {
    private static final String CRYPTO = "CRYPTO";
    private final FindingRepository findings;
    private final FindingWorkflowService workflow;
    private final RequestActorService actors;
    private final AuditEventService audit;

    public FindingVerificationService(FindingRepository findings, FindingWorkflowService workflow,
                                      RequestActorService actors, AuditEventService audit) {
        this.findings = findings;
        this.workflow = workflow;
        this.actors = actors;
        this.audit = audit;
    }

    @Transactional
    public FindingVerificationResponse update(UUID findingId, FindingVerificationRequest request) {
        RequestActor actor = actors.currentActor();
        if (!actor.hasDirectTenantMembership()) {
            throw new SecurityException("Verification requires direct tenant membership");
        }
        Finding finding = findings.findById(findingId)
                .orElseThrow(() -> new EntityNotFoundException("Finding not found: " + findingId));
        if (!CRYPTO.equals(finding.getFindingKind())) {
            throw new IllegalArgumentException("Crypto verification is only available for CRYPTO findings");
        }
        String action = request.action().trim().toUpperCase();
        if ("REQUEST".equals(action)) {
            requestVerification(finding, request, actor.userId());
        } else if ("ACCEPT".equals(action) || "REJECT".equals(action)) {
            completeVerification(finding, request, actor.userId(), "ACCEPT".equals(action));
        } else {
            throw new IllegalArgumentException("action must be REQUEST, ACCEPT, or REJECT");
        }
        finding.touch();
        findings.save(finding);
        audit.record("finding.verification." + action.toLowerCase(), "finding", findingId.toString(),
                "{\"verificationStatus\":\"" + finding.getVerificationStatus() + "\"}");
        return response(finding);
    }

    private void requestVerification(Finding finding, FindingVerificationRequest request, String actor) {
        if (finding.getStatus() == FindingStatus.RESOLVED || finding.getStatus() == FindingStatus.AUTO_CLOSED) {
            throw new IllegalStateException("Closed findings cannot request verification");
        }
        String target = required(request.targetState(), "targetState is required");
        finding.setWorkflowSubstate("VERIFICATION_REQUESTED");
        finding.setTargetState(target);
        finding.setVerificationRequired(true);
        finding.setVerificationStatus("REQUESTED");
        finding.setVerificationEvidence(null);
        finding.setVerificationRequestedAt(Instant.now());
        finding.setVerificationCompletedAt(null);
        finding.setVerificationActor(actor);
        workflow.appendEvent(finding, "VERIFICATION_REQUESTED", actor,
                "Cryptographic remediation verification requested", Map.of("targetState", target));
    }

    private void completeVerification(Finding finding, FindingVerificationRequest request, String actor,
                                      boolean accepted) {
        if (!"REQUESTED".equals(finding.getVerificationStatus())) {
            throw new IllegalStateException("Finding has no pending verification request");
        }
        String evidence = required(request.evidence(), "evidence is required");
        if (accepted && request.assessmentRunId() == null) {
            throw new IllegalArgumentException("assessmentRunId is required when accepting verification");
        }
        Instant now = Instant.now();
        finding.setVerificationEvidence(evidence);
        finding.setVerificationCompletedAt(now);
        finding.setVerificationActor(actor);
        finding.setVerificationStatus(accepted ? "ACCEPTED" : "REJECTED");
        finding.setWorkflowSubstate(accepted ? "VERIFIED" : "REMEDIATION_IN_PROGRESS");
        workflow.appendEvent(finding, accepted ? "VERIFICATION_ACCEPTED" : "VERIFICATION_REJECTED", actor,
                accepted ? "Verification evidence accepted" : "Verification evidence rejected",
                Map.of("assessmentRunId", String.valueOf(request.assessmentRunId())));
        if (accepted) {
            workflow.resolveByVerifiedReassessment(finding, request.assessmentRunId(), now, request.assessmentRunId());
        }
    }

    private String required(String value, String message) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException(message);
        return value.trim();
    }

    private FindingVerificationResponse response(Finding finding) {
        return new FindingVerificationResponse(finding.getId(), finding.getWorkflowSubstate(), finding.getTargetState(),
                finding.isVerificationRequired(), finding.getVerificationStatus(), finding.getVerificationEvidence(),
                finding.getVerificationRequestedAt(), finding.getVerificationCompletedAt(), finding.getVerificationActor());
    }
}
