package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.CbomTenantSettings;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingEvent;
import com.prototype.vulnwatch.domain.FindingSuppressionRequest;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.dto.FindingSuppressionDecisionRequest;
import com.prototype.vulnwatch.dto.FindingSuppressionRequestCreate;
import com.prototype.vulnwatch.dto.FindingSuppressionResponse;
import com.prototype.vulnwatch.repo.CbomTenantSettingsRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.FindingSuppressionRequestRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.List;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class FindingSuppressionRequestService {
    private final FindingRepository findingRepository;
    private final FindingSuppressionRequestRepository requestRepository;
    private final CbomTenantSettingsRepository settingsRepository;
    private final CryptoSuppressionPolicyGuard policyGuard;
    private final CanonicalSuppressionMutationService mutationService;
    private final RequestActorService actorService;
    private final AuditEventService auditEventService;
    private final TenantWorkRunner tenantWorkRunner;
    private final TenantMembershipRepository membershipRepository;

    public FindingSuppressionRequestService(
            FindingRepository findingRepository,
            FindingSuppressionRequestRepository requestRepository,
            CbomTenantSettingsRepository settingsRepository,
            CryptoSuppressionPolicyGuard policyGuard,
            CanonicalSuppressionMutationService mutationService,
            RequestActorService actorService,
            AuditEventService auditEventService,
            TenantWorkRunner tenantWorkRunner,
            TenantMembershipRepository membershipRepository
    ) {
        this.findingRepository = findingRepository;
        this.requestRepository = requestRepository;
        this.settingsRepository = settingsRepository;
        this.policyGuard = policyGuard;
        this.mutationService = mutationService;
        this.actorService = actorService;
        this.auditEventService = auditEventService;
        this.tenantWorkRunner = tenantWorkRunner;
        this.membershipRepository = membershipRepository;
    }

    @Transactional
    public FindingSuppressionResponse create(UUID findingId, FindingSuppressionRequestCreate input) {
        Finding finding = finding(findingId);
        RequestActor actor = requireDirectMember();
        if (!policyGuard.isCrypto(finding)) {
            throw new IllegalArgumentException("Suppression requests are only required for CRYPTO findings");
        }
        if (requestRepository.findByFinding_IdAndStatus(findingId, "REQUESTED").isPresent()) {
            throw new IllegalStateException("An active suppression request already exists");
        }
        policyGuard.check(finding, input.proposedSuppressedUntil(), SuppressionMutationSource.APPROVED_REQUEST);
        CbomTenantSettings settings = settingsRepository.findById(finding.getTenant().getId()).orElse(null);
        int deadlineDays = settings == null ? 14 : settings.getSuppressionRequestDeadlineDays();
        Instant now = Instant.now();
        FindingSuppressionRequest request = new FindingSuppressionRequest();
        request.setTenant(finding.getTenant());
        request.setFinding(finding);
        request.setFindingKind(finding.getFindingKind());
        request.setSeverityAtRequest(policyGuard.canonicalSeverity(finding));
        request.setRequestedBy(actor.userId());
        request.setRequestedAt(now);
        request.setDecisionDueAt(now.plus(deadlineDays, ChronoUnit.DAYS));
        request.setReason(input.reason().trim());
        request.setCompensatingControl(input.compensatingControl().trim());
        request.setProposedSuppressedUntil(input.proposedSuppressedUntil());
        request = requestRepository.save(request);
        auditEventService.record("finding.suppression.requested", "finding", findingId.toString(),
                "{\"requestId\":\"" + request.getId() + "\"}");
        return response(request);
    }

    @Transactional(readOnly = true)
    public List<FindingSuppressionResponse> list() {
        RequestActor actor = requireDirectMember();
        return requestRepository.findByTenant_IdOrderByCreatedAtDesc(actor.tenantId()).stream()
                .map(this::response)
                .toList();
    }

    @Transactional
    public FindingSuppressionResponse decide(UUID requestId, FindingSuppressionDecisionRequest input) {
        RequestActor actor = requireTenantAdmin();
        FindingSuppressionRequest request = requestRepository.findByIdAndTenant_Id(requestId, actor.tenantId())
                .orElseThrow(() -> new EntityNotFoundException("Suppression request not found: " + requestId));
        if (!"REQUESTED".equals(request.getStatus())) {
            throw new IllegalStateException("Suppression request is no longer pending");
        }
        Instant now = Instant.now();
        if (!request.getDecisionDueAt().isAfter(now)) {
            finish(request, "EXPIRED", actor.userId(), "Decision deadline elapsed", now);
            return response(requestRepository.save(request));
        }
        CbomTenantSettings settings = settingsRepository.findById(actor.tenantId()).orElse(null);
        if (settings != null && settings.isRequireDistinctSuppressionApprover()
                && request.getRequestedBy().equals(actor.userId())) {
            throw new CryptoSuppressionPolicyException("DISTINCT_APPROVER_REQUIRED",
                    "The requester cannot approve this tenant's suppression request");
        }
        String decision = input.decision().trim().toUpperCase();
        if ("APPROVE".equals(decision) || "APPROVED".equals(decision)) {
            if (request.getFinding().getStatus() == FindingStatus.RESOLVED
                    || request.getFinding().getStatus() == FindingStatus.AUTO_CLOSED) {
                finish(request, "CANCELLED", actor.userId(), "Finding was already resolved", now);
            } else {
                enforceCriticalMakerChecker(request, actor);
                policyGuard.check(request.getFinding(), request.getProposedSuppressedUntil(),
                        SuppressionMutationSource.APPROVED_REQUEST);
                FindingEvent event = mutationService.suppress(request.getFinding(), request.getReason(),
                        request.getProposedSuppressedUntil(), null, null,
                        SuppressionMutationSource.APPROVED_REQUEST, actor.userId());
                finish(request, "APPROVED", actor.userId(), input.reason(), now);
                request.setAppliedEventId(event.getId());
            }
        } else if ("REJECT".equals(decision) || "REJECTED".equals(decision)) {
            finish(request, "REJECTED", actor.userId(), input.reason(), now);
        } else {
            throw new IllegalArgumentException("decision must be APPROVE or REJECT");
        }
        request = requestRepository.save(request);
        auditEventService.record("finding.suppression." + request.getStatus().toLowerCase(), "finding",
                request.getFinding().getId().toString(), "{\"requestId\":\"" + request.getId() + "\"}");
        return response(request);
    }

    private void enforceCriticalMakerChecker(FindingSuppressionRequest request, RequestActor approver) {
        String severity = policyGuard.canonicalSeverity(request.getFinding());
        if (!"CRITICAL".equals(severity) && !"UNKNOWN".equals(severity)) return;
        if (request.getRequestedBy().equals(approver.userId())) {
            throw new CryptoSuppressionPolicyException("DISTINCT_APPROVER_REQUIRED",
                    "Critical CRYPTO suppression must be approved by a different active tenant administrator");
        }
        long activeAdmins = membershipRepository.countByTenantIdAndRoleAndStatus(
                approver.tenantId(), "TENANT_ADMIN", "ACTIVE");
        if (activeAdmins < 2) {
            throw new CryptoSuppressionPolicyException("CRITICAL_REMEDIATION_REQUIRED",
                    "This tenant has fewer than two active administrators; critical CRYPTO findings must be remediated");
        }
    }

    @Transactional
    public void suppressDirectly(UUID findingId, FindingSuppressionRequestCreate input) {
        RequestActor actor = requireTenantAdmin();
        Finding finding = finding(findingId);
        mutationService.suppress(finding, input.reason(), input.proposedSuppressedUntil(), null, null,
                SuppressionMutationSource.DIRECT_TENANT_ADMIN, actor.userId());
    }

    @Scheduled(zone = "UTC", cron = "0 */15 * * * *")
    public void expirePendingRequests() {
        Instant now = Instant.now();
        tenantWorkRunner.forEachActiveTenant(tenant -> expireInCurrentTenant(now));
    }

    @Transactional
    public void cancelPendingForResolvedFinding(Finding finding, String reason) {
        requestRepository.findByFinding_IdAndStatus(finding.getId(), "REQUESTED").ifPresent(request -> {
            finish(request, "CANCELLED", "system", reason, Instant.now());
            requestRepository.save(request);
        });
    }

    private void expireInCurrentTenant(Instant now) {
        for (FindingSuppressionRequest request : requestRepository
                .findByStatusAndDecisionDueAtBeforeOrderById("REQUESTED", now)) {
            finish(request, "EXPIRED", "system", "Decision deadline elapsed", now);
        }
    }

    private Finding finding(UUID id) {
        return findingRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Finding not found: " + id));
    }

    private RequestActor requireDirectMember() {
        RequestActor actor = actorService.currentActor();
        if (actor == null || actor.tenantId() == null || !actor.hasDirectTenantMembership()) {
            throw new CryptoSuppressionPolicyException("DIRECT_MEMBERSHIP_REQUIRED",
                    "Support sessions and platform impersonation cannot manage suppressions");
        }
        return actor;
    }

    private RequestActor requireTenantAdmin() {
        RequestActor actor = requireDirectMember();
        if (!actor.hasRole("TENANT_ADMIN")) {
            throw new CryptoSuppressionPolicyException("TENANT_ADMIN_REQUIRED", "Tenant administrator role is required");
        }
        return actor;
    }

    private void finish(FindingSuppressionRequest request, String status, String actor, String reason, Instant now) {
        request.setStatus(status);
        request.setDecidedBy(actor);
        request.setDecidedAt(now);
        request.setDecisionReason(reason == null || reason.isBlank() ? null : reason.trim());
        request.touch();
    }

    private FindingSuppressionResponse response(FindingSuppressionRequest value) {
        return new FindingSuppressionResponse(value.getId(), value.getFinding().getId(), value.getFindingKind(),
                value.getSeverityAtRequest(), value.getRequestedBy(), value.getRequestedAt(), value.getDecisionDueAt(),
                value.getReason(), value.getCompensatingControl(), value.getProposedSuppressedUntil(), value.getStatus(),
                value.getDecidedBy(), value.getDecidedAt(), value.getDecisionReason(), value.getAppliedEventId());
    }
}
