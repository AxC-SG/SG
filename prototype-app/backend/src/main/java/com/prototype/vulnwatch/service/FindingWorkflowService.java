package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingComment;
import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingEvent;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingCommentRequest;
import com.prototype.vulnwatch.dto.FindingCommentResponse;
import com.prototype.vulnwatch.dto.FindingEventResponse;
import com.prototype.vulnwatch.dto.FindingTimelineResponse;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingCommentRepository;
import com.prototype.vulnwatch.repo.FindingEventRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.RiskPolicyRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class FindingWorkflowService {

    private final FindingRepository findingRepository;
    private final FindingCommentRepository findingCommentRepository;
    private final FindingEventRepository findingEventRepository;
    private final RiskPolicyRepository riskPolicyRepository;
    private final AssetRepository assetRepository;
    private final ObjectMapper objectMapper;
    private final ObjectProvider<AuditEventService> auditEventServiceProvider;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final FindingListProjectionService findingListProjectionService;
    private final TenantWorkRunner tenantWorkRunner;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();
    private TransactionTemplate writeTransactionTemplate;

    public FindingWorkflowService(
            FindingRepository findingRepository,
            FindingCommentRepository findingCommentRepository,
            FindingEventRepository findingEventRepository,
            RiskPolicyRepository riskPolicyRepository,
            AssetRepository assetRepository,
            ObjectMapper objectMapper,
            ObjectProvider<AuditEventService> auditEventServiceProvider,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            FindingListProjectionService findingListProjectionService,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.findingRepository = findingRepository;
        this.findingCommentRepository = findingCommentRepository;
        this.findingEventRepository = findingEventRepository;
        this.riskPolicyRepository = riskPolicyRepository;
        this.assetRepository = assetRepository;
        this.objectMapper = objectMapper;
        this.auditEventServiceProvider = auditEventServiceProvider;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.findingListProjectionService = findingListProjectionService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager == null) {
            this.writeTransactionTemplate = null;
            return;
        }
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    @Transactional
    public Finding updateWorkflow(UUID findingId, FindingWorkflowUpdateRequest request) {
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new EntityNotFoundException("Finding not found: " + findingId));
        applyWorkflowUpdate(finding, request);
        finding.touch();
        audit("finding.workflow.updated", "finding", finding.getId().toString(), null);
        Finding saved = findingRepository.save(finding);
        findingListProjectionService.refreshTenantWithSource(saved.getTenant());
        return saved;
    }

    @Transactional
    public int updateWorkflowBulk(List<Finding> findings, FindingWorkflowUpdateRequest request) {
        int updated = 0;
        for (Finding finding : findings) {
            applyWorkflowUpdate(finding, request);
            finding.touch();
            updated += 1;
        }
        if (!findings.isEmpty()) {
            findingRepository.saveAll(findings);
            findingListProjectionService.refreshTenantWithSource(findings.get(0).getTenant());
            audit("finding.workflow.bulk_updated", "finding", null,
                    "{\"updated\":" + updated + "}");
        }
        return updated;
    }

    @Transactional
    public int updateWorkflowBulkByIds(List<UUID> findingIds, FindingWorkflowUpdateRequest request) {
        return updateWorkflowBulk(findingRepository.findAllById(findingIds), request);
    }

    @Transactional
    public int bulkDelete(List<UUID> findingIds) {
        if (findingIds == null || findingIds.isEmpty()) {
            return 0;
        }
        List<Finding> findings = findingRepository.findAllById(findingIds);
        if (findings.isEmpty()) {
            return 0;
        }
        // Delete child records first to satisfy FK constraints
        for (Finding finding : findings) {
            findingCommentRepository.deleteAll(findingCommentRepository.findByFindingOrderByCreatedAtAsc(finding));
            findingEventRepository.deleteAll(findingEventRepository.findByFindingOrderByCreatedAtAsc(finding));
        }
        findingRepository.deleteAll(findings);
        findingListProjectionService.refreshTenantWithSource(findings.get(0).getTenant());
        audit("finding.bulk_deleted", "finding", null,
                "{\"deleted\":" + findings.size() + "}");
        return findings.size();
    }

    private void applyWorkflowUpdate(Finding finding, FindingWorkflowUpdateRequest request) {
        String actor = actor(request.actor());
        Instant now = Instant.now();

        if (request.ownerGroup() != null) {
            finding.setOwnerGroup(trimToNull(request.ownerGroup()));
        }

        if (request.assignedTo() != null) {
            String previousAssignee = finding.getAssignedTo();
            finding.setAssignedTo(trimToNull(request.assignedTo()));
            finding.setAssignedBy(actor);
            finding.setAssignedAt(now);
            finding.setDueAt(request.dueAt());
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("previousAssignedTo", previousAssignee);
            details.put("assignedTo", finding.getAssignedTo());
            details.put("dueAt", finding.getDueAt());
            appendEvent(
                    finding,
                    "ASSIGNED",
                    actor,
                    "Finding assignment updated",
                    details);
        } else if (request.dueAt() != null) {
            finding.setDueAt(request.dueAt());
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("dueAt", finding.getDueAt());
            appendEvent(
                    finding,
                    "DUE_DATE_UPDATED",
                    actor,
                    "Finding due date updated",
                    details);
        }

        if (request.status() != null && !request.status().isBlank()) {
            FindingStatus nextStatus = FindingStatus.valueOf(request.status().trim().toUpperCase());
            FindingStatus previousStatus = finding.getStatus();
            finding.setStatus(nextStatus);
            if (nextStatus == FindingStatus.SUPPRESSED) {
                finding.setSuppressionReason(trimToNull(request.suppressionReason()));
                finding.setSuppressedUntil(request.suppressedUntil());
                clearClosureMetadata(finding);
            } else {
                finding.setSuppressionReason(null);
                finding.setSuppressedUntil(null);
                finding.setSuppressedByRuleId(null);
                finding.setSuppressedByRuleName(null);
                if (nextStatus == FindingStatus.OPEN) {
                    clearClosureMetadata(finding);
                } else if (nextStatus == FindingStatus.RESOLVED) {
                    applyClosureMetadata(finding, FindingCloseReason.MANUAL_FIXED, actor, null, now);
                } else if (nextStatus == FindingStatus.AUTO_CLOSED) {
                    applyClosureMetadata(finding, FindingCloseReason.MANUAL_ACCEPTED_RISK, actor, null, now);
                }
            }
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("from", previousStatus.name());
            details.put("to", nextStatus.name());
            details.put("suppressionReason", finding.getSuppressionReason());
            details.put("suppressedUntil", finding.getSuppressedUntil());
            appendEvent(
                    finding,
                    "STATUS_CHANGED",
                    actor,
                    "Finding status changed",
                    details);
        } else if (request.suppressionReason() != null || request.suppressedUntil() != null) {
            finding.setSuppressionReason(trimToNull(request.suppressionReason()));
            finding.setSuppressedUntil(request.suppressedUntil());
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("suppressionReason", finding.getSuppressionReason());
            details.put("suppressedUntil", finding.getSuppressedUntil());
            appendEvent(
                    finding,
                    "SUPPRESSION_UPDATED",
                    actor,
                    "Suppression metadata updated",
                    details);
        }
    }

    private void audit(String action, String targetType, String targetId, String detailsJson) {
        AuditEventService auditEventService = auditEventServiceProvider.getIfAvailable();
        if (auditEventService != null) {
            auditEventService.record(action, targetType, targetId, detailsJson);
        }
    }

    @Transactional
    public FindingCommentResponse addComment(UUID findingId, FindingCommentRequest request) {
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new EntityNotFoundException("Finding not found: " + findingId));
        FindingComment comment = new FindingComment();
        comment.setFinding(finding);
        comment.setAuthor(request.author().trim());
        comment.setBody(request.body().trim());
        comment = findingCommentRepository.save(comment);
        appendEvent(
                finding,
                "COMMENT_ADDED",
                request.author().trim(),
                "Workflow comment added",
                Map.of("commentId", comment.getId()));
        return new FindingCommentResponse(comment.getId(), comment.getAuthor(), comment.getBody(), comment.getCreatedAt());
    }

    @Transactional(readOnly = true)
    public FindingTimelineResponse getTimeline(UUID findingId) {
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new EntityNotFoundException("Finding not found: " + findingId));
        List<FindingEventResponse> events = findingEventRepository.findByFindingOrderByCreatedAtAsc(finding).stream()
                .map(event -> new FindingEventResponse(
                        event.getId(),
                        event.getEventType(),
                        event.getActor(),
                        event.getSummary(),
                        event.getDetailsJson(),
                        event.getCreatedAt()))
                .toList();
        List<FindingCommentResponse> comments = findingCommentRepository.findByFindingOrderByCreatedAtAsc(finding).stream()
                .map(comment -> new FindingCommentResponse(
                        comment.getId(),
                        comment.getAuthor(),
                        comment.getBody(),
                        comment.getCreatedAt()))
                .toList();
        return new FindingTimelineResponse(findingId, events, comments);
    }

    @Transactional
    public void appendEvent(Finding finding, String eventType, String actor, String summary, Map<String, Object> details) {
        FindingEvent event = new FindingEvent();
        event.setFinding(finding);
        event.setEventType(eventType);
        event.setActor(actor(actor));
        event.setSummary(summary);
        event.setDetailsJson(toJson(details));
        findingEventRepository.save(event);
    }

    public void markObserved(Finding finding, Instant observedAt, UUID observedRunId) {
        if (finding == null) {
            return;
        }
        finding.setLastObservedAt(observedAt);
        finding.setLastObservedRunId(observedRunId);
        finding.setConsecutiveMisses(0);
        finding.setAutoCloseEligibleAt(null);
    }

    public void reopenByObservation(Finding finding, Instant observedAt, UUID observedRunId) {
        FindingStatus previousStatus = finding.getStatus();
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        clearClosureMetadata(finding);
        markObserved(finding, observedAt, observedRunId);
        finding.touch();
        appendEvent(
                finding,
                "REOPENED_BY_OBSERVATION",
                "system",
                "Finding reopened because the affected subject was observed again",
                Map.of(
                        "fromStatus", previousStatus.name(),
                        "observedAt", observedAt
                ));
    }

    public void resolveByVerifiedReassessment(
            Finding finding,
            UUID assessmentId,
            Instant observedAt,
            UUID observedRunId
    ) {
        if (finding == null || finding.getStatus() == FindingStatus.RESOLVED) {
            return;
        }
        FindingStatus previousStatus = finding.getStatus();
        finding.setStatus(FindingStatus.RESOLVED);
        finding.setDecisionState(FindingDecisionState.FIXED);
        finding.setAssessmentId(assessmentId);
        finding.setSuppressionReason(null);
        finding.setSuppressedUntil(null);
        finding.setSuppressedByRuleId(null);
        finding.setSuppressedByRuleName(null);
        markObserved(finding, observedAt, observedRunId);
        applyClosureMetadata(finding, FindingCloseReason.VERIFIED_REMEDIATION,
                "ai-grid-reassessment", null, observedAt);
        finding.touch();
        appendEvent(
                finding,
                "RESOLVED_BY_VERIFIED_REASSESSMENT",
                "ai-grid-reassessment",
                "Finding resolved after a complete reassessment verified remediation",
                Map.of(
                        "fromStatus", previousStatus.name(),
                        "assessmentId", assessmentId,
                        "observedAt", observedAt
                ));
    }

    public void autoCloseFinding(
            Finding finding,
            FindingCloseReason reason,
            String summary,
            Map<String, Object> details,
            Instant closedAt
    ) {
        if (finding == null || finding.getStatus() == FindingStatus.AUTO_CLOSED) {
            return;
        }
        FindingStatus previousStatus = finding.getStatus();
        finding.setStatus(FindingStatus.AUTO_CLOSED);
        finding.setDecisionState(FindingDecisionState.NOT_AFFECTED);
        finding.setSuppressionReason(null);
        finding.setSuppressedUntil(null);
        finding.setSuppressedByRuleId(null);
        finding.setSuppressedByRuleName(null);
        applyClosureMetadata(finding, reason, "system", null, closedAt);
        finding.touch();
        Map<String, Object> eventDetails = new LinkedHashMap<>();
        eventDetails.put("fromStatus", previousStatus.name());
        eventDetails.put("toStatus", FindingStatus.AUTO_CLOSED.name());
        eventDetails.put("closedReason", reason.name());
        if (details != null) {
            eventDetails.putAll(details);
        }
        appendEvent(
                finding,
                "AUTO_CLOSED",
                "system",
                summary == null || summary.isBlank() ? "Finding auto-closed" : summary,
                eventDetails);
    }

    @Scheduled(zone = "UTC", cron = "0 */15 * * * *")
    public void reopenExpiredSuppressions() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-workflow.reopen-expired-suppressions")) {
            return;
        }
        Instant now = Instant.now();
        tenantWorkRunner.forEachActiveTenant(tenant -> reopenExpiredSuppressionsInTenant(now));
    }

    private void reopenExpiredSuppressionsInTenant(Instant now) {
        List<Finding> expired = findingRepository.findByStatusAndSuppressedUntilBeforeOrderById(FindingStatus.SUPPRESSED, now);
        for (Finding finding : expired) {
            finding.setStatus(FindingStatus.OPEN);
            finding.setDecisionState(FindingDecisionState.AFFECTED);
            finding.setSuppressionReason(null);
            finding.setSuppressedUntil(null);
            finding.setSuppressedByRuleId(null);
            finding.setSuppressedByRuleName(null);
            finding.touch();
            appendEvent(
                    finding,
                    "SUPPRESSION_EXPIRED",
                    "system",
                    "Suppression expired and finding reopened",
                    Map.of("reopenedAt", now));
        }
        if (!expired.isEmpty()) {
            findingRepository.saveAll(expired);
            findingListProjectionService.refreshTenantWithSource(expired.get(0).getTenant());
        }
    }

    @Scheduled(zone = "UTC", cron = "0 0 * * * *")
    public void autoCloseFindingsByPolicy() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-workflow.auto-close-findings")) {
            return;
        }
        Instant now = Instant.now();
        tenantWorkRunner.forEachActiveTenant(tenant -> {
            List<RiskPolicy> policies = riskPolicyRepository.findAllForUpdate();
            runAutoCloseForPolicies(policies, now, false);
        });
    }

    public int executeAutoCloseNow(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return 0;
        }
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            RiskPolicy policy = riskPolicyRepository.findTopByOrderByUpdatedAtDesc().orElse(null);
            if (policy == null) {
                return 0;
            }
            return runAutoCloseForPolicyInCurrentTenantSchema(policy, Instant.now(), true);
        }));
    }

    private int runAutoCloseForPolicies(List<RiskPolicy> policies, Instant now, boolean ignoreSchedule) {
        int updated = 0;
        for (RiskPolicy policy : policies) {
            updated += tenantSchemaExecutionService.run(
                    policy.getTenant(),
                    () -> runAutoCloseForPolicyInCurrentTenantSchema(policy, now, ignoreSchedule)
            );
        }
        return updated;
    }

    private int runAutoCloseForPolicyInCurrentTenantSchema(RiskPolicy policy, Instant now, boolean ignoreSchedule) {
        if (!policy.isAutoCloseEnabled() || !policy.isAutoCloseNotObservedEnabled()) {
            return 0;
        }
        if (!ignoreSchedule && !isAutoCloseRunDue(policy, now)) {
            return 0;
        }
        String identifier = trimToNull(policy.getAutoCloseAssetIdentifier());
        List<Finding> findings;
        if (identifier == null) {
            findings = findingRepository.findAutoCloseCandidates(policy.getTenant(), FindingStatus.OPEN, now);
        } else {
            Asset asset = assetRepository.findByIdentifier(identifier).orElse(null);
            if (asset == null) {
                return 0;
            }
            findings = findingRepository.findForMaintenance(FindingStatus.OPEN, asset.getId()).stream()
                    .filter(finding -> finding.getAutoCloseEligibleAt() != null
                            && !finding.getAutoCloseEligibleAt().isAfter(now))
                    .toList();
        }

        List<Finding> toPersist = new ArrayList<>();
        for (Finding finding : findings) {
            if (finding.getConsecutiveMisses() < policy.getAutoCloseRequiredConsecutiveMisses()) {
                continue;
            }
            autoCloseFinding(
                    finding,
                    FindingCloseReason.AUTO_NOT_OBSERVED,
                    "Finding auto-closed because it was not observed in recent scans",
                    Map.of(
                            "assetIdentifier", identifier == null ? "" : identifier,
                            "autoCloseEligibleAt", finding.getAutoCloseEligibleAt(),
                            "consecutiveMisses", finding.getConsecutiveMisses(),
                            "autoCloseAfterDays", policy.getAutoCloseAfterDays(),
                            "requiredConsecutiveMisses", policy.getAutoCloseRequiredConsecutiveMisses()
                    ),
                    now);
            toPersist.add(finding);
        }
        if (!toPersist.isEmpty()) {
            findingRepository.saveAll(toPersist);
            findingListProjectionService.refreshTenantWithSource(policy.getTenant());
        }
        policy.setAutoCloseLastRunAt(now);
        riskPolicyRepository.save(policy);
        return toPersist.size();
    }

    private boolean isAutoCloseRunDue(RiskPolicy policy, Instant now) {
        if (policy.getAutoCloseLastRunAt() == null) {
            return true;
        }
        int intervalDays = Math.max(1, policy.getAutoCloseRunIntervalDays());
        return !policy.getAutoCloseLastRunAt().plus(Duration.ofDays(intervalDays)).isAfter(now);
    }

    private void applyClosureMetadata(
            Finding finding,
            FindingCloseReason reason,
            String actor,
            UUID ruleId,
            Instant closedAt
    ) {
        finding.setClosedAt(closedAt == null ? Instant.now() : closedAt);
        finding.setClosedBy(actor(actor));
        finding.setClosedReason(reason);
        finding.setClosedRuleId(ruleId);
        finding.setAutoCloseEligibleAt(null);
    }

    private void clearClosureMetadata(Finding finding) {
        finding.setClosedAt(null);
        finding.setClosedBy(null);
        finding.setClosedReason(null);
        finding.setClosedRuleId(null);
        finding.setAutoCloseEligibleAt(null);
    }

    private String actor(String actor) {
        return actor == null || actor.isBlank() ? "system" : actor.trim();
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private <T> T executeWrite(java.util.function.Supplier<T> work) {
        if (writeTransactionTemplate == null) {
            return work.get();
        }
        return writeTransactionTemplate.execute(status -> work.get());
    }
}
