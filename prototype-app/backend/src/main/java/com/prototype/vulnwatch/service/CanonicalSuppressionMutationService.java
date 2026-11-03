package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingEvent;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.repo.FindingEventRepository;
import com.prototype.vulnwatch.repo.FindingSuppressionRequestRepository;
import java.time.Instant;
import java.util.UUID;
import org.springframework.stereotype.Service;

/** The only production boundary allowed to mutate canonical Finding suppression fields. */
@Service
public class CanonicalSuppressionMutationService {
    private final CryptoSuppressionPolicyGuard policyGuard;
    private final FindingEventRepository eventRepository;
    private final FindingSuppressionRequestRepository requestRepository;

    public CanonicalSuppressionMutationService(
            CryptoSuppressionPolicyGuard policyGuard,
            FindingEventRepository eventRepository,
            FindingSuppressionRequestRepository requestRepository
    ) {
        this.policyGuard = policyGuard;
        this.eventRepository = eventRepository;
        this.requestRepository = requestRepository;
    }

    public FindingEvent suppress(
            Finding finding,
            String reason,
            Instant suppressedUntil,
            UUID ruleId,
            String ruleName,
            SuppressionMutationSource source,
            String actor
    ) {
        policyGuard.check(finding, suppressedUntil, source);
        FindingStatus previous = finding.getStatus();
        finding.setStatus(FindingStatus.SUPPRESSED);
        finding.setSuppressionReason(trimToNull(reason));
        finding.setSuppressedUntil(suppressedUntil);
        finding.setSuppressedByRuleId(ruleId);
        finding.setSuppressedByRuleName(trimToNull(ruleName));
        finding.touch();
        return event(finding, "SUPPRESSED", actor, "Finding suppression applied",
                previous, FindingStatus.SUPPRESSED, source.name());
    }

    public FindingEvent clearMetadata(Finding finding, String actor, String eventType, String summary) {
        finding.setSuppressionReason(null);
        finding.setSuppressedUntil(null);
        finding.setSuppressedByRuleId(null);
        finding.setSuppressedByRuleName(null);
        finding.touch();
        cancelPendingIfResolved(finding, actor);
        return event(finding, eventType, actor, summary, finding.getStatus(), finding.getStatus(), "CLEAR");
    }

    private void cancelPendingIfResolved(Finding finding, String actor) {
        if (finding.getStatus() != FindingStatus.RESOLVED && finding.getStatus() != FindingStatus.AUTO_CLOSED) return;
        requestRepository.findByFinding_IdAndStatus(finding.getId(), "REQUESTED").ifPresent(request -> {
            request.setStatus("CANCELLED");
            request.setDecidedBy(actor == null || actor.isBlank() ? "system" : actor);
            request.setDecidedAt(Instant.now());
            request.setDecisionReason("Finding resolved before suppression decision");
            request.touch();
            requestRepository.save(request);
        });
    }

    public FindingEvent reopen(Finding finding, String actor, String eventType, String summary) {
        FindingStatus previous = finding.getStatus();
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        finding.setSuppressionReason(null);
        finding.setSuppressedUntil(null);
        finding.setSuppressedByRuleId(null);
        finding.setSuppressedByRuleName(null);
        finding.touch();
        return event(finding, eventType, actor, summary, previous, FindingStatus.OPEN, "REOPEN");
    }

    public FindingEvent copySuppression(Finding source, Finding target, String actor) {
        if (source.getStatus() != FindingStatus.SUPPRESSED) {
            return null;
        }
        return suppress(target, source.getSuppressionReason(), source.getSuppressedUntil(),
                source.getSuppressedByRuleId(), source.getSuppressedByRuleName(),
                SuppressionMutationSource.SYSTEM_COPY, actor);
    }

    private FindingEvent event(Finding finding, String type, String actor, String summary,
                               FindingStatus from, FindingStatus to, String source) {
        FindingEvent event = new FindingEvent();
        event.setFinding(finding);
        event.setEventType(type);
        event.setActor(actor == null || actor.isBlank() ? "system" : actor);
        event.setSummary(summary);
        event.setDetailsJson("{\"from\":\"" + from + "\",\"to\":\"" + to
                + "\",\"source\":\"" + source + "\"}");
        return eventRepository.save(event);
    }

    private String trimToNull(String value) {
        if (value == null || value.isBlank()) return null;
        return value.trim();
    }
}
