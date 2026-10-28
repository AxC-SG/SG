package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.ticketing.TicketPush;
import com.prototype.vulnwatch.ticketing.TicketStatus;
import com.prototype.vulnwatch.ticketing.TicketingProvider;
import com.prototype.vulnwatch.ticketing.TicketingProviderRegistry;
import com.prototype.vulnwatch.ticketing.TicketingService;
import com.prototype.vulnwatch.ticketing.TicketingSystem;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Keeps findings and their tickets in step, in both directions.
 *
 * <p><strong>Pull</strong> — reads each ticket's state from the system that raised it and
 * writes it to {@code findings.incident_status}. When the ticket reaches a resolved state the
 * finding is resolved too, through {@link FindingWorkflowService} so the transition is audited
 * and list projections refresh.
 *
 * <p><strong>Push</strong> — when a finding's workflow has moved on since the ticket last
 * reflected it, the change is pushed out: resolved findings resolve their ticket, reopened
 * findings reopen it.
 *
 * <p>Routing is per finding, not per tenant. A tenant that moved from ServiceNow to Jira still
 * has findings holding ServiceNow incident numbers, and asking Jira about {@code INC0010005}
 * would fail on every run. {@link TicketingService#owningSystem(Finding)} decides where each
 * ticket is handled.
 *
 * <p>The two directions cannot ping-pong. Both write {@code incident_pushed_status}, and the
 * push side acts only when the finding's status differs from it — so a ticket-driven close
 * records itself as already reflected and is never echoed back to the ticket that caused it.
 *
 * <p>Runs once per day at 07:00.
 */
@Service
public class FindingIncidentSyncService {

    private static final Logger log = LoggerFactory.getLogger(FindingIncidentSyncService.class);

    /** Actor recorded on workflow transitions this job performs. */
    static final String SYNC_ACTOR = "ticketing-sync";

    private final FindingRepository findingRepository;
    private final TicketingProviderRegistry ticketingProviderRegistry;
    private final TicketingService ticketingService;
    private final FindingWorkflowService findingWorkflowService;
    private final TenantWorkRunner tenantWorkRunner;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public FindingIncidentSyncService(
            FindingRepository findingRepository,
            TicketingProviderRegistry ticketingProviderRegistry,
            TicketingService ticketingService,
            FindingWorkflowService findingWorkflowService,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.findingRepository = findingRepository;
        this.ticketingProviderRegistry = ticketingProviderRegistry;
        this.ticketingService = ticketingService;
        this.findingWorkflowService = findingWorkflowService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    /** Scheduled daily at 07:00 to reconcile findings and tickets in both directions. */
    @Scheduled(zone = "UTC", cron = "0 0 7 * * *")
    public void syncIncidentStatuses() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-incident-sync.sync-incident-statuses")) {
            return;
        }
        log.info("Starting bidirectional ticket sync for all linked findings");
        try {
            syncAll();
        } catch (Exception e) {
            log.error("Bidirectional ticket sync failed", e);
        }
    }

    /** Can also be invoked on-demand (e.g. from an admin endpoint). */
    public SyncResult syncAll() {
        SyncAccumulator accumulator = new SyncAccumulator();
        tenantWorkRunner.forEachActiveTenant(tenant -> accumulator.add(syncCurrentTenant()));
        SyncResult result = accumulator.toResult();
        log.info("Bidirectional ticket sync complete — updated={}, unchanged={}, failed={}, "
                        + "findingsResolved={}, pushed={}",
                result.updated(), result.unchanged(), result.failed(),
                result.findingsResolved(), result.pushed());
        return result;
    }

    private SyncResult syncCurrentTenant() {
        List<Finding> findingsWithIncident = findingRepository.findForIncidentSync();
        if (findingsWithIncident.isEmpty()) {
            log.info("No findings with linked tickets — nothing to sync");
            return SyncResult.empty();
        }

        Map<Tenant, List<Finding>> byTenant = findingsWithIncident.stream()
                .collect(Collectors.groupingBy(Finding::getTenant));

        SyncAccumulator accumulator = new SyncAccumulator();
        for (Map.Entry<Tenant, List<Finding>> tenantEntry : byTenant.entrySet()) {
            accumulator.add(syncTenantFindings(tenantEntry.getKey(), tenantEntry.getValue()));
        }
        return accumulator.toResult();
    }

    private SyncResult syncTenantFindings(Tenant tenant, List<Finding> tenantFindings) {
        // Group by the system that raised each ticket, so every ticket is handled by the
        // system that actually knows about it.
        Map<TicketingSystem, List<Finding>> bySystem = new LinkedHashMap<>();
        int unroutable = 0;
        for (Finding finding : tenantFindings) {
            Optional<TicketingSystem> system = ticketingService.owningSystem(finding);
            if (system.isEmpty()) {
                unroutable++;
                continue;
            }
            bySystem.computeIfAbsent(system.get(), ignored -> new ArrayList<>()).add(finding);
        }

        SyncAccumulator accumulator = new SyncAccumulator();
        accumulator.add(SyncResult.failed(unroutable));

        for (Map.Entry<TicketingSystem, List<Finding>> entry : bySystem.entrySet()) {
            TicketingSystem system = entry.getKey();
            List<Finding> systemFindings = entry.getValue();

            Optional<TicketingProvider> providerOpt = ticketingProviderRegistry.providerFor(system);
            if (providerOpt.isEmpty()) {
                log.warn("No provider registered for ticketing system {} — skipping {} findings for tenant {}",
                        system.key(), systemFindings.size(), tenant.getId());
                accumulator.add(SyncResult.failed(systemFindings.size()));
                continue;
            }
            TicketingProvider provider = providerOpt.get();
            accumulator.add(pullFromProvider(tenant, provider, systemFindings));
            accumulator.add(pushToProvider(tenant, provider, systemFindings));
        }
        return accumulator.toResult();
    }

    // ── Pull: ticket → finding ───────────────────────────────────────────────

    private SyncResult pullFromProvider(Tenant tenant, TicketingProvider provider, List<Finding> findings) {
        int synced = 0;
        int unchanged = 0;
        int failed = 0;
        int resolved = 0;

        // Several findings can share one ticket; poll it once.
        Map<String, List<Finding>> byTicket = findings.stream()
                .collect(Collectors.groupingBy(Finding::getIncidentId));

        for (Map.Entry<String, List<Finding>> entry : byTicket.entrySet()) {
            String ticketKey = entry.getKey();
            List<Finding> ticketFindings = entry.getValue();

            Optional<TicketStatus> status;
            try {
                status = provider.fetchStatus(tenant, ticketKey);
            } catch (RuntimeException ex) {
                log.warn("Failed to fetch {} status for ticket {}: {}",
                        provider.system().key(), ticketKey, ex.getMessage());
                status = Optional.empty();
            }

            if (status.isEmpty()) {
                // Leave the last known status in place — a transient outage must not look like
                // a status change.
                log.warn("Could not fetch {} status for ticket {} — skipping",
                        provider.system().key(), ticketKey);
                failed += ticketFindings.size();
                continue;
            }

            TicketStatus ticketStatus = status.get();
            List<Finding> dirty = new ArrayList<>();
            for (Finding finding : ticketFindings) {
                boolean changed = false;
                if (!ticketStatus.label().equals(finding.getIncidentStatus())) {
                    finding.setIncidentStatus(ticketStatus.label());
                    changed = true;
                    synced++;
                } else {
                    unchanged++;
                }
                if (ticketStatus.resolved() && isOpen(finding)) {
                    resolveFromTicket(finding, provider.system(), ticketKey);
                    changed = true;
                    resolved++;
                }
                if (changed) {
                    finding.touch();
                    dirty.add(finding);
                }
            }
            if (!dirty.isEmpty()) {
                findingRepository.saveAll(dirty);
            }
        }

        return new SyncResult(synced, unchanged, failed, resolved, 0);
    }

    /**
     * Resolves a finding because its ticket was resolved.
     *
     * <p>Goes through {@link FindingWorkflowService} so the transition is audited and the
     * findings list projection refreshes, rather than writing the status field directly. The
     * push watermark is advanced in the same breath — that is what stops this close from being
     * pushed straight back to the ticket that triggered it.
     */
    private void resolveFromTicket(Finding finding, TicketingSystem system, String ticketKey) {
        log.info("Resolving finding {} — {} ticket {} is resolved",
                finding.getDisplayId(), system.key(), ticketKey);
        findingWorkflowService.updateWorkflow(finding.getId(), new FindingWorkflowUpdateRequest(
                FindingStatus.RESOLVED.name(),
                null,
                null,
                null,
                null,
                null,
                SYNC_ACTOR));
        finding.setStatus(FindingStatus.RESOLVED);
        finding.setIncidentPushedStatus(FindingStatus.RESOLVED.name());
        finding.setIncidentPushedAt(Instant.now());
    }

    // ── Push: finding → ticket ───────────────────────────────────────────────

    private SyncResult pushToProvider(Tenant tenant, TicketingProvider provider, List<Finding> findings) {
        int pushed = 0;
        int failed = 0;
        List<Finding> dirty = new ArrayList<>();

        for (Finding finding : findings) {
            Optional<TicketPush> push = pushFor(finding);
            if (push.isEmpty()) {
                continue;
            }
            boolean applied;
            try {
                applied = provider.pushFindingStatus(tenant, finding.getIncidentId(), push.get());
            } catch (RuntimeException ex) {
                log.warn("Failed to push finding {} to {} ticket {}: {}",
                        finding.getDisplayId(), provider.system().key(), finding.getIncidentId(),
                        ex.getMessage());
                applied = false;
            }
            if (!applied) {
                // Not recorded as pushed, so the next run retries it.
                failed++;
                continue;
            }
            finding.setIncidentPushedStatus(finding.getStatus() == null ? null : finding.getStatus().name());
            finding.setIncidentPushedAt(Instant.now());
            finding.touch();
            dirty.add(finding);
            pushed++;
        }

        if (!dirty.isEmpty()) {
            findingRepository.saveAll(dirty);
        }
        return new SyncResult(0, 0, failed, 0, pushed);
    }

    /**
     * What, if anything, this finding needs reflected on its ticket.
     *
     * <p>Driven by the difference between the finding's status and the status the ticket
     * already reflects, not by a modification timestamp: an unrelated edit must not trigger a
     * push, and a job that runs late must not miss a transition.
     */
    private Optional<TicketPush> pushFor(Finding finding) {
        if (finding.getIncidentId() == null || finding.getIncidentId().isBlank()) {
            return Optional.empty();
        }
        String current = finding.getStatus() == null ? null : finding.getStatus().name();
        String reflected = finding.getIncidentPushedStatus();
        if (current == null || current.equals(reflected)) {
            return Optional.empty();
        }
        return switch (finding.getStatus()) {
            case RESOLVED, AUTO_CLOSED -> Optional.of(TicketPush.resolve(
                    "Scout finding " + finding.getDisplayId() + " was "
                            + (finding.getStatus() == FindingStatus.AUTO_CLOSED ? "auto-closed" : "resolved")
                            + " — no longer exposed in the tenant's inventory."));
            case OPEN -> reflected == null
                    // Never reflected and already open: the ticket was raised from this state.
                    ? Optional.empty()
                    : Optional.of(TicketPush.reopen(
                            "Scout finding " + finding.getDisplayId() + " was reopened."));
            case SUPPRESSED -> Optional.of(TicketPush.comment(
                    "Scout finding " + finding.getDisplayId()
                            + " was suppressed. Remediation is no longer tracked in Scout."));
        };
    }

    private static boolean isOpen(Finding finding) {
        return finding.getStatus() == FindingStatus.OPEN;
    }

    /**
     * @param updated          findings whose ticket status text changed
     * @param unchanged        findings whose ticket status was already current
     * @param failed           findings that could not be read or pushed this run
     * @param findingsResolved findings closed because their ticket was resolved
     * @param pushed           findings whose workflow change reached the ticket
     */
    public record SyncResult(int updated, int unchanged, int failed, int findingsResolved, int pushed) {

        static SyncResult empty() {
            return new SyncResult(0, 0, 0, 0, 0);
        }

        static SyncResult failed(int count) {
            return new SyncResult(0, 0, count, 0, 0);
        }
    }

    private static final class SyncAccumulator {
        private int updated;
        private int unchanged;
        private int failed;
        private int findingsResolved;
        private int pushed;

        void add(SyncResult result) {
            updated += result.updated();
            unchanged += result.unchanged();
            failed += result.failed();
            findingsResolved += result.findingsResolved();
            pushed += result.pushed();
        }

        SyncResult toResult() {
            return new SyncResult(updated, unchanged, failed, findingsResolved, pushed);
        }
    }
}
