package com.prototype.vulnwatch.ticketing;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.ticketing.TicketRoutingService.Batch;
import com.prototype.vulnwatch.ticketing.TicketRoutingService.Choice;
import com.prototype.vulnwatch.ticketing.TicketRoutingService.Plan;
import com.prototype.vulnwatch.ticketing.TicketRoutingService.Preview;
import com.prototype.vulnwatch.ticketing.TicketRoutingService.Target;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE;

/**
 * The single entry point for raising a remediation ticket against a finding.
 *
 * <p>Owns everything that is not provider-specific: eligibility, provider selection, routing (Phase 0B §4.9, through
 * {@link TicketRoutingService}), the write back to the finding and the routing audit. Every path — single finding,
 * CVE, AI Grid and crypto — writes one {@code finding_ticket_attempts} row per linked finding with the owner snapshot,
 * the group sent, the routing source, the override reason and a batch ID shared by the findings of one ticket.
 * Providers only talk to their remote system.
 */
@Service
public class TicketingService {

    private static final Logger log = LoggerFactory.getLogger(TicketingService.class);

    /** Group key for assets that have neither an assignment group nor a package name. */
    private static final String UNGROUPED_PACKAGE_KEY = "__ungrouped__";
    private static final ObjectMapper JSON = new ObjectMapper();

    /**
     * Who is asking and what they chose. {@code template} labels the attempt (DEFAULT or CRYPTO); {@code routingHash}
     * is the preview's hash, required on the canonical path.
     */
    public record TicketContext(String actor, String template, String routingHash, Choice choice) {
        public static TicketContext system(String actor) {
            return new TicketContext(actor, "DEFAULT", null, Choice.none());
        }

        Choice safeChoice() {
            return choice == null ? Choice.none() : choice;
        }

        String safeActor() {
            return actor == null || actor.isBlank() ? "api" : actor;
        }

        String safeTemplate() {
            return template == null ? "DEFAULT" : template;
        }
    }

    private final TicketingProviderRegistry registry;
    private final FindingRepository findingRepository;
    private TicketRoutingService routing;
    private JdbcTemplate jdbc;
    private TransactionTemplate independent;

    public TicketingService(TicketingProviderRegistry registry, FindingRepository findingRepository) {
        this.registry = registry;
        this.findingRepository = findingRepository;
    }

    @Autowired
    void configure(TicketRoutingService routing, JdbcTemplate jdbc, PlatformTransactionManager transactions) {
        this.routing = routing;
        this.jdbc = jdbc;
        this.independent = new TransactionTemplate(transactions);
        this.independent.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    // ------------------------------------------------------------------ previews

    /** §4.9 preview for findings; writes nothing. */
    @Transactional(readOnly = true)
    public Preview previewForFindings(Tenant tenant, List<UUID> findingIds, Choice choice) {
        if (findingIds == null || findingIds.isEmpty()) throw new ResponseStatusException(BAD_REQUEST, "findingIds or a CVE is required");
        return routing.plan(tenant, findingIds.stream().distinct().toList(), choice).preview();
    }

    /** §4.9 preview for a CVE's findings on the given components; writes nothing. */
    @Transactional(readOnly = true)
    public Preview previewForCve(Tenant tenant, String cveId, List<String> componentIds, Choice choice) {
        return routing.plan(tenant, findingIdsForCve(cveId, componentIds), choice).preview();
    }

    // ------------------------------------------------------------------ single finding

    /** Raises a ticket on the legacy path for callers without a user context (kept for compatibility). */
    @Transactional
    public TicketRef createTicketForFinding(Tenant tenant, UUID findingId, TicketRequest request) {
        return createTicketForFinding(tenant, findingId, request, TicketContext.system("api"));
    }

    /**
     * Raises a ticket for the finding in the tenant's active ticketing system and links it.
     *
     * @throws ResponseStatusException 404 when the finding does not exist, 409 when it is already closed or already
     *         ticketed, 503 when no ticketing system is configured
     * @throws TicketRoutingService.RoutingChangedException on the canonical path when the routing hash is missing,
     *         expired or stale, or the finding cannot be routed without a choice
     */
    @Transactional
    public TicketRef createTicketForFinding(Tenant tenant, UUID findingId, TicketRequest request, TicketContext context) {
        Attempt attempt = new Attempt(UUID.randomUUID(), findingId, null, null, request == null ? null : blankToNull(request.assignmentGroup()),
                RoutingSource.LEGACY);
        Optional<TicketingProvider> configured = registry.activeProvider(tenant);
        if (configured.isEmpty()) {
            ResponseStatusException unavailable = noTicketingSystem();
            // Visible for retry, like every other failure; an unknown finding records nothing.
            recordFailures(List.of(attempt), null, context, unavailable);
            throw unavailable;
        }
        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Finding not found"));
        TicketingProvider active = configured.get();
        String provider = active.system().key();
        try {
            assertEligible(finding);
            Plan plan = routing.plan(tenant, List.of(findingId), context.safeChoice());
            TicketRequest effective = request == null ? TicketRequest.empty() : request;
            if (plan.preview().canonical()) {
                routing.requireCurrent(tenant, plan, context.routingHash(), context.safeChoice());
                if (plan.preview().batches().isEmpty()) {
                    throw new TicketRoutingService.RoutingChangedException(plan.preview().unroutable().isEmpty()
                            ? "The finding is not eligible for a ticket" : plan.preview().unroutable().get(0).reason(), plan.preview());
                }
                Batch batch = plan.preview().batches().get(0);
                attempt = attemptFor(plan.targets().get(findingId), batch, attempt.batchId());
                // §4.9: the routed group replaces anything the caller supplied.
                effective = withGroup(effective, batch.assignmentGroup());
            }
            TicketRef ref = active.createForFinding(tenant, finding, effective);
            link(finding, ref);
            findingRepository.save(finding);
            recordAttempt(attempt, provider, context, "SUCCEEDED", ref.externalKey(), null);
            recordOverride(attempt, context, ref);
            log.info("Linked finding {} to {} ticket {}", finding.getDisplayId(), ref.system().key(), ref.externalKey());
            return ref;
        } catch (TicketRoutingService.RoutingChangedException routingChanged) {
            throw routingChanged;
        } catch (RuntimeException failure) {
            recordFailures(List.of(attempt), provider, context, failure);
            throw failure;
        }
    }

    // ------------------------------------------------------------------ CVE

    /** Raises CVE tickets on the legacy path for callers without a user context (kept for compatibility). */
    @Transactional
    public List<TicketRef> createTicketsForCve(Tenant tenant, String cveId, CveTicketRequest request) {
        return createTicketsForCve(tenant, cveId, request, TicketContext.system("api"));
    }

    /**
     * Raises tickets for a CVE across the assets it affects, and links the matching findings.
     *
     * <p>Canonical path (§4.9): one ticket per current owner team, plus one for Unowned; Conflict findings get no
     * ticket without an override; an override sends every eligible finding as one ticket. Two teams that map to the same
     * group still get one ticket each. Legacy path: one ticket per caller-supplied group, then one per package.
     */
    @Transactional
    public List<TicketRef> createTicketsForCve(Tenant tenant, String cveId, CveTicketRequest request, TicketContext context) {
        TicketingProvider provider = activeProvider(tenant);
        List<TicketAsset> assets = request.safeAssets();
        List<UUID> findingIds = findingIdsForCve(cveId, assets.stream().map(TicketAsset::componentId).toList());
        Plan plan = routing.plan(tenant, findingIds, context.safeChoice());
        if (plan.preview().canonical()) {
            routing.requireCurrent(tenant, plan, context.routingHash(), context.safeChoice());
            if (plan.preview().batches().isEmpty()) {
                throw new TicketRoutingService.RoutingChangedException("No finding of this CVE can be routed; resolve ownership, select a group or override",
                        plan.preview());
            }
            return createCanonicalCveTickets(tenant, provider, cveId, request, context, plan);
        }
        return createLegacyCveTickets(tenant, provider, cveId, request, context);
    }

    private List<TicketRef> createCanonicalCveTickets(Tenant tenant, TicketingProvider provider, String cveId, CveTicketRequest request,
                                                      TicketContext context, Plan plan) {
        Map<String, TicketAsset> assetsByComponent = new LinkedHashMap<>();
        for (TicketAsset asset : request.safeAssets()) {
            if (asset.componentId() != null) assetsByComponent.putIfAbsent(asset.componentId().trim().toLowerCase(java.util.Locale.ROOT), asset);
        }
        List<TicketRef> refs = new ArrayList<>();
        for (Batch batch : plan.preview().batches()) {
            UUID batchId = UUID.randomUUID();
            List<Attempt> attempts = batch.findingIds().stream().map(id -> attemptFor(plan.targets().get(id), batch, batchId)).toList();
            Set<String> components = new HashSet<>();
            for (UUID id : batch.findingIds()) {
                Target target = plan.targets().get(id);
                if (target.componentId() != null) components.add(target.componentId().toString());
            }
            // The caller's per-asset CMDB group is ignored on the canonical path (§4.9).
            List<TicketAsset> batchAssets = assetsByComponent.entrySet().stream().filter(e -> components.contains(e.getKey()))
                    .map(e -> withoutGroup(e.getValue())).toList();
            CveTicketRequest batchRequest = new CveTicketRequest(cveId, batch.assignmentGroup(), request.severity(), request.priority(),
                    request.dueDate(), request.assignee(), request.notes(), request.solutionInfo(), batchAssets);
            try {
                TicketRef ref = provider.createForCve(tenant, batchRequest);
                List<Finding> findings = findingRepository.findAllById(batch.findingIds());
                findings.forEach(finding -> link(finding, ref));
                findingRepository.saveAll(findings);
                attempts.forEach(attempt -> {
                    recordAttempt(attempt, provider.system().key(), context, "SUCCEEDED", ref.externalKey(), null);
                    recordOverride(attempt, context, ref);
                });
                refs.add(ref);
            } catch (RuntimeException failure) {
                recordFailures(attempts, provider.system().key(), context, failure);
                throw failure;
            }
        }
        return refs;
    }

    private List<TicketRef> createLegacyCveTickets(Tenant tenant, TicketingProvider provider, String cveId, CveTicketRequest request,
                                                   TicketContext context) {
        List<TicketRef> refs = new ArrayList<>();
        for (AssetGroup group : groupAssets(request.safeAssets())) {
            CveTicketRequest groupRequest = new CveTicketRequest(cveId, group.assignmentGroup(), request.severity(), request.priority(),
                    request.dueDate(), request.assignee(), request.notes(), request.solutionInfo(), group.assets());
            List<Finding> findings = findingsForCve(cveId, group.assets());
            UUID batchId = UUID.randomUUID();
            List<Attempt> attempts = findings.stream()
                    .map(f -> new Attempt(batchId, f.getId(), null, null, group.assignmentGroup(), RoutingSource.LEGACY)).toList();
            try {
                TicketRef ref = provider.createForCve(tenant, groupRequest);
                findings.forEach(finding -> link(finding, ref));
                if (!findings.isEmpty()) {
                    findingRepository.saveAll(findings);
                    log.info("Linked {} finding(s) for {} to {} ticket {}", findings.size(), cveId, ref.system().key(), ref.externalKey());
                }
                attempts.forEach(attempt -> recordAttempt(attempt, provider.system().key(), context, "SUCCEEDED", ref.externalKey(), null));
                refs.add(ref);
            } catch (RuntimeException failure) {
                recordFailures(attempts, provider.system().key(), context, failure);
                throw failure;
            }
        }
        return refs;
    }

    /**
     * Partitions a CVE's assets the way the ServiceNow integration always has: by assignment group where one is known,
     * otherwise by package. Legacy path only. Preserves input order so ticket contents are stable across runs.
     */
    private List<AssetGroup> groupAssets(List<TicketAsset> assets) {
        Map<String, List<TicketAsset>> byGroup = new LinkedHashMap<>();
        Map<String, List<TicketAsset>> byPackage = new LinkedHashMap<>();
        for (TicketAsset asset : assets) {
            if (asset.assignmentGroup() != null && !asset.assignmentGroup().isBlank()) {
                byGroup.computeIfAbsent(asset.assignmentGroup().trim(), ignored -> new ArrayList<>()).add(asset);
            } else {
                String key = asset.packageName() == null || asset.packageName().isBlank()
                        ? UNGROUPED_PACKAGE_KEY
                        : asset.packageName().trim();
                byPackage.computeIfAbsent(key, ignored -> new ArrayList<>()).add(asset);
            }
        }
        List<AssetGroup> groups = new ArrayList<>();
        byGroup.forEach((group, groupAssets) -> groups.add(new AssetGroup(group, groupAssets)));
        byPackage.forEach((ignored, packageAssets) -> groups.add(new AssetGroup(null, packageAssets)));
        if (groups.isEmpty()) {
            // A CVE with no correlated assets still warrants one ticket for the default group.
            groups.add(new AssetGroup(null, List.of()));
        }
        return groups;
    }

    private List<UUID> findingIdsForCve(String cveId, List<String> componentIds) {
        List<UUID> components = parseIds(componentIds);
        if (components.isEmpty()) return List.of();
        return findingRepository.findByComponentIdInAndVulnerabilityCveId(components, cveId).stream().map(Finding::getId).toList();
    }

    /** The findings of this CVE on the group's components, which the new ticket will link. */
    private List<Finding> findingsForCve(String cveId, List<TicketAsset> assets) {
        List<UUID> componentIds = parseIds(assets.stream().map(TicketAsset::componentId).toList());
        return componentIds.isEmpty() ? List.of() : findingRepository.findByComponentIdInAndVulnerabilityCveId(componentIds, cveId);
    }

    private static List<UUID> parseIds(List<String> values) {
        List<UUID> ids = new ArrayList<>();
        for (String value : values == null ? List.<String>of() : values) {
            if (value == null || value.isBlank()) continue;
            try {
                ids.add(UUID.fromString(value.trim()));
            } catch (IllegalArgumentException ignored) {
                // A component reference that is not one of ours links nothing.
            }
        }
        return ids.stream().distinct().toList();
    }

    private record AssetGroup(String assignmentGroup, List<TicketAsset> assets) {}

    // ------------------------------------------------------------------ audit

    /** One audit row's routing facts. */
    private record Attempt(UUID batchId, UUID findingId, UUID ownerTeamId, UUID assignmentId, String assignmentGroup, RoutingSource source) { }

    private static Attempt attemptFor(Target target, Batch batch, UUID batchId) {
        return new Attempt(batchId, target.findingId(), target.teamId(), target.assignmentId(), batch.assignmentGroup(), batch.routingSource());
    }

    private void recordAttempt(Attempt attempt, String provider, TicketContext context, String outcome, String key, String error) {
        jdbc.update("""
                INSERT INTO finding_ticket_attempts (id, tenant_id, finding_id, provider, template, outcome, ticket_key, error_message, attempted_by,
                    owner_team_id, ownership_assignment_id, assignment_group, routing_source, override_reason, batch_id)
                SELECT ?, NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, f.id, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                  FROM findings f WHERE f.id = ?
                """, UUID.randomUUID(), provider, context.safeTemplate(), outcome, key, truncate(error, 500), context.safeActor(),
                attempt.ownerTeamId(), attempt.assignmentId(), truncate(attempt.assignmentGroup(), 255), attempt.source().name(),
                attempt.source() == RoutingSource.OVERRIDE ? truncate(context.safeChoice().overrideReason(), 500) : null, attempt.batchId(),
                attempt.findingId());
    }

    /** Failed attempts are recorded in their own transaction so they survive the rollback of the ticket request. */
    private void recordFailures(List<Attempt> attempts, String provider, TicketContext context, RuntimeException failure) {
        String message = failure instanceof ResponseStatusException status ? status.getReason() : failure.getMessage();
        try {
            independent.executeWithoutResult(tx -> attempts.forEach(attempt -> recordAttempt(attempt, provider, context, "FAILED", null, message)));
        } catch (RuntimeException auditFailure) {
            log.warn("Could not record failed ticket attempt: {}", auditFailure.getMessage());
        }
    }

    /** §4.9: an override is also a finding event carrying the owner snapshot (V23 columns). */
    private void recordOverride(Attempt attempt, TicketContext context, TicketRef ref) {
        if (attempt.source() != RoutingSource.OVERRIDE) return;
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("assignmentGroup", attempt.assignmentGroup());
        details.put("reason", context.safeChoice().overrideReason());
        details.put("provider", ref.system().key());
        details.put("ticketKey", ref.externalKey());
        details.put("batchId", attempt.batchId().toString());
        String json;
        try {
            json = JSON.writeValueAsString(details);
        } catch (com.fasterxml.jackson.core.JsonProcessingException impossible) {
            throw new IllegalStateException(impossible);
        }
        jdbc.update("""
                INSERT INTO finding_events (id, tenant_id, actor, created_at, details_json, event_type, summary, finding_id, owner_team_id,
                    ownership_assignment_id)
                VALUES (?, NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, now(), ?::jsonb, 'TICKET_ROUTING_OVERRIDE',
                        'Ticket assignment group overridden', ?, ?, ?)
                """, UUID.randomUUID(), context.safeActor(), json, attempt.findingId(), attempt.ownerTeamId(), attempt.assignmentId());
    }

    // ------------------------------------------------------------------ status and helpers

    /** Where new tickets will go, and which configured systems are outranked. */
    @Transactional(readOnly = true)
    public TicketingStatus status(Tenant tenant) {
        List<TicketingSystem> configured = registry.configuredSystems(tenant);
        TicketingSystem active = configured.isEmpty() ? null : configured.get(0);
        List<TicketingSystem> overridden = configured.isEmpty()
                ? List.of()
                : configured.subList(1, configured.size());
        return new TicketingStatus(active, configured, overridden);
    }

    /**
     * The system that owns an existing ticket on a finding.
     *
     * <p>Findings ticketed before provider tracking existed carry no provider, and every one of those came from
     * ServiceNow — it was the only integration. Defaulting them there keeps their status sync working instead of
     * silently dropping it.
     */
    public Optional<TicketingSystem> owningSystem(Finding finding) {
        if (finding == null || finding.getIncidentId() == null || finding.getIncidentId().isBlank()) {
            return Optional.empty();
        }
        return Optional.of(TicketingSystem.fromKey(finding.getIncidentProvider())
                .orElse(TicketingSystem.SERVICENOW));
    }

    private TicketingProvider activeProvider(Tenant tenant) {
        return registry.activeProvider(tenant).orElseThrow(TicketingService::noTicketingSystem);
    }

    private static ResponseStatusException noTicketingSystem() {
        return new ResponseStatusException(SERVICE_UNAVAILABLE,
                "No ticketing system is configured for this tenant. Configure the Jira or "
                        + "ServiceNow connector under Incident & Ticketing Tools first.");
    }

    private void link(Finding finding, TicketRef ref) {
        finding.setIncidentId(ref.externalKey());
        finding.setIncidentStatus(ref.status());
        finding.setIncidentProvider(ref.system().key());
        // Seed the watermark: the ticket was just created from this finding's current status,
        // so there is nothing for the push side to reflect yet.
        finding.setIncidentPushedStatus(finding.getStatus() == null ? null : finding.getStatus().name());
        finding.setIncidentPushedAt(Instant.now());
        finding.touch();
    }

    /**
     * A closed finding has nothing left to remediate, and a finding that already has a ticket must not get a second one
     * — a duplicate would overwrite the link and orphan the first.
     */
    private void assertEligible(Finding finding) {
        if (finding.getStatus() == FindingStatus.RESOLVED || finding.getStatus() == FindingStatus.AUTO_CLOSED) {
            throw new ResponseStatusException(CONFLICT, "Closed findings are not eligible for a new ticket");
        }
        if (finding.getIncidentId() != null && !finding.getIncidentId().isBlank()) {
            TicketingSystem existing = owningSystem(finding).orElse(TicketingSystem.SERVICENOW);
            throw new ResponseStatusException(CONFLICT,
                    "This finding is already linked to " + existing.displayName() + " ticket "
                            + finding.getIncidentId());
        }
    }

    private static TicketRequest withGroup(TicketRequest request, String group) {
        return new TicketRequest(request.title(), request.severity(), request.priority(), request.dueDate(), request.assignee(), group,
                request.notes(), request.solutionInfo());
    }

    private static TicketAsset withoutGroup(TicketAsset asset) {
        return new TicketAsset(asset.componentId(), asset.assetName(), asset.assetIdentifier(), asset.assetType(), asset.packageName(),
                asset.packageVersion(), null);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }

    /**
     * @param active      where new tickets go, or null when nothing is configured
     * @param configured  every configured system, highest precedence first
     * @param overridden  configured systems that {@code active} outranks
     */
    public record TicketingStatus(
            TicketingSystem active,
            List<TicketingSystem> configured,
            List<TicketingSystem> overridden
    ) {
    }
}
