package com.prototype.vulnwatch.ticketing;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE;

/**
 * The single entry point for raising a remediation ticket against a finding.
 *
 * <p>Owns everything that is not provider-specific: eligibility, provider selection, and the
 * write back to the finding. Providers only talk to their remote system, so a new integration
 * cannot forget to record which system holds the ticket.
 */
@Service
public class TicketingService {

    private static final Logger log = LoggerFactory.getLogger(TicketingService.class);

    /** Group key for assets that have neither an assignment group nor a package name. */
    private static final String UNGROUPED_PACKAGE_KEY = "__ungrouped__";

    private final TicketingProviderRegistry registry;
    private final FindingRepository findingRepository;

    public TicketingService(TicketingProviderRegistry registry, FindingRepository findingRepository) {
        this.registry = registry;
        this.findingRepository = findingRepository;
    }

    /**
     * Raises a ticket for the finding in the tenant's active ticketing system and links it.
     *
     * @throws ResponseStatusException 404 when the finding does not exist, 409 when it is
     *         already closed or already ticketed, 503 when no ticketing system is configured
     */
    @Transactional
    public TicketRef createTicketForFinding(Tenant tenant, UUID findingId, TicketRequest request) {
        TicketingProvider provider = registry.activeProvider(tenant)
                .orElseThrow(() -> new ResponseStatusException(SERVICE_UNAVAILABLE,
                        "No ticketing system is configured for this tenant. Configure the Jira or "
                                + "ServiceNow connector under Incident & Ticketing Tools first."));

        Finding finding = findingRepository.findById(findingId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Finding not found"));
        assertEligible(finding);

        TicketRef ref = provider.createForFinding(tenant, finding, request);
        link(finding, ref);
        findingRepository.save(finding);
        log.info("Linked finding {} to {} ticket {}", finding.getDisplayId(), ref.system().key(), ref.externalKey());
        return ref;
    }

    /**
     * Raises tickets for a CVE across the assets it affects, and links the matching findings.
     *
     * <p>Grouping is provider-neutral and lives here, so a provider only ever renders one
     * ticket for one group:
     * <ol>
     *   <li>assets with a known assignment group are consolidated into one ticket per group;</li>
     *   <li>assets without one are grouped by software package, each under the default group.</li>
     * </ol>
     *
     * <p>Routing obeys the same precedence as single-finding ticketing, which is what makes the
     * Jira override apply to the CVE workflow rather than only to findings.
     */
    @Transactional
    public List<TicketRef> createTicketsForCve(Tenant tenant, String cveId, CveTicketRequest request) {
        TicketingProvider provider = registry.activeProvider(tenant)
                .orElseThrow(() -> new ResponseStatusException(SERVICE_UNAVAILABLE,
                        "No ticketing system is configured for this tenant. Configure the Jira or "
                                + "ServiceNow connector under Incident & Ticketing Tools first."));

        List<TicketRef> refs = new ArrayList<>();
        for (AssetGroup group : groupAssets(request.safeAssets())) {
            CveTicketRequest groupRequest = new CveTicketRequest(
                    cveId,
                    group.assignmentGroup(),
                    request.severity(),
                    request.priority(),
                    request.dueDate(),
                    request.assignee(),
                    request.notes(),
                    request.solutionInfo(),
                    group.assets());
            TicketRef ref = provider.createForCve(tenant, groupRequest);
            refs.add(ref);
            linkFindingsForCve(cveId, group.assets(), ref);
        }
        return refs;
    }

    /**
     * Partitions a CVE's assets the way the ServiceNow integration always has: by assignment
     * group where one is known, otherwise by package. Preserves input order so ticket contents
     * are stable across runs.
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

    /**
     * Links every finding for this CVE on the group's components to the new ticket.
     *
     * <p>Writes the same four fields as the single-finding path — id, status, provider and the
     * push watermark — so a CVE-raised ticket is indistinguishable to the sync job from one
     * raised on a finding.
     */
    private void linkFindingsForCve(String cveId, List<TicketAsset> assets, TicketRef ref) {
        List<UUID> componentIds = assets.stream()
                .map(TicketAsset::componentId)
                .filter(id -> id != null && !id.isBlank())
                .map(id -> {
                    try {
                        return UUID.fromString(id.trim());
                    } catch (IllegalArgumentException ex) {
                        return null;
                    }
                })
                .filter(id -> id != null)
                .toList();
        if (componentIds.isEmpty()) {
            return;
        }
        List<Finding> findings =
                findingRepository.findByComponentIdInAndVulnerabilityCveId(componentIds, cveId);
        for (Finding finding : findings) {
            link(finding, ref);
        }
        if (!findings.isEmpty()) {
            findingRepository.saveAll(findings);
            log.info("Linked {} finding(s) for {} to {} ticket {}",
                    findings.size(), cveId, ref.system().key(), ref.externalKey());
        }
    }

    private record AssetGroup(String assignmentGroup, List<TicketAsset> assets) {}

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
     * <p>Findings ticketed before provider tracking existed carry no provider, and every one of
     * those came from ServiceNow — it was the only integration. Defaulting them there keeps
     * their status sync working instead of silently dropping it.
     */
    public Optional<TicketingSystem> owningSystem(Finding finding) {
        if (finding == null || finding.getIncidentId() == null || finding.getIncidentId().isBlank()) {
            return Optional.empty();
        }
        return Optional.of(TicketingSystem.fromKey(finding.getIncidentProvider())
                .orElse(TicketingSystem.SERVICENOW));
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
     * A closed finding has nothing left to remediate, and a finding that already has a ticket
     * must not get a second one — a duplicate would overwrite the link and orphan the first.
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
