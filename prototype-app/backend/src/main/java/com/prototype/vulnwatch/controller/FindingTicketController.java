package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CreateFindingTicketRequest;
import com.prototype.vulnwatch.dto.FindingTicketResponse;
import com.prototype.vulnwatch.dto.TicketingProviderStatusResponse;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.ticketing.TicketRef;
import com.prototype.vulnwatch.ticketing.TicketRequest;
import com.prototype.vulnwatch.ticketing.TicketRoutingService;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import com.prototype.vulnwatch.ticketing.TicketingService;
import com.prototype.vulnwatch.ticketing.TicketingSystem;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

/**
 * Provider-neutral ticketing endpoints.
 *
 * <p>Callers do not choose the system — {@link TicketingService} resolves it from the tenant's
 * configured connectors, so enabling Jira redirects new tickets without any client change.
 */
@RestController
public class FindingTicketController {

    private final WorkspaceService workspaceService;
    private final TicketingService ticketingService;
    private com.prototype.vulnwatch.service.cbom.CryptoRemediationService remediation;
    private com.prototype.vulnwatch.service.RequestActorService actors;

    /** CRYPTO findings get the crypto ticket template; every attempt, including failures, is recorded for retry. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setRemediation(com.prototype.vulnwatch.service.cbom.CryptoRemediationService remediation,
            com.prototype.vulnwatch.service.RequestActorService actors) {
        this.remediation = remediation;
        this.actors = actors;
    }

    public FindingTicketController(WorkspaceService workspaceService, TicketingService ticketingService) {
        this.workspaceService = workspaceService;
        this.ticketingService = ticketingService;
    }

    /** Which system new tickets will go to, so the UI can label the action and explain overrides. */
    @GetMapping("/api/ticketing/status")
    public TicketingProviderStatusResponse status() {
        TicketingService.TicketingStatus status = ticketingService.status(workspaceService.getWorkspace());
        return new TicketingProviderStatusResponse(
                status.active() == null ? null : status.active().key(),
                status.active() == null ? null : status.active().displayName(),
                keys(status.configured()),
                keys(status.overridden())
        );
    }

    /**
     * Phase 0B §4.9 routing preview: finding IDs, or a CVE plus component IDs. Returns the batches (owner team, group,
     * routing source, findings), the unroutable and excluded findings and the {@code routingHash} create must send.
     */
    public record TicketPreviewRequest(List<UUID> findingIds, String cveId, List<String> componentIds, String selectedAssignmentGroup,
                                       String assignmentGroupOverride, String overrideReason) { }

    @PostMapping("/api/tickets/preview")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public TicketRoutingService.Preview preview(@RequestBody TicketPreviewRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        if (request == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "findingIds or a CVE is required");
        TicketRoutingService.Choice choice = new TicketRoutingService.Choice(request.selectedAssignmentGroup(),
                request.assignmentGroupOverride(), request.overrideReason());
        if (request.cveId() != null && !request.cveId().isBlank()) {
            return ticketingService.previewForCve(tenant, request.cveId().trim(), request.componentIds(), choice);
        }
        return ticketingService.previewForFindings(tenant, request.findingIds(), choice);
    }

    @PostMapping("/api/findings/{findingId}/ticket")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public FindingTicketResponse create(
            @PathVariable UUID findingId,
            @RequestBody(required = false) CreateFindingTicketRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        String actor = actors == null || actors.currentActor() == null ? "api" : actors.currentActor().userId();
        TicketingService.TicketContext context = new TicketingService.TicketContext(actor, "DEFAULT",
                request == null ? null : request.routingHash(),
                request == null ? TicketRoutingService.Choice.none()
                        : new TicketRoutingService.Choice(request.selectedAssignmentGroup(), request.assignmentGroupOverride(), request.overrideReason()));
        TicketRef ref = remediation == null
                ? ticketingService.createTicketForFinding(tenant, findingId, toTicketRequest(request), context)
                : remediation.createTicket(tenant, findingId, toTicketRequest(request), context);
        return new FindingTicketResponse(
                ref.system().key(),
                ref.system().displayName(),
                ref.externalKey(),
                ref.externalId(),
                ref.url(),
                ref.status(),
                ref.message()
        );
    }

    private static List<String> keys(List<TicketingSystem> systems) {
        return systems.stream().map(TicketingSystem::key).toList();
    }

    private static TicketRequest toTicketRequest(CreateFindingTicketRequest request) {
        if (request == null) {
            return TicketRequest.empty();
        }
        return new TicketRequest(
                request.title(),
                request.severity(),
                request.priority(),
                request.dueDate(),
                request.assignee(),
                request.assignmentGroup(),
                request.notes(),
                request.solutionInfo()
        );
    }
}
