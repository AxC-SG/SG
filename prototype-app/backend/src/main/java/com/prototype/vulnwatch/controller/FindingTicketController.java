package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CreateFindingTicketRequest;
import com.prototype.vulnwatch.dto.FindingTicketResponse;
import com.prototype.vulnwatch.dto.TicketingProviderStatusResponse;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.ticketing.TicketRef;
import com.prototype.vulnwatch.ticketing.TicketRequest;
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

    @PostMapping("/api/findings/{findingId}/ticket")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public FindingTicketResponse create(
            @PathVariable UUID findingId,
            @RequestBody(required = false) CreateFindingTicketRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        TicketRef ref = ticketingService.createTicketForFinding(tenant, findingId, toTicketRequest(request));
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
