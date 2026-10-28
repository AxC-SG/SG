package com.prototype.vulnwatch.aisecurity.controller;

import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CreateServiceNowIncidentRequest;
import com.prototype.vulnwatch.dto.ServiceNowIncidentResponse;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.ticketing.TicketRef;
import com.prototype.vulnwatch.ticketing.TicketRequest;
import com.prototype.vulnwatch.ticketing.TicketingService;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/findings")
public class AiGridFindingIncidentController {

    private final WorkspaceService workspaces;
    private final AiSecurityAccessService access;
    private final TicketingService ticketing;

    public AiGridFindingIncidentController(WorkspaceService workspaces, AiSecurityAccessService access,
                                           TicketingService ticketing) {
        this.workspaces = workspaces;
        this.access = access;
        this.ticketing = ticketing;
    }

    /**
     * Raises a remediation ticket for an AI Grid finding.
     *
     * <p>The path still says {@code servicenow-incident} and the response keeps its original
     * field names so existing clients are unaffected, but the ticket now goes to whichever
     * system the tenant has active — Jira overrides ServiceNow. Prefer
     * {@code POST /api/findings/{findingId}/ticket}, which names the provider in its response.
     */
    @PostMapping("/{findingId}/servicenow-incident")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','SECURITY_ANALYST')")
    public ServiceNowIncidentResponse create(@PathVariable UUID findingId,
                                             @RequestBody CreateServiceNowIncidentRequest request) {
        Tenant tenant = workspaces.getWorkspace();
        access.assertEntitled(tenant);
        TicketRef ref = ticketing.createTicketForFinding(tenant, findingId, toTicketRequest(request));
        return new ServiceNowIncidentResponse(
                ref.externalKey(), ref.externalId(), ref.url(), "created", ref.message());
    }

    private static TicketRequest toTicketRequest(CreateServiceNowIncidentRequest request) {
        if (request == null) {
            return TicketRequest.empty();
        }
        return new TicketRequest(
                request.findingTitle(),
                request.severity(),
                request.priority(),
                request.dueDate(),
                request.assignedTo(),
                null,
                request.notes(),
                request.solutionInfo()
        );
    }
}
