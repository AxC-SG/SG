package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CreateServiceNowIncidentRequest;
import com.prototype.vulnwatch.dto.FindingTicketResponse;
import com.prototype.vulnwatch.dto.ServiceNowIncidentResponse;
import com.prototype.vulnwatch.service.ServiceNowIncidentService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.ticketing.CveTicketRequest;
import com.prototype.vulnwatch.ticketing.TicketAsset;
import com.prototype.vulnwatch.ticketing.TicketRef;
import com.prototype.vulnwatch.ticketing.TicketingService;
import java.util.List;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/cve-detail")
public class ServiceNowIncidentController {

    private final WorkspaceService workspaceService;
    private final ServiceNowIncidentService serviceNowIncidentService;
    private final TicketingService ticketingService;

    public ServiceNowIncidentController(
            WorkspaceService workspaceService,
            ServiceNowIncidentService serviceNowIncidentService,
            TicketingService ticketingService
    ) {
        this.workspaceService = workspaceService;
        this.serviceNowIncidentService = serviceNowIncidentService;
        this.ticketingService = ticketingService;
    }

    /**
     * GET /api/cve-detail/servicenow/assignment-groups
     * Returns the list of active assignment group names from ServiceNow's sys_user_group table.
     * ServiceNow-specific by nature: Jira has no equivalent concept.
     */
    @GetMapping("/servicenow/assignment-groups")
    public List<String> listAssignmentGroups() {
        Tenant tenant = workspaceService.getWorkspace();
        return serviceNowIncidentService.listAssignmentGroups(tenant);
    }

    /**
     * POST /api/cve-detail/{cveId}/servicenow-incident
     *
     * <p>Raises remediation tickets for a CVE, one per assignment group and then one per
     * package for assets without a group.
     *
     * <p>The path and response shape are unchanged for existing clients, but the tickets now go
     * to whichever system the tenant has active — Jira overrides ServiceNow here just as it
     * does for single findings. Prefer {@code POST /api/cve-detail/{cveId}/ticket}, whose
     * response names the provider.
     */
    @PostMapping("/{cveId}/servicenow-incident")
    public ResponseEntity<List<ServiceNowIncidentResponse>> createIncident(
            @PathVariable String cveId,
            @RequestBody CreateServiceNowIncidentRequest request
    ) {
        List<TicketRef> refs = raiseTickets(cveId, request);
        return ResponseEntity.ok(refs.stream()
                .map(ref -> new ServiceNowIncidentResponse(
                        ref.externalKey(), ref.externalId(), ref.url(), "created", ref.message()))
                .toList());
    }

    /**
     * POST /api/cve-detail/{cveId}/ticket
     * Provider-neutral equivalent: same grouping, but the response says which system holds
     * each ticket so the UI can label it correctly.
     */
    @PostMapping("/{cveId}/ticket")
    public List<FindingTicketResponse> createTickets(
            @PathVariable String cveId,
            @RequestBody CreateServiceNowIncidentRequest request
    ) {
        return raiseTickets(cveId, request).stream()
                .map(ref -> new FindingTicketResponse(
                        ref.system().key(),
                        ref.system().displayName(),
                        ref.externalKey(),
                        ref.externalId(),
                        ref.url(),
                        ref.status(),
                        ref.message()))
                .toList();
    }

    private List<TicketRef> raiseTickets(String cveId, CreateServiceNowIncidentRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return ticketingService.createTicketsForCve(tenant, cveId, toCveTicketRequest(cveId, request));
    }

    private static CveTicketRequest toCveTicketRequest(String cveId, CreateServiceNowIncidentRequest request) {
        List<TicketAsset> assets = request == null || request.affectedAssets() == null
                ? List.of()
                : request.affectedAssets().stream()
                        .map(asset -> new TicketAsset(
                                asset.componentId(),
                                asset.assetName(),
                                asset.assetIdentifier(),
                                asset.assetType(),
                                asset.packageName(),
                                asset.packageVersion(),
                                asset.assignmentGroup()))
                        .toList();
        return new CveTicketRequest(
                cveId,
                null,
                request == null ? null : request.severity(),
                request == null ? null : request.priority(),
                request == null ? null : request.dueDate(),
                request == null ? null : request.assignedTo(),
                request == null ? null : request.notes(),
                request == null ? null : request.solutionInfo(),
                assets);
    }
}
