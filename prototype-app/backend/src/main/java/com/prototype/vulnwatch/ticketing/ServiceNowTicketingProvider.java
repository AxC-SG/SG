package com.prototype.vulnwatch.ticketing;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CreateServiceNowIncidentRequest;
import com.prototype.vulnwatch.dto.ServiceNowIncidentResponse;
import com.prototype.vulnwatch.service.ServiceNowCmdbConfigService;
import com.prototype.vulnwatch.service.ServiceNowIncidentService;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * {@link TicketingProvider} over the existing ServiceNow incident integration.
 *
 * <p>A thin adapter on purpose: payload construction, retry policy and error mapping stay in
 * {@link ServiceNowIncidentService}, which is already in production use. This class only
 * translates between the neutral framework types and the ServiceNow-shaped ones.
 */
@Component
public class ServiceNowTicketingProvider implements TicketingProvider {

    private static final String DEFAULT_ASSIGNMENT_GROUP = "App-Sec Manager";

    /** ServiceNow incident states: 2 = In Progress, 6 = Resolved. */
    private static final String STATE_IN_PROGRESS = "2";
    private static final String STATE_RESOLVED = "6";

    private final ServiceNowIncidentService serviceNowIncidentService;
    private final ServiceNowCmdbConfigService serviceNowCmdbConfigService;

    public ServiceNowTicketingProvider(
            ServiceNowIncidentService serviceNowIncidentService,
            ServiceNowCmdbConfigService serviceNowCmdbConfigService
    ) {
        this.serviceNowIncidentService = serviceNowIncidentService;
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
    }

    @Override
    public TicketingSystem system() {
        return TicketingSystem.SERVICENOW;
    }

    /**
     * Presence of a connector config, which is exactly what the pre-existing incident path
     * required. The connector's {@code enabled} flag governs CMDB sync rather than ticketing,
     * so it is deliberately not consulted here — doing so would silently stop incident
     * creation for tenants who only ever disabled inventory sync.
     */
    @Override
    public boolean isConfigured(Tenant tenant) {
        return serviceNowCmdbConfigService.resolveRuntimeConfig(tenant).isPresent();
    }

    @Override
    public TicketRef createForFinding(Tenant tenant, Finding finding, TicketRequest request) {
        ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config =
                serviceNowIncidentService.resolveIncidentConfig(tenant);
        ServiceNowIncidentResponse response = serviceNowIncidentService.createFindingIncidentRemote(
                config, finding, toServiceNowRequest(request));
        return toTicketRef(response, "New");
    }

    @Override
    public TicketRef createForCve(Tenant tenant, CveTicketRequest request) {
        ServiceNowCmdbConfigService.ServiceNowRuntimeConfig config =
                serviceNowIncidentService.resolveIncidentConfig(tenant);
        String assignmentGroup = request.assignmentGroup() == null || request.assignmentGroup().isBlank()
                ? DEFAULT_ASSIGNMENT_GROUP
                : request.assignmentGroup().trim();
        ServiceNowIncidentResponse response = serviceNowIncidentService.createCveIncidentRemote(
                config,
                request.cveId(),
                toServiceNowCveRequest(request),
                assignmentGroup,
                request.safeAssets().stream().map(ServiceNowTicketingProvider::toAffectedAsset).toList());
        return toTicketRef(response, "New");
    }

    @Override
    public Optional<TicketStatus> fetchStatus(Tenant tenant, String externalKey) {
        return serviceNowCmdbConfigService.resolveRuntimeConfig(tenant)
                .flatMap(config -> serviceNowIncidentService.fetchIncidentStateCode(config, externalKey))
                .map(stateCode -> new TicketStatus(
                        ServiceNowIncidentService.SNOW_STATE_LABELS
                                .getOrDefault(stateCode, "Unknown (" + stateCode + ")"),
                        ServiceNowIncidentService.SNOW_RESOLVED_STATE_CODES.contains(stateCode)));
    }

    @Override
    public boolean pushFindingStatus(Tenant tenant, String externalKey, TicketPush push) {
        Optional<ServiceNowCmdbConfigService.ServiceNowRuntimeConfig> config =
                serviceNowCmdbConfigService.resolveRuntimeConfig(tenant);
        if (config.isEmpty() || push == null) {
            return false;
        }
        Map<String, Object> fields = new LinkedHashMap<>();
        // work_notes is the incident's activity log, so every push leaves an audit trail in
        // ServiceNow itself rather than only in Scout.
        fields.put("work_notes", push.note() == null ? "Updated by Scout" : push.note());
        switch (push.action()) {
            case RESOLVE -> {
                fields.put("state", STATE_RESOLVED);
                fields.put("close_code", "Solved (Permanently)");
                fields.put("close_notes", push.note() == null ? "Remediated in Scout" : push.note());
            }
            case REOPEN -> fields.put("state", STATE_IN_PROGRESS);
            case COMMENT -> {
                // note only
            }
        }
        return serviceNowIncidentService.updateIncidentByNumber(config.get(), externalKey, fields);
    }

    private TicketRef toTicketRef(ServiceNowIncidentResponse response, String status) {
        return new TicketRef(
                TicketingSystem.SERVICENOW,
                response.incidentNumber(),
                response.sysId(),
                response.url(),
                status,
                response.message());
    }

    private CreateServiceNowIncidentRequest toServiceNowRequest(TicketRequest request) {
        TicketRequest safe = request == null ? TicketRequest.empty() : request;
        return new CreateServiceNowIncidentRequest(
                safe.title(), safe.severity(), null, null, false, safe.priority(),
                safe.dueDate(), safe.assignee(), safe.notes(), safe.solutionInfo(),
                safe.dueDate(), List.of());
    }

    private CreateServiceNowIncidentRequest toServiceNowCveRequest(CveTicketRequest request) {
        return new CreateServiceNowIncidentRequest(
                request.cveId(), request.severity(), null, null, false, request.priority(),
                request.dueDate(), request.assignee(), request.notes(), request.solutionInfo(),
                request.dueDate(),
                request.safeAssets().stream().map(ServiceNowTicketingProvider::toAffectedAsset).toList());
    }

    private static CreateServiceNowIncidentRequest.AffectedAsset toAffectedAsset(TicketAsset asset) {
        return new CreateServiceNowIncidentRequest.AffectedAsset(
                asset.componentId(),
                asset.assetName(),
                asset.assetIdentifier(),
                asset.assetType(),
                asset.packageName(),
                asset.packageVersion(),
                asset.assignmentGroup());
    }
}
