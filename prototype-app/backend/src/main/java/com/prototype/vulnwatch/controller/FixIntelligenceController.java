package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FixContextResponse;
import com.prototype.vulnwatch.dto.FixControlRequest;
import com.prototype.vulnwatch.dto.FixDetailResponse;
import com.prototype.vulnwatch.dto.FixListPageResponse;
import com.prototype.vulnwatch.dto.FixSummaryResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.service.fix.FixIntelligenceQueryService;
import com.prototype.vulnwatch.service.fix.FixIntelligenceQueryService.ListFilter;
import com.prototype.vulnwatch.service.fix.FixManagementService;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Fix Intelligence: patches from patch tools, Workbench recommendations, and analyst
 * workarounds and compensating controls. Every read is scoped to the authenticated workspace;
 * fixes give remediation context and never change a finding's status.
 */
@RestController
@RequestMapping("/api/fix-intelligence")
public class FixIntelligenceController {

    private final WorkspaceService workspaceService;
    private final FixIntelligenceQueryService queryService;
    private final FixManagementService managementService;
    private final RequestActorService requestActorService;
    private final AuditEventService auditEventService;

    public FixIntelligenceController(
            WorkspaceService workspaceService,
            FixIntelligenceQueryService queryService,
            FixManagementService managementService,
            RequestActorService requestActorService,
            AuditEventService auditEventService
    ) {
        this.workspaceService = workspaceService;
        this.queryService = queryService;
        this.managementService = managementService;
        this.requestActorService = requestActorService;
        this.auditEventService = auditEventService;
    }

    @GetMapping("/summary")
    public FixSummaryResponse summary(@RequestParam(defaultValue = "all") String view) {
        return queryService.summary(workspaceService.getWorkspace(), view);
    }

    @GetMapping("/fixes")
    public FixListPageResponse list(
            @RequestParam(defaultValue = "all") String view,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String ecosystem,
            @RequestParam(required = false) String status,
            @RequestParam(required = false) String search,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        return queryService.list(workspaceService.getWorkspace(),
                new ListFilter(view, severity, ecosystem, status, search), page, size);
    }

    @GetMapping("/fixes/{fixId}")
    public FixDetailResponse detail(@PathVariable UUID fixId) {
        return queryService.detail(workspaceService.getWorkspace(), fixId);
    }

    @GetMapping("/context")
    public FixContextResponse context(@RequestParam(required = false) String cveId,
                                      @RequestParam(required = false) UUID assetId) {
        return queryService.context(workspaceService.getWorkspace(), cveId, assetId);
    }

    @PostMapping("/fixes")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("fix.control.created")
    public FixDetailResponse create(@RequestBody(required = false) FixControlRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        UUID fixId = managementService.create(tenant, actor(), request);
        auditEventService.record("fix.control.created", "fix_record", fixId.toString(), null);
        return queryService.detail(tenant, fixId);
    }

    @PutMapping("/fixes/{fixId}")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("fix.control.updated")
    public FixDetailResponse update(@PathVariable UUID fixId, @RequestBody(required = false) FixControlRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        managementService.update(tenant, actor(), fixId, request);
        auditEventService.record("fix.control.updated", "fix_record", fixId.toString(), null);
        return queryService.detail(tenant, fixId);
    }

    @PostMapping("/fixes/{fixId}/approve")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("fix.control.approved")
    public FixDetailResponse approve(@PathVariable UUID fixId) {
        Tenant tenant = workspaceService.getWorkspace();
        managementService.approve(tenant, actor(), fixId);
        auditEventService.record("fix.control.approved", "fix_record", fixId.toString(), null);
        return queryService.detail(tenant, fixId);
    }

    @PostMapping("/fixes/{fixId}/retire")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("fix.control.retired")
    public FixDetailResponse retire(@PathVariable UUID fixId) {
        Tenant tenant = workspaceService.getWorkspace();
        managementService.retire(tenant, fixId);
        auditEventService.record("fix.control.retired", "fix_record", fixId.toString(), null);
        return queryService.detail(tenant, fixId);
    }

    private String actor() {
        return requestActorService.currentActor().userId();
    }
}
