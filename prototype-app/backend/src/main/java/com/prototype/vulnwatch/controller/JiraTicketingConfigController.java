package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.JiraConnectionTestResponse;
import com.prototype.vulnwatch.dto.JiraTicketingConfigRequest;
import com.prototype.vulnwatch.dto.JiraTicketingConfigResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.JiraTicketingConfigService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Tenant-facing configuration for the Jira ticketing connector. */
@RestController
@RequestMapping("/api/connectors/jira-ticketing")
public class JiraTicketingConfigController {

    private static final Logger LOG = LoggerFactory.getLogger(JiraTicketingConfigController.class);

    private final WorkspaceService workspaceService;
    private final JiraTicketingConfigService jiraTicketingConfigService;
    private final AuditEventService auditEventService;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;

    public JiraTicketingConfigController(
            WorkspaceService workspaceService,
            JiraTicketingConfigService jiraTicketingConfigService,
            AuditEventService auditEventService,
            ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider
    ) {
        this.workspaceService = workspaceService;
        this.jiraTicketingConfigService = jiraTicketingConfigService;
        this.auditEventService = auditEventService;
        this.demoLifecycleServiceProvider = demoLifecycleServiceProvider;
    }

    @GetMapping
    public JiraTicketingConfigResponse get() {
        return jiraTicketingConfigService.get(workspaceService.getWorkspace());
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.jira_ticketing.saved")
    public JiraTicketingConfigResponse save(@Valid @RequestBody JiraTicketingConfigRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        JiraTicketingConfigResponse response = jiraTicketingConfigService.save(tenant, request);
        recordAuditSafely("connector.jira_ticketing.saved", "connector_config", tenant.getId().toString(), null);
        return response;
    }

    @PostMapping("/test")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.jira_ticketing.tested")
    public JiraConnectionTestResponse test() {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        JiraConnectionTestResponse response = jiraTicketingConfigService.test(tenant);
        recordAuditSafely("connector.jira_ticketing.tested", "connector_config", tenant.getId().toString(),
                "{\"status\":\"" + response.status() + "\"}");
        return response;
    }

    private void assertDemoAllowsLiveConnector(Tenant tenant) {
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        if (demoLifecycleService != null) {
            demoLifecycleService.assertDemoAllowsLiveConnector(tenant);
        }
    }

    private void recordAuditSafely(String action, String targetType, String targetId, String detailsJson) {
        try {
            auditEventService.record(action, targetType, targetId, detailsJson);
        } catch (Exception ex) {
            LOG.warn("Failed to record audit event for {} ({}): {}", action, targetType, ex.getMessage());
        }
    }
}
