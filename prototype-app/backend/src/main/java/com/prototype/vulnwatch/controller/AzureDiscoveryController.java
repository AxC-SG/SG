package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AzureConnectionTestResponse;
import com.prototype.vulnwatch.dto.AzureDiscoveryConfigRequest;
import com.prototype.vulnwatch.dto.AzureDiscoveryConfigResponse;
import com.prototype.vulnwatch.dto.AzureDiscoveryTargetRequest;
import com.prototype.vulnwatch.dto.AzureDiscoveryTargetResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.AzureDiscoveryConfigService;
import com.prototype.vulnwatch.service.AzureDiscoverySyncService;
import com.prototype.vulnwatch.service.AzureDiscoveryTargetService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.WorkspaceService;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/connectors/azure-discovery")
public class AzureDiscoveryController {

    private final WorkspaceService workspaceService;
    private final AzureDiscoveryConfigService azureDiscoveryConfigService;
    private final AzureDiscoveryTargetService azureDiscoveryTargetService;
    private final AzureDiscoverySyncService azureDiscoverySyncService;
    private final AuditEventService auditEventService;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;

    public AzureDiscoveryController(
            WorkspaceService workspaceService,
            AzureDiscoveryConfigService azureDiscoveryConfigService,
            AzureDiscoveryTargetService azureDiscoveryTargetService,
            AzureDiscoverySyncService azureDiscoverySyncService,
            AuditEventService auditEventService,
            ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider
    ) {
        this.workspaceService = workspaceService;
        this.azureDiscoveryConfigService = azureDiscoveryConfigService;
        this.azureDiscoveryTargetService = azureDiscoveryTargetService;
        this.azureDiscoverySyncService = azureDiscoverySyncService;
        this.auditEventService = auditEventService;
        this.demoLifecycleServiceProvider = demoLifecycleServiceProvider;
    }

    @GetMapping
    public AzureDiscoveryConfigResponse get() {
        Tenant tenant = workspaceService.getWorkspace();
        return azureDiscoveryConfigService.get(tenant);
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.azure_discovery.saved")
    public AzureDiscoveryConfigResponse save(@RequestBody AzureDiscoveryConfigRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        AzureDiscoveryConfigResponse response = azureDiscoveryConfigService.save(tenant, request);
        auditEventService.record("connector.azure_discovery.saved", "connector_config", tenant.getId().toString(), null);
        return response;
    }

    @PostMapping("/test")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.azure_discovery.tested")
    public AzureConnectionTestResponse test() {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        AzureConnectionTestResponse response = azureDiscoveryConfigService.test(tenant);
        auditEventService.record("connector.azure_discovery.tested", "connector_config", tenant.getId().toString(),
                "{\"status\":\"" + response.status() + "\"}");
        return response;
    }

    @PostMapping("/sync")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.azure_discovery.sync_triggered")
    public SyncTriggerResponse sync() {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        SyncTriggerResponse response = azureDiscoverySyncService.trigger();
        auditEventService.record("connector.azure_discovery.sync_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @GetMapping("/sync/status")
    public AzureSyncStatusResponse syncStatus() {
        boolean active = azureDiscoverySyncService.hasActiveRun();
        return new AzureSyncStatusResponse(active, active ? "running" : "disabled");
    }

    @GetMapping("/targets")
    public List<AzureDiscoveryTargetResponse> listTargets() {
        Tenant tenant = workspaceService.getWorkspace();
        return azureDiscoveryTargetService.list(tenant);
    }

    @PostMapping("/targets")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.azure_discovery.target_created")
    public AzureDiscoveryTargetResponse createTarget(@RequestBody AzureDiscoveryTargetRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        AzureDiscoveryTargetResponse response = azureDiscoveryTargetService.create(tenant, request);
        auditEventService.record("connector.azure_discovery.target_created", "connector_target", response.id().toString(), null);
        return response;
    }

    @PutMapping("/targets/{targetId}")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.azure_discovery.target_updated")
    public AzureDiscoveryTargetResponse updateTarget(
            @PathVariable UUID targetId,
            @RequestBody AzureDiscoveryTargetRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        AzureDiscoveryTargetResponse response = azureDiscoveryTargetService.update(tenant, targetId, request);
        auditEventService.record("connector.azure_discovery.target_updated", "connector_target", targetId.toString(), null);
        return response;
    }

    @DeleteMapping("/targets/{targetId}")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.azure_discovery.target_deleted")
    public void deleteTarget(@PathVariable UUID targetId) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        azureDiscoveryTargetService.delete(tenant, targetId);
        auditEventService.record("connector.azure_discovery.target_deleted", "connector_target", targetId.toString(), null);
    }

    @PostMapping("/targets/{targetId}/test")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.azure_discovery.target_tested")
    public AzureConnectionTestResponse testTarget(@PathVariable UUID targetId) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        AzureConnectionTestResponse response = azureDiscoveryTargetService.test(tenant, targetId);
        auditEventService.record("connector.azure_discovery.target_tested", "connector_target", targetId.toString(),
                "{\"status\":\"" + response.status() + "\"}");
        return response;
    }

    @PostMapping("/targets/{targetId}/sync")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.azure_discovery.target_sync_triggered")
    public SyncTriggerResponse syncTarget(@PathVariable UUID targetId) {
        Tenant tenant = workspaceService.getWorkspace();
        assertDemoAllowsLiveConnector(tenant);
        SyncTriggerResponse response = azureDiscoverySyncService.triggerTarget(tenant, targetId);
        auditEventService.record("connector.azure_discovery.target_sync_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), "{\"targetId\":\"" + targetId + "\"}");
        return response;
    }

    public record AzureSyncStatusResponse(boolean active, String status) {}

    private void assertDemoAllowsLiveConnector(Tenant tenant) {
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        if (demoLifecycleService != null) {
            demoLifecycleService.assertDemoAllowsLiveConnector(tenant);
        }
    }
}
