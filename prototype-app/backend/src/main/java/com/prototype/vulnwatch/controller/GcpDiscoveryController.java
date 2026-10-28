package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GcpConnectionTestResponse;
import com.prototype.vulnwatch.dto.GcpDiscoveryConfigRequest;
import com.prototype.vulnwatch.dto.GcpDiscoveryConfigResponse;
import com.prototype.vulnwatch.dto.GcpDiscoveryTargetRequest;
import com.prototype.vulnwatch.dto.GcpDiscoveryTargetResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.GcpDiscoveryConfigService;
import com.prototype.vulnwatch.service.GcpDiscoverySyncService;
import com.prototype.vulnwatch.service.GcpDiscoveryTargetService;
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

/** GCP Cloud Discovery connector; same authority, audit and demo rules as AWS discovery. */
@RestController
@RequestMapping("/api/connectors/gcp-discovery")
public class GcpDiscoveryController {

    private final WorkspaceService workspaceService;
    private final GcpDiscoveryConfigService configService;
    private final GcpDiscoverySyncService syncService;
    private final GcpDiscoveryTargetService targetService;
    private final AuditEventService auditEventService;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;

    public GcpDiscoveryController(
            WorkspaceService workspaceService,
            GcpDiscoveryConfigService configService,
            GcpDiscoverySyncService syncService,
            GcpDiscoveryTargetService targetService,
            AuditEventService auditEventService,
            ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider
    ) {
        this.workspaceService = workspaceService;
        this.configService = configService;
        this.syncService = syncService;
        this.targetService = targetService;
        this.auditEventService = auditEventService;
        this.demoLifecycleServiceProvider = demoLifecycleServiceProvider;
    }

    @GetMapping
    public GcpDiscoveryConfigResponse get() {
        return configService.get(workspaceService.getWorkspace());
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.gcp_discovery.saved")
    public GcpDiscoveryConfigResponse save(@RequestBody(required = false) GcpDiscoveryConfigRequest request) {
        Tenant tenant = liveTenant();
        GcpDiscoveryConfigResponse response = configService.save(tenant, request);
        auditEventService.record("connector.gcp_discovery.saved", "connector_config", tenant.getId().toString(), null);
        return response;
    }

    @PostMapping("/test")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.gcp_discovery.tested")
    public GcpConnectionTestResponse test() {
        Tenant tenant = liveTenant();
        GcpConnectionTestResponse response = targetService.testAll(tenant);
        auditEventService.record("connector.gcp_discovery.tested", "connector_config", tenant.getId().toString(),
                "{\"status\":\"" + response.status() + "\"}");
        return response;
    }

    @PostMapping("/sync")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.gcp_discovery.sync_triggered")
    public SyncTriggerResponse sync() {
        liveTenant();
        SyncTriggerResponse response = syncService.trigger();
        auditEventService.record("connector.gcp_discovery.sync_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), null);
        return response;
    }

    @GetMapping("/targets")
    public List<GcpDiscoveryTargetResponse> listTargets() {
        return targetService.list(workspaceService.getWorkspace());
    }

    @PostMapping("/targets")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.gcp_discovery.target_created")
    public GcpDiscoveryTargetResponse createTarget(@RequestBody GcpDiscoveryTargetRequest request) {
        Tenant tenant = liveTenant();
        GcpDiscoveryTargetResponse response = targetService.create(tenant, request);
        auditEventService.record("connector.gcp_discovery.target_created", "connector_target", response.id().toString(), null);
        return response;
    }

    @PutMapping("/targets/{targetId}")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.gcp_discovery.target_updated")
    public GcpDiscoveryTargetResponse updateTarget(@PathVariable UUID targetId, @RequestBody GcpDiscoveryTargetRequest request) {
        Tenant tenant = liveTenant();
        GcpDiscoveryTargetResponse response = targetService.update(tenant, targetId, request);
        auditEventService.record("connector.gcp_discovery.target_updated", "connector_target", targetId.toString(), null);
        return response;
    }

    @DeleteMapping("/targets/{targetId}")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.gcp_discovery.target_deleted")
    public void deleteTarget(@PathVariable UUID targetId) {
        Tenant tenant = liveTenant();
        targetService.delete(tenant, targetId);
        auditEventService.record("connector.gcp_discovery.target_deleted", "connector_target", targetId.toString(), null);
    }

    @PostMapping("/targets/{targetId}/test")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.gcp_discovery.target_tested")
    public GcpConnectionTestResponse testTarget(@PathVariable UUID targetId) {
        Tenant tenant = liveTenant();
        GcpConnectionTestResponse response = targetService.test(tenant, targetId);
        auditEventService.record("connector.gcp_discovery.target_tested", "connector_target", targetId.toString(),
                "{\"status\":\"" + response.status() + "\"}");
        return response;
    }

    @PostMapping("/targets/{targetId}/sync")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.gcp_discovery.target_sync_triggered")
    public SyncTriggerResponse syncTarget(@PathVariable UUID targetId) {
        Tenant tenant = liveTenant();
        SyncTriggerResponse response = syncService.triggerTarget(tenant, targetId);
        auditEventService.record("connector.gcp_discovery.target_sync_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), "{\"targetId\":\"" + targetId + "\"}");
        return response;
    }

    @GetMapping("/sync/status")
    public GcpSyncStatusResponse syncStatus() {
        boolean active = syncService.hasActiveRun();
        return new GcpSyncStatusResponse(active, active ? "running" : "idle");
    }

    public record GcpSyncStatusResponse(boolean active, String status) {}

    private Tenant liveTenant() {
        Tenant tenant = workspaceService.getWorkspace();
        DemoLifecycleService demoLifecycleService = demoLifecycleServiceProvider.getIfAvailable();
        if (demoLifecycleService != null) {
            demoLifecycleService.assertDemoAllowsLiveConnector(tenant);
        }
        return tenant;
    }
}
