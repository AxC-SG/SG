package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.PatchProviderType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.PatchConnectionTestResponse;
import com.prototype.vulnwatch.dto.PatchConnectorConfigRequest;
import com.prototype.vulnwatch.dto.PatchConnectorConfigResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.service.patch.PatchConnectorService;
import com.prototype.vulnwatch.service.patch.PatchSyncService;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * Patch management connectors (SCCM, Intune, BigFix, Tanium). Same authority, audit and demo
 * rules as the inventory connectors; the tenant always comes from the authenticated workspace.
 */
@RestController
@RequestMapping("/api/connectors/patch/{provider}")
public class PatchConnectorController {

    private final WorkspaceService workspaceService;
    private final PatchConnectorService connectorService;
    private final PatchSyncService syncService;
    private final AuditEventService auditEventService;
    private final ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider;

    public PatchConnectorController(
            WorkspaceService workspaceService,
            PatchConnectorService connectorService,
            PatchSyncService syncService,
            AuditEventService auditEventService,
            ObjectProvider<DemoLifecycleService> demoLifecycleServiceProvider
    ) {
        this.workspaceService = workspaceService;
        this.connectorService = connectorService;
        this.syncService = syncService;
        this.auditEventService = auditEventService;
        this.demoLifecycleServiceProvider = demoLifecycleServiceProvider;
    }

    @GetMapping
    public PatchConnectorConfigResponse get(@PathVariable String provider) {
        return connectorService.get(workspaceService.getWorkspace(), type(provider));
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.patch.saved")
    public PatchConnectorConfigResponse save(@PathVariable String provider,
                                             @RequestBody(required = false) PatchConnectorConfigRequest request) {
        PatchProviderType type = type(provider);
        Tenant tenant = liveTenant();
        PatchConnectorConfigResponse response = connectorService.save(tenant, type, request);
        auditEventService.record("connector.patch.saved", "connector_config", tenant.getId().toString(),
                "{\"provider\":\"" + type.name() + "\"}");
        return response;
    }

    @PostMapping("/test")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.patch.tested")
    public PatchConnectionTestResponse test(@PathVariable String provider) {
        PatchProviderType type = type(provider);
        Tenant tenant = liveTenant();
        PatchConnectionTestResponse response = connectorService.test(tenant, type);
        auditEventService.record("connector.patch.tested", "connector_config", tenant.getId().toString(),
                "{\"provider\":\"" + type.name() + "\",\"status\":\"" + response.status() + "\"}");
        return response;
    }

    @PostMapping("/sync")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    @SensitiveTenantAction("connector.patch.sync_triggered")
    public SyncTriggerResponse sync(@PathVariable String provider) {
        PatchProviderType type = type(provider);
        liveTenant();
        SyncTriggerResponse response = syncService.trigger(type);
        auditEventService.record("connector.patch.sync_triggered", "sync_run",
                response.runId() == null ? null : response.runId().toString(), "{\"provider\":\"" + type.name() + "\"}");
        return response;
    }

    @GetMapping("/sync/status")
    public PatchSyncStatusResponse syncStatus(@PathVariable String provider) {
        boolean active = syncService.hasActiveRun(type(provider));
        return new PatchSyncStatusResponse(active, active ? "running" : "idle");
    }

    public record PatchSyncStatusResponse(boolean active, String status) {}

    private static PatchProviderType type(String provider) {
        try {
            return PatchProviderType.parse(provider);
        } catch (IllegalArgumentException unknown) {
            throw new ResponseStatusException(NOT_FOUND, "Unsupported patch provider");
        }
    }

    private Tenant liveTenant() {
        Tenant tenant = workspaceService.getWorkspace();
        DemoLifecycleService demo = demoLifecycleServiceProvider.getIfAvailable();
        if (demo != null) {
            demo.assertDemoAllowsLiveConnector(tenant);
        }
        return tenant;
    }
}
