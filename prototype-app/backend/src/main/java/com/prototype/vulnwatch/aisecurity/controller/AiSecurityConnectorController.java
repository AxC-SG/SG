package com.prototype.vulnwatch.aisecurity.controller;

import com.fasterxml.jackson.databind.node.NullNode;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAccessService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.ConnectionTestResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.ConnectorConfigRequest;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.ConnectorConfigResponse;
import com.prototype.vulnwatch.aisecurity.aws.AwsPermissionPreflightService;
import com.prototype.vulnwatch.aisecurity.aws.AwsPolicyPermissionMatrix;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/connectors/ai-security/aws")
public class AiSecurityConnectorController {

    private final WorkspaceService workspaceService;
    private final RequestActorService actorService;
    private final AiSecurityAccessService accessService;
    private final AiSecurityAwsConnectorService connectorService;
    private final AwsPermissionPreflightService preflightService;
    private final AwsPolicyPermissionMatrix permissionMatrix;

    public AiSecurityConnectorController(
            WorkspaceService workspaceService,
            RequestActorService actorService,
            AiSecurityAccessService accessService,
            AiSecurityAwsConnectorService connectorService,
            AwsPermissionPreflightService preflightService,
            AwsPolicyPermissionMatrix permissionMatrix
    ) {
        this.workspaceService = workspaceService;
        this.actorService = actorService;
        this.accessService = accessService;
        this.connectorService = connectorService;
        this.preflightService = preflightService;
        this.permissionMatrix = permissionMatrix;
    }

    @GetMapping
    public ResponseEntity<Object> get() {
        ConnectorConfigResponse config = connectorService.get(tenant());
        // Spring writes a null controller return value as an empty body. Query clients
        // need a JSON value to distinguish an unconfigured connector from a read failure.
        return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
                .body(config == null ? NullNode.getInstance() : config);
    }

    @PutMapping
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public ConnectorConfigResponse save(@RequestBody ConnectorConfigRequest request) {
        return connectorService.save(tenant(), request);
    }

    @PostMapping("/test")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public ConnectionTestResponse test() {
        Tenant tenant = tenant();
        ConnectionTestResponse connection = connectorService.test(tenant);
        return connection.success() ? connection.withPreflight(preflightService.run(tenant)) : connection;
    }

    @GetMapping("/requirements")
    public AwsPolicyPermissionMatrix.RequirementsReport requirements() {
        tenant();
        return permissionMatrix.requirementsReport();
    }

    @PostMapping("/preflight")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public AwsPermissionPreflightService.PreflightReport preflight() {
        return preflightService.run(tenant());
    }

    @PostMapping("/run")
    @PreAuthorize("hasAnyRole('PLATFORM_OWNER','TENANT_ADMIN','INVENTORY_ADMIN')")
    public IngestionJobAcceptedResponse run() {
        return connectorService.trigger(tenant(), actorService.currentActor().userId());
    }

    private Tenant tenant() {
        Tenant tenant = workspaceService.getWorkspace();
        accessService.assertEntitled(tenant);
        return tenant;
    }
}
