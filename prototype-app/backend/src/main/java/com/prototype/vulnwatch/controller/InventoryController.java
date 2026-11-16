package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.InventoryComponentFilterValuesResponse;
import com.prototype.vulnwatch.dto.InventoryComponentPageResponse;
import com.prototype.vulnwatch.dto.SoftwareIdentityDetailResponse;
import com.prototype.vulnwatch.dto.SoftwareIdentityFunnelResponse;
import com.prototype.vulnwatch.dto.SoftwareIdentityMetadataRequest;
import com.prototype.vulnwatch.dto.SoftwareIdentityMetadataResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.dto.SoftwareIdentityPageResponse;
import com.prototype.vulnwatch.service.InventoryService;
import com.prototype.vulnwatch.service.SoftwareIdentityMetadataService;
import com.prototype.vulnwatch.service.SoftwareIdentityReadService;
import java.util.List;
import java.util.UUID;
import com.prototype.vulnwatch.service.WorkspaceService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/inventory")
public class InventoryController {

    private final WorkspaceService workspaceService;
    private final InventoryService inventoryService;
    private final SoftwareIdentityReadService softwareIdentityReadService;
    private final SoftwareIdentityMetadataService softwareIdentityMetadataService;

    public InventoryController(
            WorkspaceService workspaceService,
            InventoryService inventoryService,
            SoftwareIdentityReadService softwareIdentityReadService,
            SoftwareIdentityMetadataService softwareIdentityMetadataService
    ) {
        this.workspaceService = workspaceService;
        this.inventoryService = inventoryService;
        this.softwareIdentityReadService = softwareIdentityReadService;
        this.softwareIdentityMetadataService = softwareIdentityMetadataService;
    }

    @GetMapping("/components")
    public InventoryComponentPageResponse listComponents(
            @RequestParam(required = false) List<AssetType> assetType,
            @RequestParam(required = false) List<InventoryComponentStatus> componentStatus,
            @RequestParam(required = false) List<String> sourceSystem,
            @RequestParam(required = false) List<String> ecosystem,
            @RequestParam(required = false) List<String> reviewCategory,
            @RequestParam(required = false) String query,
            @RequestParam(required = false) java.util.UUID ownerTeamId,
            @RequestParam(required = false) String ownershipStatus,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return inventoryService.listComponentsPage(tenant, assetType, componentStatus, sourceSystem, ecosystem, reviewCategory, query,
                ownerTeamId, ownershipStatus, page, size);
    }

    @GetMapping("/components/filters")
    public InventoryComponentFilterValuesResponse componentFilters() {
        Tenant tenant = workspaceService.getWorkspace();
        return inventoryService.listComponentFilterValues(tenant);
    }

    @GetMapping("/software-identities")
    public SoftwareIdentityPageResponse listSoftwareIdentities(
            @RequestParam(required = false) List<AssetType> assetType,
            @RequestParam(required = false) List<String> sourceSystem,
            @RequestParam(required = false) List<String> ecosystem,
            @RequestParam(required = false) String lifecycle,
            @RequestParam(required = false) String mappingState,
            @RequestParam(required = false) String coverage,
            @RequestParam(required = false) String operatingSystem,
            @RequestParam(required = false) String query,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return softwareIdentityReadService.listPage(tenant, assetType, sourceSystem, ecosystem, query, lifecycle, mappingState, coverage, operatingSystem, page, size);
    }

    @GetMapping("/software-identities/funnel")
    public SoftwareIdentityFunnelResponse softwareIdentityFunnel() {
        Tenant tenant = workspaceService.getWorkspace();
        return softwareIdentityReadService.getFunnel(tenant);
    }

    @GetMapping("/software-identities/{softwareIdentityId}")
    public SoftwareIdentityDetailResponse getSoftwareIdentity(@PathVariable UUID softwareIdentityId) {
        Tenant tenant = workspaceService.getWorkspace();
        return softwareIdentityReadService.getDetail(tenant, softwareIdentityId);
    }

    @GetMapping("/software-identities/{softwareIdentityId}/metadata")
    public SoftwareIdentityMetadataResponse getSoftwareIdentityMetadata(@PathVariable UUID softwareIdentityId) {
        Tenant tenant = workspaceService.getWorkspace();
        return softwareIdentityMetadataService.getMetadata(tenant, softwareIdentityId);
    }

    @PutMapping("/software-identities/{softwareIdentityId}/metadata")
    @SensitiveTenantAction("inventory.software_identity.metadata_saved")
    public SoftwareIdentityMetadataResponse saveSoftwareIdentityMetadata(
            @PathVariable UUID softwareIdentityId,
            @RequestBody SoftwareIdentityMetadataRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return softwareIdentityMetadataService.saveMetadata(tenant, softwareIdentityId, request);
    }
}
