package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomSourceCompleteness;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.ApplicationRiskResponse;
import com.prototype.vulnwatch.dto.ApplicationCveResponse;
import com.prototype.vulnwatch.dto.BomComponentDetailResponse;
import com.prototype.vulnwatch.dto.BomComponentSummaryResponse;
import com.prototype.vulnwatch.dto.BomDetailResponse;
import com.prototype.vulnwatch.dto.CbomBomAssetResponse;
import com.prototype.vulnwatch.dto.BomDashboardResponse;
import com.prototype.vulnwatch.dto.BomFetchRequest;
import com.prototype.vulnwatch.dto.BomIngestionResultResponse;
import com.prototype.vulnwatch.dto.BomInventoryItemResponse;
import com.prototype.vulnwatch.dto.BomLineageItemResponse;
import com.prototype.vulnwatch.dto.BomSourceResponse;
import com.prototype.vulnwatch.dto.BomSourceSelector;
import com.prototype.vulnwatch.dto.BomSupportMatrixResponse;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.service.BomIngestionOrchestrator;
import com.prototype.vulnwatch.service.BomInventoryReadService;
import com.prototype.vulnwatch.service.BomSourceReadService;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import jakarta.validation.Valid;
import java.io.IOException;
import java.util.List;
import java.util.UUID;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/bom")
public class BomController {

    private final WorkspaceService workspaceService;
    private final BomIngestionOrchestrator bomIngestionOrchestrator;
    private final BomInventoryReadService bomInventoryReadService;
    private final IngestionJobService ingestionJobService;
    private final RequestActorService requestActorService;
    private final BomSourceReadService bomSourceReadService;

    public BomController(
            WorkspaceService workspaceService,
            BomIngestionOrchestrator bomIngestionOrchestrator,
            BomInventoryReadService bomInventoryReadService,
            IngestionJobService ingestionJobService,
            RequestActorService requestActorService,
            BomSourceReadService bomSourceReadService
    ) {
        this.workspaceService = workspaceService;
        this.bomIngestionOrchestrator = bomIngestionOrchestrator;
        this.bomInventoryReadService = bomInventoryReadService;
        this.ingestionJobService = ingestionJobService;
        this.requestActorService = requestActorService;
        this.bomSourceReadService = bomSourceReadService;
    }

    /**
     * POST /api/bom/fetch
     * Fetch a BOM from a remote URL and ingest it.
     * Supports SBOM, VENDOR, AI_BOM, CBOM types.
     * CycloneDX 1.4/1.5 and SPDX 2.2/2.3 formats.
     */
    @PostMapping("/fetch")
    @PreAuthorize("hasAnyRole('INVENTORY_ADMIN','TENANT_ADMIN','CREATOR')")
    public ResponseEntity<IngestionJobAcceptedResponse> fetchBom(
            @Valid @RequestBody BomFetchRequest request
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        IngestionJobAcceptedResponse response = ingestionJobService.enqueueBomFetchJob(
                tenant,
                request,
                requestActorService.currentActor().userId()
        );
        return ResponseEntity.accepted().body(response);
    }

    /**
     * POST /api/bom/upload
     * Upload a BOM file (multipart) and ingest it.
     * Max 50 MB. Supports CycloneDX JSON/XML and SPDX JSON/TV/XML.
     */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    @PreAuthorize("hasAnyRole('INVENTORY_ADMIN','TENANT_ADMIN','CREATOR')")
    public BomIngestionResultResponse uploadBom(
            @RequestPart("file") MultipartFile file,
            @RequestParam BomType bomType,
            @RequestParam AssetType assetType,
            @RequestParam String assetName,
            @RequestParam String assetIdentifier,
            @RequestParam(required = false) String supplier,
            // Omit to create an independent source; supply it to replace that source's
            // current version. Replacement is never inferred from asset and supplier.
            @RequestParam(required = false) UUID sourceId,
            // PARTIAL unless the uploader asserts the document covers the asset's whole
            // software inventory. Only that assertion can later justify retiring a component,
            // and it must be repeated on every replacement.
            @RequestParam(required = false) BomSourceCompleteness completeness
    ) throws IOException {
        if (file.isEmpty()) {
            throw new IOException("BOM file is empty");
        }
        if (file.getSize() > BomIngestionOrchestrator.MAX_BOM_BYTES) {
            throw new IOException("BOM file exceeds 50 MB limit");
        }
        Tenant tenant = workspaceService.getWorkspace();
        RequestActor actor = requestActorService.currentActor();
        BomSourceSelector selector = new BomSourceSelector(
                sourceId,
                null,
                completeness == null ? BomSourceCompleteness.PARTIAL : completeness,
                actor.roles(),
                actor.userId());
        return bomIngestionOrchestrator.ingestFromUpload(
                tenant, bomType, assetType, assetName, assetIdentifier,
                supplier, file.getBytes(), file.getOriginalFilename(), selector
        );
    }

    /**
     * GET /api/bom/sources
     * Logical BOM sources, optionally for one asset.
     *
     * <p>Replacement is explicit now, so a client that wants to replace a source has to be
     * able to discover which sources exist and what each currently claims.
     */
    @GetMapping("/sources")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<BomSourceResponse> listBomSources(
            @RequestParam(required = false) UUID assetId
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return bomSourceReadService.listSources(tenant, assetId);
    }

    /**
     * GET /api/bom/inventory
     * Paginated list of active BOM records for the tenant.
     */
    @GetMapping("/inventory")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<BomInventoryItemResponse> listInventory(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return bomInventoryReadService.listInventory(tenant, page, size);
    }

    @GetMapping("/components")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<BomComponentSummaryResponse> getBomComponents(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "500") int size
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return bomInventoryReadService.getBomComponentSummaries(tenant, page, size);
    }

    @GetMapping("/components/{componentId}")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public BomComponentDetailResponse getComponentDetail(@PathVariable UUID componentId) {
        Tenant tenant = workspaceService.getWorkspace();
        return bomInventoryReadService.getComponentDetail(tenant, componentId);
    }

    @GetMapping("/assets/{assetId}/cves")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<ApplicationCveResponse> getApplicationCves(@PathVariable UUID assetId) {
        Tenant tenant = workspaceService.getWorkspace();
        return bomInventoryReadService.getApplicationCves(tenant, assetId);
    }

    @GetMapping("/application-risk")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<ApplicationRiskResponse> getApplicationRisk() {
        Tenant tenant = workspaceService.getWorkspace();
        return bomInventoryReadService.getApplicationRisk(tenant);
    }

    @GetMapping("/dashboard")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public BomDashboardResponse getDashboard() {
        Tenant tenant = workspaceService.getWorkspace();
        return bomInventoryReadService.getDashboard(tenant);
    }

    @GetMapping("/support")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public BomSupportMatrixResponse getSupportMatrix() {
        return bomInventoryReadService.getSupportMatrix();
    }

    /**
     * GET /api/bom/inventory/{bomId}
     * Single BOM detail with up to 500 components.
     */
    @GetMapping("/inventory/{bomId}")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public BomDetailResponse getBomDetail(@PathVariable UUID bomId) {
        Tenant tenant = workspaceService.getWorkspace();
        return bomInventoryReadService.getDetail(tenant, bomId);
    }

    /**
     * GET /api/bom/inventory/{bomId}/cbom-assets
     * Cryptographic assets reported by one CBOM document, with their findings.
     */
    @GetMapping("/inventory/{bomId}/cbom-assets")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<CbomBomAssetResponse> getCbomAssets(@PathVariable UUID bomId) {
        Tenant tenant = workspaceService.getWorkspace();
        return bomInventoryReadService.getCbomAssets(tenant, bomId);
    }

    @GetMapping("/inventory/{bomId}/lineage")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<BomLineageItemResponse> getBomLineage(@PathVariable UUID bomId) {
        Tenant tenant = workspaceService.getWorkspace();
        return bomInventoryReadService.getLineage(tenant, bomId);
    }

    /**
     * DELETE /api/bom/inventory/{bomId}
     * Soft-delete a BOM record and deactivate its components.
     */
    @DeleteMapping("/inventory/{bomId}")
    @PreAuthorize("hasAnyRole('INVENTORY_ADMIN','TENANT_ADMIN','CREATOR')")
    public void deleteBom(@PathVariable UUID bomId) {
        Tenant tenant = workspaceService.getWorkspace();
        bomInventoryReadService.softDelete(tenant, bomId);
    }
}
