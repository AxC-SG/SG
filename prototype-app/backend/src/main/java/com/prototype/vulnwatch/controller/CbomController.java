package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CbomComponentResponse;
import com.prototype.vulnwatch.dto.CbomPostureSummaryResponse;
import com.prototype.vulnwatch.dto.CbomRiskFindingResponse;
import com.prototype.vulnwatch.dto.CbomAssessmentResponse;
import com.prototype.vulnwatch.dto.CbomDiffResponse;
import com.prototype.vulnwatch.dto.CbomGraphResponse;
import com.prototype.vulnwatch.dto.IngestionJobAcceptedResponse;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.cbom.CbomAssessmentService;
import com.prototype.vulnwatch.service.cbom.CbomAssessmentReportService;
import com.prototype.vulnwatch.service.cbom.CbomDiffService;
import com.prototype.vulnwatch.service.cbom.CbomGraphService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.service.cbom.CbomReadService;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/bom/cbom")
public class CbomController {

    private final WorkspaceService workspaceService;
    private final CbomReadService cbomReadService;
    private final CbomAssessmentService cbomAssessmentService;
    private final IngestionJobService ingestionJobService;
    private final RequestActorService requestActorService;
    private final CbomDiffService cbomDiffService;
    private final CbomAssessmentReportService reportService;
    private final CbomGraphService graphService;
    private com.prototype.vulnwatch.service.cbom.CbomAssessmentBackfillService backfillService;
    private com.prototype.vulnwatch.service.cbom.CbomVisibilityService visibility;

    @org.springframework.beans.factory.annotation.Autowired
    public void setVisibility(com.prototype.vulnwatch.service.cbom.CbomVisibilityService value){this.visibility=value;}

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackfillService(com.prototype.vulnwatch.service.cbom.CbomAssessmentBackfillService value){this.backfillService=value;}

    public CbomController(WorkspaceService workspaceService, CbomReadService cbomReadService,
            CbomAssessmentService cbomAssessmentService,IngestionJobService ingestionJobService,RequestActorService requestActorService,
            CbomDiffService cbomDiffService,CbomAssessmentReportService reportService,CbomGraphService graphService) {
        this.workspaceService = workspaceService;
        this.cbomReadService = cbomReadService;
        this.cbomAssessmentService=cbomAssessmentService;
        this.ingestionJobService=ingestionJobService;
        this.requestActorService=requestActorService;
        this.cbomDiffService=cbomDiffService;
        this.reportService=reportService;
        this.graphService=graphService;
    }

    @GetMapping("/assessments")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<CbomAssessmentResponse> listAssessments(@RequestParam UUID bomId){return cbomAssessmentService.list(workspaceService.getWorkspace(),bomId);}

    @GetMapping("/assessments/{runId}")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public CbomAssessmentResponse getAssessment(@PathVariable UUID runId){return cbomAssessmentService.get(workspaceService.getWorkspace(),runId);}

    @PostMapping("/assessments/{bomId}")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','TENANT_ADMIN')")
    public IngestionJobAcceptedResponse requestAssessment(@PathVariable UUID bomId){
        var actor=requestActorService.currentActor();
        return ingestionJobService.enqueueCbomAssessmentJob(workspaceService.getWorkspace(),bomId,actor==null?"api":actor.userId());
    }

    @GetMapping("/assessment-backfill")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','TENANT_ADMIN')")
    public com.prototype.vulnwatch.service.cbom.CbomAssessmentBackfillService.BackfillStatus backfillStatus(){
        return backfillService.status(workspaceService.getWorkspace());
    }

    /** Enqueues assessment for active CBOM artifacts not yet assessed under the current rule package. Idempotent. */
    @PostMapping("/assessment-backfill")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    public com.prototype.vulnwatch.service.cbom.CbomAssessmentBackfillService.BackfillStart startBackfill(@RequestParam(required=false) Integer limit){
        var actor=requestActorService.currentActor();
        return backfillService.start(workspaceService.getWorkspace(),actor==null?"api":actor.userId(),limit);
    }

    @GetMapping("/diff")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public CbomDiffResponse diff(@RequestParam UUID fromBomId,@RequestParam UUID toBomId){return cbomDiffService.diff(workspaceService.getWorkspace(),fromBomId,toBomId);}

    @GetMapping("/graph")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR','READ_ONLY_AUDITOR')")
    public CbomGraphResponse graph(@RequestParam String startType,@RequestParam UUID startId,
            @RequestParam(defaultValue="1") int depth,@RequestParam(required=false) String relationshipType,
            @RequestParam(defaultValue="100") int limit){
        return graphService.traverse(workspaceService.getWorkspace(),startType,startId,depth,relationshipType,limit);
    }

    @GetMapping("/assessments/{runId}/report")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','TENANT_ADMIN','READ_ONLY_AUDITOR')")
    public ResponseEntity<byte[]> report(@PathVariable UUID runId,@RequestParam(defaultValue="json") String format){
        var report=reportService.generate(workspaceService.getWorkspace(),runId,format);
        return ResponseEntity.ok().header(HttpHeaders.CONTENT_TYPE,report.contentType())
                .header(HttpHeaders.CONTENT_DISPOSITION,"attachment; filename=\""+report.filename()+"\"")
                .header("X-Content-SHA256",report.checksum()).body(report.content());
    }

    @GetMapping("/overview")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','READ_ONLY_AUDITOR')")
    public com.prototype.vulnwatch.dto.CbomVisibilityDtos.Overview overview(){return visibility.overview(workspaceService.getWorkspace());}

    @GetMapping("/trends")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','READ_ONLY_AUDITOR')")
    public com.prototype.vulnwatch.dto.CbomVisibilityDtos.Trends trends(@RequestParam(defaultValue="90") int days){
        return visibility.trends(workspaceService.getWorkspace(),days);
    }

    /** Tenant-wide, server-paged crypto inventory with analyst filters. */
    @GetMapping("/inventory")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','READ_ONLY_AUDITOR')")
    public com.prototype.vulnwatch.dto.CbomVisibilityDtos.InventoryPage inventory(
            @RequestParam(required=false) String assetType,@RequestParam(required=false) String primitive,
            @RequestParam(required=false) String severity,@RequestParam(required=false) String evidenceState,
            @RequestParam(required=false) String custody,@RequestParam(required=false) String environment,
            @RequestParam(required=false) UUID assetId,@RequestParam(required=false) UUID bomId,
            @RequestParam(required=false) String q,@RequestParam(defaultValue="false") boolean includeInactive,
            @RequestParam(defaultValue="0") int page,@RequestParam(defaultValue="50") int size){
        return visibility.inventory(workspaceService.getWorkspace(),new com.prototype.vulnwatch.service.cbom.CbomVisibilityService.InventoryFilter(
                assetType,primitive,severity,evidenceState,custody,environment,assetId,bomId,q,includeInactive),page,size);
    }

    /** Evidence drawer: component, provenance, claims, explainable findings and relationships. */
    @GetMapping("/components/{componentId}")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','READ_ONLY_AUDITOR')")
    public com.prototype.vulnwatch.dto.CbomVisibilityDtos.ComponentDetail component(@PathVariable UUID componentId){
        return visibility.component(workspaceService.getWorkspace(),componentId);
    }

    @GetMapping("/posture")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<CbomPostureSummaryResponse> listPosture() {
        Tenant tenant = workspaceService.getWorkspace();
        return cbomReadService.listPosture(tenant);
    }

    @GetMapping("/posture/{assetId}")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public CbomPostureSummaryResponse getPosture(@PathVariable UUID assetId) {
        Tenant tenant = workspaceService.getWorkspace();
        return cbomReadService.getPosture(tenant, assetId);
    }

    @GetMapping("/components")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<CbomComponentResponse> listComponents(
            @RequestParam UUID assetId,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "100") int size
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return cbomReadService.listComponents(tenant, assetId, page, size);
    }

    @GetMapping("/findings")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','CREATOR','OPERATOR')")
    public List<CbomRiskFindingResponse> listFindings(
            @RequestParam UUID assetId,
            @RequestParam(required = false) String severity
    ) {
        Tenant tenant = workspaceService.getWorkspace();
        return cbomReadService.listFindings(tenant, assetId, severity);
    }

}
