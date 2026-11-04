package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.CbomGraphResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.service.cbom.CbomContradictionService;
import com.prototype.vulnwatch.service.cbom.CbomEvidenceExpiryService;
import com.prototype.vulnwatch.service.cbom.CbomGraphService;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Relationships and blast radius (plan Milestone 4): bounded blast radius, contradiction review, evidence expiry. */
@RestController
@RequestMapping("/api/bom/cbom")
public class CbomRelationshipController {
    private final WorkspaceService workspace;
    private final RequestActorService actors;
    private final CbomGraphService graph;
    private final CbomContradictionService contradictions;
    private final CbomEvidenceExpiryService expiry;

    public CbomRelationshipController(WorkspaceService workspace, RequestActorService actors, CbomGraphService graph,
            CbomContradictionService contradictions, CbomEvidenceExpiryService expiry) {
        this.workspace = workspace; this.actors = actors; this.graph = graph; this.contradictions = contradictions; this.expiry = expiry;
    }

    @GetMapping("/blast-radius")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','READ_ONLY_AUDITOR')")
    public CbomGraphResponse.BlastRadius blastRadius(@RequestParam UUID componentId, @RequestParam(defaultValue = "3") int depth,
            @RequestParam(defaultValue = "500") int limit) {
        return graph.blastRadius(workspace.getWorkspace(), componentId, depth, limit);
    }

    @GetMapping("/contradictions")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','INVENTORY_ADMIN','TENANT_ADMIN','READ_ONLY_AUDITOR')")
    public List<CbomContradictionService.Contradiction> contradictions(@RequestParam(defaultValue = "OPEN") String status,
            @RequestParam(defaultValue = "100") int limit) {
        workspace.getWorkspace();
        return contradictions.list(status, limit);
    }

    @PostMapping("/contradictions/{contradictionId}/review")
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST','TENANT_ADMIN')")
    @SensitiveTenantAction("cbom.contradiction.reviewed")
    public CbomContradictionService.Contradiction review(@PathVariable UUID contradictionId,
            @RequestBody CbomContradictionService.ReviewRequest request) {
        workspace.getWorkspace();
        var actor = actors.currentActor();
        return contradictions.review(contradictionId, request, actor == null ? "api" : actor.userId());
    }

    /** Runs the evidence-expiry sweep for this workspace now (it also runs daily). */
    @PostMapping("/evidence-expiry/run")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("cbom.evidence_expiry.run")
    public CbomEvidenceExpiryService.TenantSweep runExpiry() {
        return expiry.sweep(workspace.getWorkspace());
    }
}
