package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.service.cbom.CbomEnterpriseService;
import com.prototype.vulnwatch.service.cbom.CbomGateService;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/** Enterprise governance (plan Milestone 5): CI gate policies, PQC migration campaigns and portfolio rollups. */
@RestController
@RequestMapping("/api/bom/cbom")
public class CbomEnterpriseController {
    private final WorkspaceService workspace;
    private final RequestActorService actors;
    private final CbomGateService gates;
    private final CbomEnterpriseService enterprise;

    public CbomEnterpriseController(WorkspaceService workspace, RequestActorService actors, CbomGateService gates,
            CbomEnterpriseService enterprise) {
        this.workspace = workspace; this.actors = actors; this.gates = gates; this.enterprise = enterprise;
    }

    @GetMapping("/governance/gate-policies")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST','READ_ONLY_AUDITOR')")
    public List<CbomGateService.GatePolicy> gatePolicies() {
        workspace.getWorkspace();
        return gates.policies();
    }

    @GetMapping("/governance/gate-policies/{environment}")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST','READ_ONLY_AUDITOR')")
    public CbomGateService.GatePolicy gatePolicy(@PathVariable String environment) {
        workspace.getWorkspace();
        return gates.policy(environment);
    }

    @PutMapping("/governance/gate-policies/{environment}")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("cbom.gate_policy.updated")
    public CbomGateService.GatePolicy saveGatePolicy(@PathVariable String environment, @RequestBody CbomGateService.GatePolicyRequest request) {
        workspace.getWorkspace();
        return gates.save(environment, request, actor());
    }

    @PostMapping("/pqc/campaigns")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    @SensitiveTenantAction("cbom.pqc_campaign.created")
    public CampaignDetailResponse createPqcCampaign(@RequestBody CbomEnterpriseService.PqcCampaignRequest request) {
        return enterprise.createPqcCampaign(workspace.getWorkspace(), request, actor());
    }

    @GetMapping("/pqc/progress")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST','INVENTORY_ADMIN','READ_ONLY_AUDITOR')")
    public CbomEnterpriseService.PqcProgress pqcProgress() {
        workspace.getWorkspace();
        return enterprise.pqcProgress();
    }

    @GetMapping("/portfolio")
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST','INVENTORY_ADMIN','READ_ONLY_AUDITOR')")
    public CbomEnterpriseService.Portfolio portfolio(@RequestParam(defaultValue = "department") String groupBy) {
        workspace.getWorkspace();
        return enterprise.portfolio(groupBy);
    }

    private String actor() {
        var actor = actors.currentActor();
        return actor == null ? "api" : actor.userId();
    }
}
