package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.CbomGovernanceDtos.*;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.service.cbom.CbomGovernanceService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/bom/cbom/governance")
public class CbomGovernanceController {
    private final WorkspaceService workspace;private final CbomGovernanceService governance;
    public CbomGovernanceController(WorkspaceService workspace,CbomGovernanceService governance){this.workspace=workspace;this.governance=governance;}
    @GetMapping("/rules") @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST','READ_ONLY_AUDITOR')")
    public RuleConfiguration rules(){return governance.configuration(workspace.getWorkspace());}
    @PostMapping("/rules/preview") @PreAuthorize("hasRole('TENANT_ADMIN')")
    public RuleImpactPreview preview(@RequestBody RuleConfigurationRequest request){return governance.preview(workspace.getWorkspace(),request);}
    @PutMapping("/rules") @PreAuthorize("hasRole('TENANT_ADMIN')") @SensitiveTenantAction("cbom.rules.updated")
    public RuleConfiguration update(@RequestBody RuleConfigurationRequest request){return governance.update(workspace.getWorkspace(),request);}
    @GetMapping("/pqc-readiness") @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST','READ_ONLY_AUDITOR')")
    public PqcReadiness pqc(){return governance.pqc(workspace.getWorkspace());}
    @PostMapping("/gates/evaluate") @PreAuthorize("hasAnyRole('TENANT_ADMIN','SECURITY_ANALYST')")
    public GateResult gate(@RequestBody GateRequest request){return governance.gate(workspace.getWorkspace(),request);}
}
