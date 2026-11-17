package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.CatalogBuildService;
import com.prototype.vulnwatch.service.CatalogActivationReadinessService;
import com.prototype.vulnwatch.service.CatalogBuildService.*;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

@RestController
@RequestMapping("/api/intelligence/catalog-policy/builds")
@PreAuthorize("hasRole('TENANT_ADMIN')")
public class CatalogBuildController {
    public record Create(UUID requestId, long policyVersion) {}
    private final CatalogBuildService service;
    private final CatalogActivationReadinessService readiness;
    public CatalogBuildController(CatalogBuildService service, CatalogActivationReadinessService readiness) {
        this.service=service; this.readiness=readiness;
    }
    @PostMapping public Build create(@RequestBody Create request) {
        if(request==null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Build request is required");
        return service.create(request.requestId(),request.policyVersion());
    }
    @GetMapping public List<Build> list() { return service.list(); }
    @GetMapping("/{id}") public Build get(@PathVariable UUID id) { return service.get(id); }
    @GetMapping("/{id}/members") public List<Member> members(@PathVariable UUID id,@RequestParam(required=false) UUID afterId) {
        return service.members(id,afterId);
    }
    @GetMapping("/{id}/finding-comparison") public FindingComparison compareFindings(@PathVariable UUID id) {
        return service.compareFindings(id);
    }
    @GetMapping("/{id}/org-cve-comparison") public OrgCveComparison compareOrgCveRecords(@PathVariable UUID id) {
        return service.compareOrgCveRecords(id);
    }
    @GetMapping("/{id}/org-cve-differences") public DifferencePage orgCveDifferences(@PathVariable UUID id,
            @RequestParam DifferenceDirection direction, @RequestParam(required=false) UUID afterId) {
        return service.orgCveDifferences(id,direction,afterId);
    }
    @GetMapping("/{id}/input-status") public InputStatus inputStatus(@PathVariable UUID id) { return service.inputStatus(id); }
    @GetMapping("/{id}/activation-readiness") public CatalogActivationReadinessService.Review activationReadiness(@PathVariable UUID id) {
        return readiness.inspect(id);
    }
    @PostMapping("/{id}/cancel") public Build cancel(@PathVariable UUID id) { return service.cancel(id); }
}
