package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.CatalogPolicy;
import com.prototype.vulnwatch.dto.CatalogPolicyVersionResponse;
import com.prototype.vulnwatch.service.CatalogPolicyVersionService;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/intelligence/catalog-policy/versions")
@PreAuthorize("hasRole('TENANT_ADMIN')")
public class CatalogPolicyVersionController {
    public record SaveRequest(Long expectedVersion, CatalogPolicy policy) {}
    private final CatalogPolicyVersionService service;
    public CatalogPolicyVersionController(CatalogPolicyVersionService service) { this.service = service; }
    @GetMapping public List<CatalogPolicyVersionResponse> list() { return service.list(); }
    @PostMapping public CatalogPolicyVersionResponse save(@RequestBody SaveRequest request) {
        if (request == null) throw new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.BAD_REQUEST, "Save request is required");
        return service.save(request.expectedVersion(), request.policy());
    }
}
