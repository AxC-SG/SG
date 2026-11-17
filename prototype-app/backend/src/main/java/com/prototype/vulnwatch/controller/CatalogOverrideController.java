package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.service.CatalogOverrideService;
import com.prototype.vulnwatch.service.CatalogOverrideService.*;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/intelligence/catalog-policy/overrides/{vulnerabilityId}")
@PreAuthorize("hasRole('TENANT_ADMIN')")
public class CatalogOverrideController {
    private final CatalogOverrideService service;
    public CatalogOverrideController(CatalogOverrideService service) { this.service = service; }
    @GetMapping public List<Entry> history(@PathVariable UUID vulnerabilityId, @RequestParam(required = false) Long beforeRevision) {
        return service.history(vulnerabilityId, beforeRevision);
    }
    @PostMapping public Entry change(@PathVariable UUID vulnerabilityId, @RequestBody Change change) {
        return service.change(vulnerabilityId, change);
    }
}
