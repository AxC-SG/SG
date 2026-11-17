package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.CatalogPolicyPreview.*;
import com.prototype.vulnwatch.service.CatalogPolicyPreviewService;
import com.prototype.vulnwatch.service.CatalogLegacyCompatibilityService;
import com.prototype.vulnwatch.dto.CatalogLegacyCompatibility;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/intelligence/catalog-policy")
@PreAuthorize("hasRole('TENANT_ADMIN')")
public class CatalogPolicyPreviewController {
    private final CatalogPolicyPreviewService service;
    private final CatalogLegacyCompatibilityService legacyCompatibility;
    public CatalogPolicyPreviewController(CatalogPolicyPreviewService service,
            CatalogLegacyCompatibilityService legacyCompatibility) {
        this.service = service;
        this.legacyCompatibility = legacyCompatibility;
    }
    @PostMapping("/preview")
    public Response preview(@RequestBody Request request) { return service.preview(request); }
    @GetMapping("/legacy-compatibility")
    public CatalogLegacyCompatibility legacyCompatibility() { return legacyCompatibility.inspect(); }
}
