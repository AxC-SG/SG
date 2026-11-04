package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.CbomSuppressionSettingsRequest;
import com.prototype.vulnwatch.dto.CbomSuppressionSettingsResponse;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.CbomSuppressionSettingsService;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/bom/cbom/suppression-settings")
public class CbomSuppressionSettingsController {
    private final CbomSuppressionSettingsService service;

    public CbomSuppressionSettingsController(CbomSuppressionSettingsService service) {
        this.service = service;
    }

    @GetMapping
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    public CbomSuppressionSettingsResponse get() {
        return service.get();
    }

    @PutMapping
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("cbom.suppression_settings.updated")
    public CbomSuppressionSettingsResponse update(@RequestBody CbomSuppressionSettingsRequest request) {
        return service.update(request);
    }
}
