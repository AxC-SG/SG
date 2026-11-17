package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.PlatformVulnIntelDetailResponse;
import com.prototype.vulnwatch.dto.PlatformObservationPageResponse;
import com.prototype.vulnwatch.dto.CentralCatalogPageResponse;
import com.prototype.vulnwatch.dto.CentralCatalogCursorResponse;
import java.util.UUID;
import com.prototype.vulnwatch.dto.PlatformVulnRepoPageResponse;
import com.prototype.vulnwatch.dto.VulnRepoDashboardResponse;
import com.prototype.vulnwatch.service.PlatformVulnRepoService;
import java.util.Map;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/platform/vuln-repo")
@RequiredArgsConstructor
@PreAuthorize("hasRole('PLATFORM_OWNER')")
public class PlatformVulnRepoController {

    private final PlatformVulnRepoService platformVulnRepoService;

    @GetMapping("/records/cursor")
    public CentralCatalogCursorResponse scanCentralRecords(
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) String query,
            @RequestParam(required = false) Boolean inKev,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String source,
            @RequestParam(defaultValue = "ALL") CentralCatalogPageResponse.Kind kind,
            @RequestParam(defaultValue = "ACTIVE") CentralCatalogPageResponse.Status status,
            @RequestParam(required = false) String afterExternalId,
            @RequestParam(required = false) UUID afterId) {
        return platformVulnRepoService.scanCentralRecords(size, query, inKev, severity, source,
                kind, status, afterExternalId, afterId);
    }

    @GetMapping("/records")
    public CentralCatalogPageResponse listCentralRecords(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) String query,
            @RequestParam(required = false) Boolean inKev,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String source,
            @RequestParam(defaultValue = "ALL") CentralCatalogPageResponse.Kind kind,
            @RequestParam(defaultValue = "ACTIVE") CentralCatalogPageResponse.Status status) {
        return platformVulnRepoService.listCentralRecords(page, size, query, inKev, severity, source, kind, status);
    }

    @GetMapping("/dashboard")
    public VulnRepoDashboardResponse getDashboard() {
        return platformVulnRepoService.getDashboard();
    }

    @GetMapping("/vulnerabilities")
    public PlatformVulnRepoPageResponse listVulnerabilities(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) String query,
            @RequestParam(required = false) Boolean inKev,
            @RequestParam(required = false) String severity,
            @RequestParam(required = false) String source
    ) {
        return platformVulnRepoService.listVulnerabilities(page, size, query, inKev, severity, source);
    }

    @GetMapping("/source-stats")
    public Map<String, Object> getSourceStats() {
        return platformVulnRepoService.getSourceStats();
    }

    @GetMapping("/intel/{externalId}")
    public PlatformVulnIntelDetailResponse getIntelDetail(@PathVariable String externalId,
            @RequestParam(defaultValue = "true") boolean includeObservations) {
        return platformVulnRepoService.getIntelDetail(externalId, includeObservations);
    }

    @GetMapping("/intel/{externalId}/observations")
    public PlatformObservationPageResponse getIntelObservations(@PathVariable String externalId,
            @RequestParam(defaultValue = "25") int size,
            @RequestParam(required = false) UUID afterId) {
        return platformVulnRepoService.getIntelObservations(externalId, size, afterId);
    }
}
