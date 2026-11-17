package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.dto.CatalogLegacyCompatibility;
import com.prototype.vulnwatch.dto.CatalogLegacyCompatibility.Gap;
import com.prototype.vulnwatch.repo.VulnerabilitySourceFilterConfigRepository;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.TreeSet;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CatalogLegacyCompatibilityService {
    private final WorkspaceService workspace;
    private final VulnerabilitySourceFilterConfigRepository repository;
    private final ObjectMapper mapper;

    public CatalogLegacyCompatibilityService(WorkspaceService workspace,
            VulnerabilitySourceFilterConfigRepository repository, ObjectMapper mapper) {
        this.workspace = workspace;
        this.repository = repository;
        this.mapper = mapper;
    }

    @Transactional(readOnly = true)
    public CatalogLegacyCompatibility inspect() {
        if (TenantContext.getCurrentTenantId() == null || TenantContext.isPlatformContext()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "An active tenant context is required");
        }
        var tenant = workspace.getWorkspace();
        var enabled = new TreeSet<>(IntelligenceSourceRegistry.SOURCES);
        var gaps = new ArrayList<Gap>();
        for (var config : repository.findAll()) {
            if (!tenant.getId().equals(config.getTenant().getId())) continue;
            String source = config.getSourceSystem() == null ? "" : config.getSourceSystem().trim().toLowerCase(Locale.ROOT);
            if (!IntelligenceSourceRegistry.SOURCES.contains(source)) {
                String canonical = IntelligenceSourceRegistry.setting(source);
                boolean knownAlias = IntelligenceSourceRegistry.SOURCES.contains(canonical);
                gaps.add(new Gap(source, List.of(), knownAlias ? "SOURCE_ALIAS_NOT_APPLIED" : "UNSUPPORTED_SOURCE",
                        knownAlias ? canonical : null));
                continue;
            }
            if (!config.isEnabledForCorrelation()) enabled.remove(source);
            String json = config.getFiltersJson();
            if (json == null || json.isBlank()) continue;
            try {
                JsonNode filters = mapper.readTree(json);
                if (filters == null || !filters.isObject()) {
                    gaps.add(new Gap(source, List.of(), "MALFORMED_FILTERS", null));
                } else if (!filters.isEmpty()) {
                    var fields = new TreeSet<String>();
                    filters.fieldNames().forEachRemaining(fields::add);
                    gaps.add(new Gap(source, List.copyOf(fields), "FILTER_NOT_REPRESENTABLE", null));
                }
            } catch (Exception invalid) {
                gaps.add(new Gap(source, List.of(), "MALFORMED_FILTERS", null));
            }
        }
        gaps.sort(java.util.Comparator.comparing(Gap::source).thenComparing(Gap::reason));
        return new CatalogLegacyCompatibility(List.copyOf(enabled), List.copyOf(gaps));
    }
}
