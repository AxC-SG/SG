package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.dto.CloudResourcePageResponse;
import com.prototype.vulnwatch.dto.CloudResourcePageResponse.FacetValue;
import com.prototype.vulnwatch.dto.CloudResourceResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.function.Function;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

/**
 * Read model for the Cloud Resources view: every asset carrying cloud metadata, whichever
 * connector discovered it. Tenant scoping comes from the request's tenant schema and RLS.
 */
@Service
public class CloudResourceService {

    static final int MAX_PAGE_SIZE = 200;

    private final AssetRepository assets;
    private final ObjectMapper objectMapper;

    public CloudResourceService(AssetRepository assets, ObjectMapper objectMapper) {
        this.assets = assets;
        this.objectMapper = objectMapper;
    }

    public record Filter(String provider, String accountId, String region, String resourceType, String state, String search) {}

    @Transactional(readOnly = true)
    public CloudResourcePageResponse search(Filter filter, int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.min(MAX_PAGE_SIZE, Math.max(1, size));
        Page<Asset> result = assets.searchCloudResources(
                lower(filter.provider()),
                blankToNull(filter.accountId()),
                blankToNull(filter.region()),
                upper(filter.resourceType()),
                state(filter.state()),
                filter.search() == null || filter.search().isBlank() ? null
                        : "%" + filter.search().trim().toLowerCase(Locale.ROOT).replace("%", "\\%").replace("_", "\\_") + "%",
                PageRequest.of(safePage, safeSize, Sort.by("cloudProvider", "cloudAccountId", "name", "id")));
        return new CloudResourcePageResponse(
                result.getContent().stream().map(this::toResponse).toList(),
                safePage,
                safeSize,
                result.getTotalElements(),
                result.getTotalPages(),
                facets());
    }

    private CloudResourcePageResponse.Facets facets() {
        List<Object[]> rows = assets.cloudResourceFacets();
        return new CloudResourcePageResponse.Facets(
                facet(rows, row -> (String) row[0]),
                facet(rows, row -> (String) row[1]),
                facet(rows, row -> (String) row[2]),
                facet(rows, row -> (String) row[3]),
                facet(rows, row -> row[4] == null ? null : row[4].toString()));
    }

    private static List<FacetValue> facet(List<Object[]> rows, Function<Object[], String> key) {
        Map<String, Long> counts = new TreeMap<>();
        for (Object[] row : rows) {
            String value = key.apply(row);
            if (value != null && !value.isBlank()) {
                counts.merge(value, ((Number) row[5]).longValue(), Long::sum);
            }
        }
        return counts.entrySet().stream()
                .map(entry -> new FacetValue(entry.getKey(), entry.getValue()))
                .sorted(Comparator.comparing(FacetValue::count).reversed().thenComparing(FacetValue::value))
                .toList();
    }

    private CloudResourceResponse toResponse(Asset asset) {
        return new CloudResourceResponse(
                asset.getId(),
                asset.getName(),
                asset.getIdentifier(),
                asset.getType() == null ? null : asset.getType().name(),
                asset.getState() == null ? null : asset.getState().name(),
                asset.getCloudProvider(),
                asset.getCloudAccountId(),
                asset.getCloudRegion(),
                asset.getCloudAvailabilityZone(),
                asset.getCloudResourceType(),
                asset.getCloudInstanceType(),
                asset.getCloudVpcId(),
                asset.getCloudSubnetId(),
                labels(asset.getCloudTagsJson()),
                asset.getCloudLaunchTime(),
                asset.getLastCmdbSyncAt());
    }

    private Map<String, String> labels(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<Map<String, String>>() { });
        } catch (Exception unreadable) {
            return Map.of();
        }
    }

    private static AssetState state(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return AssetState.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(BAD_REQUEST, "Unknown asset state: " + value);
        }
    }

    private static String lower(String value) {
        String trimmed = blankToNull(value);
        return trimmed == null ? null : trimmed.toLowerCase(Locale.ROOT);
    }

    private static String upper(String value) {
        String trimmed = blankToNull(value);
        return trimmed == null ? null : trimmed.toUpperCase(Locale.ROOT);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
