package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.CiAlias;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.SoftwareInstance;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.InventoryComponentFilterValuesResponse;
import com.prototype.vulnwatch.dto.InventoryComponentPageResponse;
import com.prototype.vulnwatch.dto.InventoryComponentResponse;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.CiAliasRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SoftwareInstanceRepository;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class InventoryService {

    private static final String REVIEW_NEEDS_ANY = "NEEDS_REVIEW";
    private static final String REVIEW_MISSING_VERSION = "MISSING_VERSION";
    private static final String REVIEW_UNMAPPED_SOFTWARE = "UNMAPPED_SOFTWARE";
    private static final String REVIEW_LOW_CONFIDENCE_ALIAS = "LOW_CONFIDENCE_ALIAS";
    private static final String REVIEW_DISCOVERY_MODEL = "DISCOVERY_MODEL_REVIEW";

    private final InventoryComponentRepository inventoryComponentRepository;
    private final SoftwareInstanceRepository softwareInstanceRepository;
    private final CiRepository ciRepository;
    private final CiAliasRepository ciAliasRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;

    private com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter ownershipReads;

    /** Phase 0B §3.7: owner envelopes on component rows once CLOUD_BOM inventory reads are canonical. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setOwnershipReads(com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter ownershipReads) {
        this.ownershipReads = ownershipReads;
    }

    public InventoryService(
            InventoryComponentRepository inventoryComponentRepository,
            SoftwareInstanceRepository softwareInstanceRepository,
            CiRepository ciRepository,
            CiAliasRepository ciAliasRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository
    ) {
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.softwareInstanceRepository = softwareInstanceRepository;
        this.ciRepository = ciRepository;
        this.ciAliasRepository = ciAliasRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
    }

    @Transactional(readOnly = true)
    public InventoryComponentPageResponse listComponentsPage(
            Tenant tenant,
            List<AssetType> assetTypes,
            List<InventoryComponentStatus> componentStatuses,
            List<String> sourceSystems,
            List<String> ecosystems,
            List<String> reviewCategories,
            String query,
            int page,
            int size
    ) {
        return listComponentsPage(tenant, assetTypes, componentStatuses, sourceSystems, ecosystems, reviewCategories, query, null, null, page, size);
    }

    /**
     * As above, optionally filtered by the occurrence's live owner team and/or status (Phase 0B §3.7). The filter is
     * 409 while BOM ownership is not canonical, and 400 when more than
     * {@link com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter#MAX_OCCURRENCE_FILTER_IDS} rows match.
     */
    @Transactional(readOnly = true)
    public InventoryComponentPageResponse listComponentsPage(
            Tenant tenant,
            List<AssetType> assetTypes,
            List<InventoryComponentStatus> componentStatuses,
            List<String> sourceSystems,
            List<String> ecosystems,
            List<String> reviewCategories,
            String query,
            UUID ownerTeamId,
            String ownershipStatus,
            int page,
            int size
    ) {
        boolean ownerFilter = ownerTeamId != null || (ownershipStatus != null && !ownershipStatus.isBlank());
        List<UUID> ownerIds = ownerFilter && ownershipReads != null
                ? ownershipReads.occurrenceIds(com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.OccurrenceTable.INVENTORY_COMPONENTS,
                        ownerTeamId, ownershipStatus)
                : List.of();
        int safePage = Math.max(0, page);
        int safeSize = Math.min(200, Math.max(1, size));
        List<AssetType> normalizedAssetTypes = sanitizeEnumValues(assetTypes);
        List<InventoryComponentStatus> normalizedComponentStatuses = sanitizeEnumValues(componentStatuses);
        List<String> normalizedSourceSystems = normalizeValueList(sourceSystems, this::normalizeSourceSystem);
        List<String> normalizedEcosystems = normalizeValueList(ecosystems, this::normalizeExactValue);
        List<String> normalizedReviewCategories = normalizeReviewCategoryList(reviewCategories);
        String normalizedQueryPattern = buildQueryPattern(query);
        boolean applyReviewFilters = normalizedReviewCategories != null;
        boolean reviewNeedsAny = containsReviewCategory(normalizedReviewCategories, REVIEW_NEEDS_ANY);
        boolean reviewMissingVersion = containsReviewCategory(normalizedReviewCategories, REVIEW_MISSING_VERSION);
        boolean reviewUnmappedSoftware = containsReviewCategory(normalizedReviewCategories, REVIEW_UNMAPPED_SOFTWARE);
        boolean reviewLowConfidenceAlias = containsReviewCategory(normalizedReviewCategories, REVIEW_LOW_CONFIDENCE_ALIAS);
        boolean reviewDiscoveryModel = containsReviewCategory(normalizedReviewCategories, REVIEW_DISCOVERY_MODEL);
        Pageable pageable = PageRequest.of(safePage, safeSize, Sort.by(Sort.Direction.DESC, "lastObservedAt"));
        Page<InventoryComponent> componentPage = inventoryComponentRepository.findPageByFilters(
                tenant,
                normalizedAssetTypes,
                normalizedComponentStatuses,
                normalizedSourceSystems,
                normalizedEcosystems,
                applyReviewFilters,
                reviewNeedsAny,
                reviewMissingVersion,
                reviewUnmappedSoftware,
                reviewLowConfidenceAlias,
                reviewDiscoveryModel,
                HostInventoryReviewEvaluator.LOW_CONFIDENCE_ALIAS_THRESHOLD,
                normalizedQueryPattern,
                ownerFilter,
                ownerFilter ? ownerIds : List.of(new UUID(0L, 0L)),
                pageable
        );
        Map<UUID, ComponentVulnerabilitySummary> vulnerabilitySummaryByComponentId =
                buildComponentVulnerabilitySummaries(tenant, componentPage.getContent());
        Map<UUID, HostReviewSignals> hostReviewSignalsByComponentId = buildHostReviewSignals(tenant, componentPage.getContent());
        Map<UUID, com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary> owners = ownershipReads == null ? Map.of()
                : ownershipReads.forOccurrences(com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.OccurrenceTable.INVENTORY_COMPONENTS,
                        componentPage.getContent().stream().map(InventoryComponent::getId).toList());
        List<InventoryComponentResponse> items = componentPage.getContent().stream()
                .map(component -> toInventoryComponentResponse(
                        component,
                        hostReviewSignalsByComponentId.getOrDefault(component.getId(), HostReviewSignals.NONE),
                        vulnerabilitySummaryByComponentId.getOrDefault(component.getId(), ComponentVulnerabilitySummary.NONE),
                        owners.get(component.getId())
                ))
                .toList();
        return new InventoryComponentPageResponse(
                items,
                componentPage.getNumber(),
                componentPage.getSize(),
                componentPage.getTotalElements(),
                componentPage.getTotalPages()
        );
    }

    @Transactional(readOnly = true)
    public InventoryComponentFilterValuesResponse listComponentFilterValues(Tenant tenant) {
        LinkedHashSet<String> assetTypes = new LinkedHashSet<>();
        inventoryComponentRepository.findDistinctAssetTypesByTenant(tenant).stream()
                .filter(Objects::nonNull)
                .map(Enum::name)
                .forEach(assetTypes::add);
        for (AssetType assetType : AssetType.values()) {
            assetTypes.add(assetType.name());
        }

        LinkedHashSet<String> componentStatuses = new LinkedHashSet<>();
        inventoryComponentRepository.findDistinctComponentStatusesByTenant(tenant).stream()
                .filter(Objects::nonNull)
                .map(Enum::name)
                .forEach(componentStatuses::add);
        for (InventoryComponentStatus status : InventoryComponentStatus.values()) {
            componentStatuses.add(status.name());
        }

        LinkedHashSet<String> sourceSystems = new LinkedHashSet<>();
        inventoryComponentRepository.findDistinctSourceSystemsByTenant(tenant).stream()
                .filter(this::hasText)
                .map(this::normalizeSourceSystem)
                .forEach(sourceSystems::add);
        sourceSystems.add("api");
        sourceSystems.add("github");
        sourceSystems.add("servicenow");

        LinkedHashSet<String> ecosystems = new LinkedHashSet<>();
        inventoryComponentRepository.findDistinctEcosystemsByTenant(tenant).stream()
                .filter(this::hasText)
                .map(this::normalizeExactValue)
                .forEach(ecosystems::add);

        return new InventoryComponentFilterValuesResponse(
                sortByPreferredOrder(assetTypes, List.of("APPLICATION", "HOST", "CONTAINER_IMAGE")),
                sortByPreferredOrder(componentStatuses, List.of("ACTIVE", "RETIRED")),
                sourceSystems.stream().sorted().toList(),
                ecosystems.stream().sorted().toList()
        );
    }

    private InventoryComponentResponse toInventoryComponentResponse(
            InventoryComponent component,
            HostReviewSignals reviewSignals,
            ComponentVulnerabilitySummary vulnerabilitySummary,
            com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Summary owner
    ) {
        SbomUpload upload = component.getSbomUpload();
        SoftwareIdentity identity = component.getSoftwareIdentity();
        return new InventoryComponentResponse(
                component.getId(),
                component.getAsset().getId(),
                component.getAsset().getName(),
                component.getAsset().getIdentifier(),
                component.getAsset().getType().name(),
                component.getComponentStatus().name(),
                component.getEcosystem(),
                component.getPackageName(),
                component.getPackageGroup(),
                component.getLicense(),
                component.getScope(),
                component.getVersion(),
                component.getNormalizedName(),
                component.getNormalizedVersion(),
                component.getPurl(),
                component.getComponentDigest(),
                identity == null ? null : identity.getDisplayName(),
                vulnerabilitySummary.cveCount(),
                vulnerabilitySummary.impactedCveCount(),
                vulnerabilitySummary.cveIds(),
                upload == null ? null : upload.getIngestionSourceSystem(),
                upload == null ? null : upload.getIngestionSourceType(),
                upload == null ? null : upload.getSourceReference(),
                upload == null ? null : upload.getUploadedAt(),
                component.getLastObservedAt(),
                component.getRetiredAt(),
                reviewSignals.needsReview(),
                reviewSignals.reviewItemCount(),
                reviewSignals.missingVersion(),
                reviewSignals.unmappedSoftware(),
                reviewSignals.lowConfidenceAlias(),
                reviewSignals.discoveryModelReview(),
                component.getEolSlug(),
                component.getEolCycle(),
                component.getEolDate(),
                component.getIsEol(),
                component.getEolDate() != null
                        ? (int) java.time.temporal.ChronoUnit.DAYS.between(java.time.LocalDate.now(), component.getEolDate())
                        : null,
                owner
        );
    }

    private Map<UUID, ComponentVulnerabilitySummary> buildComponentVulnerabilitySummaries(
            Tenant tenant,
            List<InventoryComponent> components
    ) {
        if (tenant == null || tenant.getId() == null || components == null || components.isEmpty()) {
            return Map.of();
        }
        List<UUID> componentIds = components.stream()
                .map(InventoryComponent::getId)
                .filter(Objects::nonNull)
                .toList();
        if (componentIds.isEmpty()) {
            return Map.of();
        }

        Map<UUID, LinkedHashSet<String>> cveIdsByComponentId = new LinkedHashMap<>();
        Map<UUID, Set<UUID>> vulnerabilityIdsByComponentId = new LinkedHashMap<>();
        Map<UUID, Set<UUID>> impactedVulnerabilityIdsByComponentId = new LinkedHashMap<>();

        for (ComponentVulnerabilityStateRepository.ComponentVulnerabilitySummaryRow row
                : componentVulnerabilityStateRepository.findSummariesByTenantIdAndComponentIds(tenant.getId(), componentIds)) {
            if (row.getComponentId() == null || row.getVulnerabilityId() == null) {
                continue;
            }
            if (row.getApplicabilityState() != ApplicabilityState.APPLICABLE) {
                continue;
            }
            vulnerabilityIdsByComponentId
                    .computeIfAbsent(row.getComponentId(), ignored -> new LinkedHashSet<>())
                    .add(row.getVulnerabilityId());
            if (hasText(row.getExternalId())) {
                LinkedHashSet<String> cveIds = cveIdsByComponentId.computeIfAbsent(row.getComponentId(), ignored -> new LinkedHashSet<>());
                if (cveIds.size() < 3) {
                    cveIds.add(row.getExternalId());
                }
            }
            if (row.getImpactState() == ImpactState.IMPACTED || row.getImpactState() == ImpactState.NO_PATCH) {
                impactedVulnerabilityIdsByComponentId
                        .computeIfAbsent(row.getComponentId(), ignored -> new LinkedHashSet<>())
                        .add(row.getVulnerabilityId());
            }
        }

        Map<UUID, ComponentVulnerabilitySummary> summaryByComponentId = new LinkedHashMap<>();
        for (UUID componentId : componentIds) {
            Set<UUID> vulnerabilityIds = vulnerabilityIdsByComponentId.getOrDefault(componentId, Set.of());
            Set<UUID> impactedIds = impactedVulnerabilityIdsByComponentId.getOrDefault(componentId, Set.of());
            List<String> cveIds = new ArrayList<>(cveIdsByComponentId.getOrDefault(componentId, new LinkedHashSet<>()));
            summaryByComponentId.put(
                    componentId,
                    new ComponentVulnerabilitySummary(vulnerabilityIds.size(), impactedIds.size(), cveIds)
            );
        }
        return summaryByComponentId;
    }

    private Map<UUID, HostReviewSignals> buildHostReviewSignals(Tenant tenant, List<InventoryComponent> components) {
        if (tenant == null || tenant.getId() == null || components == null || components.isEmpty()) {
            return Map.of();
        }

        List<InventoryComponent> hostComponents = components.stream()
                .filter(component -> component.getId() != null)
                .filter(component -> component.getAsset() != null && component.getAsset().getType() == AssetType.HOST)
                .toList();
        if (hostComponents.isEmpty()) {
            return Map.of();
        }

        List<UUID> componentIds = hostComponents.stream().map(InventoryComponent::getId).toList();
        Map<UUID, List<SoftwareInstance>> softwareByComponentId = new LinkedHashMap<>();
        for (SoftwareInstance instance : softwareInstanceRepository.findByInventoryComponent_IdIn(componentIds)) {
            if (instance.getInventoryComponent() == null || instance.getInventoryComponent().getId() == null) {
                continue;
            }
            softwareByComponentId.computeIfAbsent(instance.getInventoryComponent().getId(), ignored -> new ArrayList<>()).add(instance);
        }

        List<UUID> assetIds = hostComponents.stream()
                .map(InventoryComponent::getAsset)
                .filter(Objects::nonNull)
                .map(asset -> asset.getId())
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        Map<UUID, UUID> ciIdByAssetId = new LinkedHashMap<>();
        List<UUID> ciIds = new ArrayList<>();
        for (Ci ci : ciRepository.findByAsset_IdIn(assetIds)) {
            if (ci.getAsset() == null || ci.getAsset().getId() == null || ci.getId() == null) {
                continue;
            }
            ciIdByAssetId.put(ci.getAsset().getId(), ci.getId());
            ciIds.add(ci.getId());
        }

        Map<UUID, List<CiAlias>> aliasesByCiId = new LinkedHashMap<>();
        if (!ciIds.isEmpty()) {
            for (CiAlias alias : ciAliasRepository.findByCi_IdIn(ciIds)) {
                if (alias.getCi() == null || alias.getCi().getId() == null) {
                    continue;
                }
                aliasesByCiId.computeIfAbsent(alias.getCi().getId(), ignored -> new ArrayList<>()).add(alias);
            }
        }

        Map<UUID, HostReviewSignals> signalsByComponentId = new LinkedHashMap<>();
        for (InventoryComponent component : hostComponents) {
            UUID ciId = component.getAsset() == null ? null : ciIdByAssetId.get(component.getAsset().getId());
            List<CiAlias> aliases = ciId == null ? List.of() : aliasesByCiId.getOrDefault(ciId, List.of());
            List<SoftwareInstance> softwareInstances = softwareByComponentId.getOrDefault(component.getId(), List.of());
            signalsByComponentId.put(component.getId(), summarizeHostReviewSignals(component, aliases, softwareInstances));
        }
        return signalsByComponentId;
    }

    private HostReviewSignals summarizeHostReviewSignals(
            InventoryComponent component,
            List<CiAlias> aliases,
            List<SoftwareInstance> softwareInstances
    ) {
        String componentSourceSystem = component.getSbomUpload() == null
                ? null
                : normalizeSourceSystemOrNull(component.getSbomUpload().getIngestionSourceSystem());

        int lowConfidenceAliasCount = (int) aliases.stream()
                .filter(alias -> sourceMatches(alias.getSourceSystem(), componentSourceSystem))
                .filter(HostInventoryReviewEvaluator::isLowConfidenceAlias)
                .count();
        int missingVersionCount = (int) softwareInstances.stream()
                .filter(instance -> sourceMatches(instance.getSourceSystem(), componentSourceSystem))
                .filter(HostInventoryReviewEvaluator::needsVersionReview)
                .count();
        int unmappedSoftwareCount = (int) softwareInstances.stream()
                .filter(instance -> sourceMatches(instance.getSourceSystem(), componentSourceSystem))
                .filter(HostInventoryReviewEvaluator::needsIdentityReview)
                .count();
        int discoveryModelReviewCount = (int) softwareInstances.stream()
                .filter(instance -> sourceMatches(instance.getSourceSystem(), componentSourceSystem))
                .filter(HostInventoryReviewEvaluator::needsDiscoveryModelReview)
                .count();
        int reviewItemCount = lowConfidenceAliasCount + missingVersionCount + unmappedSoftwareCount + discoveryModelReviewCount;
        return new HostReviewSignals(
                reviewItemCount > 0,
                reviewItemCount,
                missingVersionCount > 0,
                unmappedSoftwareCount > 0,
                lowConfidenceAliasCount > 0,
                discoveryModelReviewCount > 0
        );
    }

    private List<String> sortByPreferredOrder(Set<String> values, List<String> preferredOrder) {
        LinkedHashSet<String> remaining = new LinkedHashSet<>(values);
        List<String> sorted = new ArrayList<>();
        for (String preferredValue : preferredOrder) {
            if (remaining.remove(preferredValue)) {
                sorted.add(preferredValue);
            }
        }
        sorted.addAll(remaining.stream().sorted().toList());
        return sorted;
    }

    private String normalizeSourceSystem(String sourceSystem) {
        return sourceSystem.trim()
                .toLowerCase(Locale.ROOT)
                .replace('_', '-')
                .replace(' ', '-');
    }

    private String normalizeSourceSystemOrNull(String sourceSystem) {
        if (!hasText(sourceSystem)) {
            return null;
        }
        return HostInventoryReviewEvaluator.normalize(sourceSystem);
    }

    private String normalizeExactValue(String value) {
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeReviewCategory(String value) {
        return value.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
    }

    private String buildQueryPattern(String query) {
        if (query == null || query.isBlank()) {
            return null;
        }
        return "%" + query.trim().toLowerCase(Locale.ROOT) + "%";
    }

    private <T> List<T> sanitizeEnumValues(List<T> values) {
        if (values == null) {
            return null;
        }
        List<T> normalized = values.stream()
                .filter(Objects::nonNull)
                .distinct()
                .toList();
        return normalized.isEmpty() ? null : normalized;
    }

    private List<String> normalizeValueList(List<String> values, java.util.function.Function<String, String> normalizer) {
        if (values == null) {
            return null;
        }
        List<String> normalized = values.stream()
                .filter(this::hasText)
                .map(normalizer)
                .filter(this::hasText)
                .distinct()
                .toList();
        return normalized.isEmpty() ? null : normalized;
    }

    private List<String> normalizeReviewCategoryList(List<String> values) {
        if (values == null) {
            return null;
        }
        List<String> normalized = values.stream()
                .filter(this::hasText)
                .map(this::normalizeReviewCategory)
                .filter(this::isSupportedReviewCategory)
                .distinct()
                .toList();
        return normalized.isEmpty() ? null : normalized;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private boolean containsReviewCategory(Collection<String> reviewCategories, String value) {
        return reviewCategories != null && reviewCategories.contains(value);
    }

    private boolean isSupportedReviewCategory(String value) {
        if (!hasText(value)) {
            return false;
        }
        return REVIEW_NEEDS_ANY.equals(value)
                || REVIEW_MISSING_VERSION.equals(value)
                || REVIEW_UNMAPPED_SOFTWARE.equals(value)
                || REVIEW_LOW_CONFIDENCE_ALIAS.equals(value)
                || REVIEW_DISCOVERY_MODEL.equals(value);
    }

    private boolean sourceMatches(String rowSourceSystem, String componentSourceSystem) {
        return HostInventoryReviewEvaluator.sourceMatches(rowSourceSystem, componentSourceSystem);
    }

    private record HostReviewSignals(
            boolean needsReview,
            int reviewItemCount,
            boolean missingVersion,
            boolean unmappedSoftware,
            boolean lowConfidenceAlias,
            boolean discoveryModelReview
    ) {
        private static final HostReviewSignals NONE = new HostReviewSignals(false, 0, false, false, false, false);
    }

    private record ComponentVulnerabilitySummary(
            int cveCount,
            int impactedCveCount,
            List<String> cveIds
    ) {
        private static final ComponentVulnerabilitySummary NONE = new ComponentVulnerabilitySummary(0, 0, List.of());
    }
}
