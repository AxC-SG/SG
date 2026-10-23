package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.InventoryComponentCpeMapRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Service;

@Service
public class FindingRecomputeService {

    private final FindingAssetRecomputeService findingAssetRecomputeService;
    private final FindingComponentRecomputeService findingComponentRecomputeService;
    private final FindingCorrelationProjectionService findingCorrelationProjectionService;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final InventoryComponentRepository inventoryComponentRepository;
    private final InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final OrgCveRecordRepository orgCveRecordRepository;
    private final OrgCveRecordService orgCveRecordService;
    private final TenantWorkRunner tenantWorkRunner;

    public FindingRecomputeService(
            FindingAssetRecomputeService findingAssetRecomputeService,
            FindingComponentRecomputeService findingComponentRecomputeService,
            FindingCorrelationProjectionService findingCorrelationProjectionService,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            InventoryComponentRepository inventoryComponentRepository,
            InventoryComponentCpeMapRepository inventoryComponentCpeMapRepository,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            OrgCveRecordRepository orgCveRecordRepository,
            OrgCveRecordService orgCveRecordService,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.findingAssetRecomputeService = findingAssetRecomputeService;
        this.findingComponentRecomputeService = findingComponentRecomputeService;
        this.findingCorrelationProjectionService = findingCorrelationProjectionService;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.inventoryComponentRepository = inventoryComponentRepository;
        this.inventoryComponentCpeMapRepository = inventoryComponentCpeMapRepository;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.orgCveRecordService = orgCveRecordService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    @Transactional
    public int recomputeForAsset(Tenant tenant, Asset asset) {
        return findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(tenant.getId(),
                inventoryComponentRepository.findByAsset(asset).stream().map(com.prototype.vulnwatch.domain.InventoryComponent::getId).toList());
    }

    @Transactional
    public int recomputeForAssets(List<Asset> assets) {
        int count=0;
        for(Asset asset:assets) count+=recomputeForAsset(asset.getTenant(),asset);
        return count;
    }

    public int recomputeOnSoftwareDelta(UUID tenantId, UUID componentId) {
        if (tenantId == null || componentId == null) {
            return 0;
        }
        return recomputeOnSoftwareDeltaBatch(tenantId, List.of(componentId));
    }

    public int recomputeOnSoftwareDeltaBatch(UUID tenantId, Collection<UUID> componentIds) {
        if (tenantId == null || componentIds == null || componentIds.isEmpty()) {
            return 0;
        }
        return tenantWorkRunner.runScoped(
                tenantId,
                () -> findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(tenantId, componentIds)
        );
    }

    public int recomputeOnCveDelta(UUID vulnerabilityId) {
        if (vulnerabilityId == null) {
            return 0;
        }
        return recomputeOnCveDeltaBatch(List.of(vulnerabilityId));
    }

    public int recomputeOnCveDeltaBatch(Collection<UUID> vulnerabilityIds) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        if (scopedVulnerabilityIds.isEmpty()) {
            return 0;
        }
        Map<UUID, Set<UUID>> componentsByTenant = collectAffectedComponentsByTenant(scopedVulnerabilityIds);
        int total = 0;
        for (Map.Entry<UUID, Set<UUID>> entry : componentsByTenant.entrySet()) {
            total += tenantWorkRunner.runScoped(
                    entry.getKey(),
                    () -> findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(entry.getKey(), entry.getValue())
            );
        }
        refreshMetadataForTenantsWithoutComponentRecompute(scopedVulnerabilityIds, componentsByTenant.keySet());
        return total;
    }

    public int applyVexDelta(UUID tenantId, UUID vulnerabilityId) {
        return applyVexDelta(tenantId, vulnerabilityId, null);
    }

    public int applyVexDeltaForVulnerability(UUID vulnerabilityId, String sourceKey) {
        if (vulnerabilityId == null) {
            return 0;
        }
        return applyVexDeltaBatch(List.of(vulnerabilityId), sourceKey);
    }

    public int applyVexDeltaBatch(Collection<UUID> vulnerabilityIds, String sourceKey) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        if (scopedVulnerabilityIds.isEmpty()) {
            return 0;
        }
        Map<UUID, Set<UUID>> componentsByTenant = collectAffectedComponentsByTenant(scopedVulnerabilityIds);
        int total = 0;
        for (Map.Entry<UUID, Set<UUID>> entry : componentsByTenant.entrySet()) {
            total += tenantWorkRunner.runScoped(
                    entry.getKey(),
                    () -> findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(entry.getKey(), entry.getValue())
            );
        }
        refreshMetadataForTenantsWithoutComponentRecompute(scopedVulnerabilityIds, componentsByTenant.keySet());
        return total;
    }

    public int applyVexDelta(UUID tenantId, UUID vulnerabilityId, String sourceKey) {
        if (tenantId == null || vulnerabilityId == null) {
            return 0;
        }
        Set<UUID> affectedComponentIds = collectAffectedComponentsByTenant(List.of(vulnerabilityId))
                .getOrDefault(tenantId, Set.of());
        if (affectedComponentIds.isEmpty()) {
            return orgCveRecordService.refreshForTenantAndVulnerabilities(tenantId, List.of(vulnerabilityId));
        }
        return tenantWorkRunner.runScoped(
                tenantId,
                () -> findingComponentRecomputeService.recomputeOnSoftwareDeltaBatch(tenantId, affectedComponentIds)
        );
    }

    public int refreshMetadataForVulnerabilityBatch(Collection<UUID> vulnerabilityIds) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        if (scopedVulnerabilityIds.isEmpty()) {
            return 0;
        }
        int updated = 0;
        for (UUID tenantId : findTenantIdsForVulnerabilities(scopedVulnerabilityIds)) {
            updated += orgCveRecordService.refreshForTenantAndVulnerabilities(tenantId, scopedVulnerabilityIds);
        }
        return updated;
    }

    public int refreshLifecycleForComponents(UUID tenantId, Collection<UUID> componentIds) {
        if (tenantId == null) {
            return 0;
        }
        List<UUID> scopedComponentIds = normalizeIds(componentIds);
        if (scopedComponentIds.isEmpty()) {
            return 0;
        }
        return tenantWorkRunner.runScoped(tenantId, () -> {
            Set<UUID> vulnerabilityIds =
                    componentVulnerabilityStateRepository.findDistinctVulnerabilityIdsByTenantIdAndComponentIds(
                            tenantId,
                            scopedComponentIds
                    );
            if (vulnerabilityIds.isEmpty()) {
                return 0;
            }
            return orgCveRecordService.refreshForTenantAndVulnerabilities(tenantId, vulnerabilityIds);
        });
    }

    @Transactional(readOnly = true)
    public NotApplicableProjection projectNotApplicableByCorrelation(Tenant tenant) {
        return findingCorrelationProjectionService.projectNotApplicableByCorrelation(tenant);
    }

    private void refreshMetadataForTenantsWithoutComponentRecompute(
            Collection<UUID> vulnerabilityIds,
            Collection<UUID> recomputedTenantIds
    ) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        if (scopedVulnerabilityIds.isEmpty()) {
            return;
        }
        Set<UUID> tenantsNeedingMetadataRefresh = findTenantIdsForVulnerabilities(scopedVulnerabilityIds);
        if (recomputedTenantIds != null && !recomputedTenantIds.isEmpty()) {
            tenantsNeedingMetadataRefresh.removeAll(recomputedTenantIds);
        }
        for (UUID tenantId : tenantsNeedingMetadataRefresh) {
            orgCveRecordService.refreshForTenantAndVulnerabilities(tenantId, scopedVulnerabilityIds);
        }
    }

    private Map<UUID, Set<UUID>> collectAffectedComponentsByTenant(Collection<UUID> vulnerabilityIds) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        Map<UUID, Set<UUID>> componentsByTenant = new HashMap<>();
        if (scopedVulnerabilityIds.isEmpty()) {
            return componentsByTenant;
        }

        Set<UUID> cpeIds = vulnerabilityTargetRepository.findVulnerabilityCpeRows(
                        scopedVulnerabilityIds,
                        VulnerabilityTargetType.CPE
                ).stream()
                .map(VulnerabilityTargetRepository.VulnerabilityCpeRow::getCpeId)
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (!cpeIds.isEmpty()) {
            inventoryComponentCpeMapRepository.findDistinctTenantComponentRowsByCpeIds(cpeIds)
                    .forEach(row -> addComponentLookupRow(componentsByTenant, row.getTenantId(), row.getComponentId()));
        }

        Set<String> purlKeys = vulnerabilityTargetRepository
                .findByVulnerability_IdInAndTargetType(scopedVulnerabilityIds, VulnerabilityTargetType.PURL).stream()
                .map(VulnerabilityTarget::getNormalizedTargetKey)
                .filter(this::hasText)
                .map(String::trim)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        if (!purlKeys.isEmpty()) {
            inventoryComponentRepository.findDistinctTenantComponentRowsByNormalizedPurlIn(purlKeys)
                    .forEach(row -> addComponentLookupRow(componentsByTenant, row.getTenantId(), row.getComponentId()));
        }

        Set<String> coordKeys = vulnerabilityTargetRepository
                .findByVulnerability_IdInAndTargetType(scopedVulnerabilityIds, VulnerabilityTargetType.COORD).stream()
                .map(VulnerabilityTarget::getNormalizedTargetKey)
                .filter(this::hasText)
                .map(String::trim)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> advisoryKeys = vulnerabilityTargetRepository
                .findByVulnerability_IdInAndTargetType(scopedVulnerabilityIds, VulnerabilityTargetType.ADVISORY_PACKAGE).stream()
                .map(VulnerabilityTarget::getNormalizedTargetKey)
                .filter(this::hasText)
                .map(String::trim)
                .collect(Collectors.toCollection(LinkedHashSet::new));
        Set<String> allCoordKeys = new HashSet<>(coordKeys);
        allCoordKeys.addAll(advisoryKeys);
        if (!allCoordKeys.isEmpty()) {
            inventoryComponentRepository.findDistinctTenantComponentRowsByCoordKeyIn(allCoordKeys)
                    .forEach(row -> addComponentLookupRow(componentsByTenant, row.getTenantId(), row.getComponentId()));
        }

        componentVulnerabilityStateRepository.findDistinctTenantComponentRowsByVulnerabilityIds(scopedVulnerabilityIds)
                .forEach(row -> addComponentLookupRow(componentsByTenant, row.getTenantId(), row.getComponentId()));

        return componentsByTenant;
    }

    private Set<UUID> findTenantIdsForVulnerabilities(Collection<UUID> vulnerabilityIds) {
        List<UUID> scopedVulnerabilityIds = normalizeIds(vulnerabilityIds);
        if (scopedVulnerabilityIds.isEmpty()) {
            return Set.of();
        }
        Set<UUID> tenantIds = new LinkedHashSet<>();
        tenantIds.addAll(componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(scopedVulnerabilityIds));
        tenantIds.addAll(orgCveRecordRepository.findDistinctTenantIdsByVulnerabilityIds(scopedVulnerabilityIds));
        return tenantIds;
    }

    private List<UUID> normalizeIds(Collection<UUID> ids) {
        if (ids == null || ids.isEmpty()) {
            return List.of();
        }
        return ids.stream()
                .filter(Objects::nonNull)
                .collect(Collectors.toCollection(LinkedHashSet::new))
                .stream()
                .sorted(UUID::compareTo)
                .toList();
    }

    private void addComponentLookupRow(Map<UUID, Set<UUID>> componentsByTenant, UUID tenantId, UUID componentId) {
        if (tenantId == null || componentId == null) {
            return;
        }
        componentsByTenant.computeIfAbsent(tenantId, ignored -> new HashSet<>()).add(componentId);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
