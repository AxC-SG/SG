package com.prototype.vulnwatch.service.cmdbingestion;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.DiscoveryModel;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.SbomIngestionStatus;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.SoftwareInstance;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CmdbInventorySyncResponse;
import com.prototype.vulnwatch.service.AssetLifecycleService;
import com.prototype.vulnwatch.service.CiResolutionService;
import com.prototype.vulnwatch.service.CmdbIngestionService;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.HostSoftwareNormalizationService;
import com.prototype.vulnwatch.service.InventoryComponentCpeMappingService;
import com.prototype.vulnwatch.service.SoftwareIdentityService;
import com.prototype.vulnwatch.service.SoftwareIdentitySummaryProjectionService;
import com.prototype.vulnwatch.service.SoftwareInventorySyncService;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class CmdbInventoryIngestionRunner {

    private static final int INGEST_FLUSH_INTERVAL = 250;

    private final HostSoftwareNormalizationService hostSoftwareNormalizationService;
    private final SoftwareIdentityService softwareIdentityService;
    private final CiResolutionService ciResolutionService;
    private final InventoryComponentCpeMappingService inventoryComponentCpeMappingService;
    private final SoftwareInventorySyncService softwareInventorySyncService;
    private final FindingDeltaQueueService findingDeltaQueueService;
    private final AssetLifecycleService assetLifecycleService;
    private final SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService;
    private final EntityManager entityManager;
    private final CmdbHostInventorySupportService supportService;

    public CmdbInventoryIngestionRunner(
            HostSoftwareNormalizationService hostSoftwareNormalizationService,
            SoftwareIdentityService softwareIdentityService,
            CiResolutionService ciResolutionService,
            InventoryComponentCpeMappingService inventoryComponentCpeMappingService,
            SoftwareInventorySyncService softwareInventorySyncService,
            FindingDeltaQueueService findingDeltaQueueService,
            AssetLifecycleService assetLifecycleService,
            SoftwareIdentitySummaryProjectionService softwareIdentitySummaryProjectionService,
            EntityManager entityManager,
            CmdbHostInventorySupportService supportService
    ) {
        this.hostSoftwareNormalizationService = hostSoftwareNormalizationService;
        this.softwareIdentityService = softwareIdentityService;
        this.ciResolutionService = ciResolutionService;
        this.inventoryComponentCpeMappingService = inventoryComponentCpeMappingService;
        this.softwareInventorySyncService = softwareInventorySyncService;
        this.findingDeltaQueueService = findingDeltaQueueService;
        this.assetLifecycleService = assetLifecycleService;
        this.softwareIdentitySummaryProjectionService = softwareIdentitySummaryProjectionService;
        this.entityManager = entityManager;
        this.supportService = supportService;
    }

    public CmdbInventorySyncResponse ingestRows(
            Tenant tenant,
            String sourceSystem,
            List<Map<String, String>> installRowValues,
            List<Map<String, String>> discoveryRowValues,
            CmdbIngestionService.HostInventorySourceDescriptor sourceDescriptor
    ) {
        List<CmdbHostInventorySupportService.ImportedRow> installRows = supportService.toImportedRows(installRowValues);
        List<CmdbHostInventorySupportService.ImportedRow> discoveryRows = supportService.toImportedRows(discoveryRowValues);
        return ingestParsedRows(tenant, sourceSystem, installRows, discoveryRows, sourceDescriptor);
    }

    private CmdbInventorySyncResponse ingestParsedRows(
            Tenant tenant,
            String sourceSystem,
            List<CmdbHostInventorySupportService.ImportedRow> installRows,
            List<CmdbHostInventorySupportService.ImportedRow> discoveryRows,
            CmdbIngestionService.HostInventorySourceDescriptor sourceDescriptor
    ) {
        Instant now = Instant.now();
        String normalizedSource = supportService.normalizeSource(sourceSystem);
        Map<String, DiscoveryModel> discoveryModelsByKey = supportService.upsertDiscoveryModels(tenant, discoveryRows);
        Map<UUID, SbomUpload> uploadByAssetId = new HashMap<>();
        Map<UUID, Asset> changedAssetsById = new LinkedHashMap<>();
        Map<UUID, Set<String>> cpesByComponentId = new LinkedHashMap<>();
        Map<UUID, Integer> componentCountsByAssetId = new HashMap<>();
        List<InventoryComponent> touchedComponents = new ArrayList<>();
        List<CmdbHostInventorySupportService.ResolvedInstallRow> resolvedRows = new ArrayList<>();

        int unmatchedDiscoveryRows = 0;
        int ciCreated = 0;
        int ciAliasesCreated = 0;
        int softwareInstancesCreated = 0;
        int softwareInstancesUpdated = 0;
        int inventoryComponentsCreated = 0;
        int inventoryComponentsUpdated = 0;

        try {
            CiResolutionService.BatchResolutionContext resolutionContext = ciResolutionService.prepareBatchContext(
                    tenant,
                    normalizedSource,
                    installRows.stream()
                            .map(row -> new CiResolutionService.HostLookupInput(
                                    row.get("ci_sys_id", "installed_on_sys_id", "sys_id"),
                                    supportService.extractHostName(row)
                            ))
                            .toList()
            );

            int resolvedHostRows = 0;
            for (CmdbHostInventorySupportService.ImportedRow row : installRows) {
                String hostName = supportService.extractHostName(row);
                if (!supportService.hasText(hostName)) {
                    continue;
                }

                String discoveryKey = row.get(
                        "discovery_model_pk",
                        "discovery_model_primary_key",
                        "primary_key",
                        "discovery_model"
                );
                DiscoveryModel discoveryModel = supportService.hasText(discoveryKey)
                        ? discoveryModelsByKey.get(supportService.blankToNull(discoveryKey) == null
                                ? null
                                : discoveryKey.trim().toLowerCase())
                        : null;
                if (supportService.hasText(discoveryKey) && discoveryModel == null) {
                    unmatchedDiscoveryRows++;
                }

                BusinessCriticality businessCriticality = supportService.parseBusinessCriticality(
                        row.get("business_criticality", "criticality", "ci_criticality")
                );
                CiResolutionService.OwnershipDetails ownership = new CiResolutionService.OwnershipDetails(
                        row.get("owner_email", "owner",
                                "installed_on_owned_by_display_value", "owned_by_display_value",
                                "installed_on_owned_by", "owned_by"),
                        row.get("installed_on_managed_by_display_value", "managed_by_display_value",
                                "installed_on_managed_by", "managed_by"),
                        row.get("installed_on_department_display_value", "department_display_value",
                                "installed_on_department", "department"),
                        row.get("installed_on_support_group_display_value", "support_group_display_value",
                                "installed_on_support_group", "support_group"),
                        supportGroupSysId(row),
                        row.get("installed_on_assigned_to_display_value", "assigned_to_display_value",
                                "installed_on_assigned_to", "assigned_to")
                );
                CiResolutionService.Resolution ciResolution = ciResolutionService.resolve(
                        resolutionContext,
                        tenant,
                        row.get("ci_sys_id", "installed_on_sys_id", "sys_id"),
                        hostName,
                        row.get("environment", "env"),
                        ownership,
                        businessCriticality,
                        normalizedSource
                );
                Ci ci = ciResolution.ci();
                if (ciResolution.created()) {
                    ciCreated++;
                }
                if (ciResolution.aliasCreated()) {
                    ciAliasesCreated++;
                }
                resolvedRows.add(new CmdbHostInventorySupportService.ResolvedInstallRow(row, discoveryModel, ci));
                resolvedHostRows++;
                if (resolvedHostRows % INGEST_FLUSH_INTERVAL == 0) {
                    entityManager.flush();
                }
            }

            entityManager.flush();
            entityManager.clear();
            Map<UUID, Map<String, SoftwareInstance>> existingInstancesByCiId = supportService.preloadSoftwareInstances(tenant, resolvedRows);
            Map<UUID, Map<String, InventoryComponent>> existingComponentsByAssetId = supportService.preloadInventoryComponents(resolvedRows);

            for (int index = 0; index < resolvedRows.size(); index++) {
                CmdbHostInventorySupportService.ResolvedInstallRow resolved = resolvedRows.get(index);
                CmdbHostInventorySupportService.ImportedRow row = resolved.row();
                Ci ci = resolved.ci();
                Asset asset = ci.getAsset();
                DiscoveryModel discoveryModel = resolved.discoveryModel();
                String discoveryKey = row.get(
                        "discovery_model_pk",
                        "discovery_model_primary_key",
                        "primary_key",
                        "discovery_model"
                );

                HostSoftwareNormalizationService.NormalizedHostSoftware normalized = hostSoftwareNormalizationService.normalize(
                        row.get("display_name", "software", "name", "product_name"),
                        row.get("publisher", "manufacturer", "vendor"),
                        row.get("version", "display_version"),
                        supportService.preferredValue(row.get("normalized_product"), discoveryModel == null ? null : discoveryModel.getNormalizedProduct()),
                        supportService.preferredValue(row.get("normalized_publisher"), discoveryModel == null ? null : discoveryModel.getNormalizedPublisher()),
                        supportService.preferredValue(row.get("normalized_version"), discoveryModel == null ? null : discoveryModel.getNormalizedVersion()),
                        row.get("version_evidence", "msi_product_code", "package_id", "group_id")
                );
                String normalizedVersion = supportService.blankToNull(normalized.normalizedVersion());
                String normalizedEvidence = supportService.blankToNull(normalized.normalizedEvidence());
                Map<String, SoftwareInstance> instancesByKey = existingInstancesByCiId.computeIfAbsent(
                        ci.getId(),
                        ignored -> new LinkedHashMap<>()
                );
                String instanceKey = supportService.softwareInstanceKey(
                        normalized.normalizedProduct(),
                        normalizedVersion,
                        normalizedEvidence
                );
                SoftwareInstance instance = instancesByKey.get(instanceKey);
                boolean createdInstance = instance == null;
                if (createdInstance) {
                    instance = new SoftwareInstance();
                    instance.setTenant(tenant);
                    instance.setCi(ci);
                }
                instance.setDiscoveryModel(discoveryModel);
                instance.setDisplayName(supportService.preferredValue(
                        row.get("display_name", "software", "name", "product_name"),
                        normalized.rawDisplayName()
                ));
                instance.setPublisher(supportService.preferredValue(
                        row.get("publisher", "manufacturer", "vendor"),
                        normalized.rawPublisher()
                ));
                instance.setVersion(supportService.blankToNull(supportService.preferredValue(
                        row.get("version", "display_version"),
                        normalized.rawVersion()
                )));
                instance.setNormalizedPublisher(normalized.normalizedPublisher());
                instance.setNormalizedProduct(normalized.normalizedProduct());
                instance.setNormalizedVersion(normalizedVersion);
                instance.setInstallDate(supportService.parseInstant(row.get("install_date", "installed_at")));
                instance.setLastScanned(supportService.parseInstant(row.get("last_scanned", "last_discovered", "last_scan")));
                instance.setLastUsed(supportService.parseInstant(row.get("last_used")));
                instance.setActiveInstall(supportService.parseBoolean(row.get("active_install", "active"), true));
                instance.setUnlicensedInstall(supportService.parseBoolean(row.get("unlicensed_install"), false));
                instance.setDiscoveryModelPk(supportService.blankToNull(discoveryKey));
                instance.setVersionEvidence(normalizedEvidence);
                instance.setSourceSystem(normalizedSource);
                instance.touch();
                if (createdInstance) {
                    instance = supportService.saveSoftwareInstance(instance);
                    instancesByKey.put(instanceKey, instance);
                }

                SoftwareIdentityService.HostIdentityResolution identityResolution =
                        softwareIdentityService.resolveHostSoftwareIdentity(instance, discoveryModel, normalized, normalizedSource, false);
                instance.setSoftwareIdentity(identityResolution.identity());

                SbomUpload upload = uploadByAssetId.computeIfAbsent(
                        asset.getId(),
                        ignored -> supportService.createHostInventoryUpload(tenant, asset, normalizedSource, sourceDescriptor, now)
                );
                CmdbHostInventorySupportService.ComponentUpsertResult componentResult = supportService.upsertInventoryComponent(
                        asset,
                        upload,
                        normalized,
                        identityResolution.identity(),
                        instance.isActiveInstall(),
                        existingComponentsByAssetId,
                        now
                );
                instance.setInventoryComponent(componentResult.component());
                instance.touch();
                instance = supportService.saveSoftwareInstance(instance);
                instancesByKey.put(instanceKey, instance);

                if (createdInstance) {
                    softwareInstancesCreated++;
                } else {
                    softwareInstancesUpdated++;
                }
                if (componentResult.created()) {
                    inventoryComponentsCreated++;
                } else if (componentResult.updated()) {
                    inventoryComponentsUpdated++;
                }

                touchedComponents.add(componentResult.component());
                cpesByComponentId.computeIfAbsent(componentResult.component().getId(), ignored -> new LinkedHashSet<>())
                        .addAll(identityResolution.cpeCandidates());
                changedAssetsById.put(asset.getId(), asset);
                componentCountsByAssetId.merge(asset.getId(), 1, Integer::sum);
                if ((index + 1) % INGEST_FLUSH_INTERVAL == 0) {
                    entityManager.flush();
                    entityManager.clear();
                }
            }

            entityManager.flush();
            entityManager.clear();

            Map<UUID, InventoryComponent> uniqueComponents = new LinkedHashMap<>();
            for (InventoryComponent component : touchedComponents) {
                if (component != null && component.getId() != null) {
                    uniqueComponents.put(component.getId(), component);
                }
            }

            if (!uniqueComponents.isEmpty()) {
                inventoryComponentCpeMappingService.syncComponentMappings(uniqueComponents.values(), cpesByComponentId);
                softwareInventorySyncService.syncFromInventoryDelta(tenant, uniqueComponents.values(), now);
            }

            for (Asset asset : changedAssetsById.values()) {
                assetLifecycleService.markInventoryIngested(asset);
            }

            for (Map.Entry<UUID, SbomUpload> entry : uploadByAssetId.entrySet()) {
                SbomUpload upload = entry.getValue();
                upload.setComponentCount(componentCountsByAssetId.getOrDefault(entry.getKey(), 0));
                supportService.saveUpload(upload);
            }

            int findingsRecomputed = uniqueComponents.isEmpty()
                    || findingDeltaQueueService.usesIncrementalInventoryCorrelation(tenant.getId())
                    ? 0
                    : recomputeTouchedComponents(tenant, uniqueComponents.keySet());
            softwareIdentitySummaryProjectionService.refreshTenant(tenant);

            Instant completedAt = Instant.now();
            for (Map.Entry<UUID, SbomUpload> entry : uploadByAssetId.entrySet()) {
                SbomUpload upload = entry.getValue();
                upload.setStatus(SbomIngestionStatus.SUCCESS);
                upload.setFindingsGenerated(findingsRecomputed);
                upload.setEvidenceJson(supportService.buildHostUploadEvidence(
                        "SUCCESS",
                        normalizedSource,
                        sourceDescriptor.originalFilename(),
                        now,
                        completedAt,
                        componentCountsByAssetId.getOrDefault(entry.getKey(), 0),
                        findingsRecomputed,
                        null,
                        upload.getEvidenceJson(),
                        sourceDescriptor
                ));
                supportService.saveUpload(upload);
            }
            return new CmdbInventorySyncResponse(
                    normalizedSource,
                    installRows.size(),
                    discoveryRows.size(),
                    unmatchedDiscoveryRows,
                    uploadByAssetId.size(),
                    ciCreated,
                    ciAliasesCreated,
                    softwareInstancesCreated,
                    softwareInstancesUpdated,
                    inventoryComponentsCreated,
                    inventoryComponentsUpdated,
                    findingsRecomputed,
                    "CMDB host software sync completed"
            );
        } catch (RuntimeException ex) {
            supportService.markHostUploadsFailed(
                    uploadByAssetId.values(),
                    normalizedSource,
                    sourceDescriptor.originalFilename(),
                    now,
                    ex.getMessage(),
                    sourceDescriptor
            );
            throw ex;
        }
    }

    private int recomputeTouchedComponents(Tenant tenant, Collection<UUID> componentIds) {
        if (tenant == null || tenant.getId() == null || componentIds == null || componentIds.isEmpty()) {
            return 0;
        }

        List<UUID> orderedIds = componentIds.stream()
                .filter(id -> id != null)
                .distinct()
                .toList();
        if (orderedIds.isEmpty()) {
            return 0;
        }

        int findingsRecomputed = 0;
        for (int start = 0; start < orderedIds.size(); start += INGEST_FLUSH_INTERVAL) {
            int end = Math.min(start + INGEST_FLUSH_INTERVAL, orderedIds.size());
            findingsRecomputed += findingDeltaQueueService.enqueueSoftwareDeltas(
                    tenant.getId(),
                    orderedIds.subList(start, end),
                    "cmdb-ingestion"
            );
            entityManager.clear();
        }
        return findingsRecomputed;
    }

    /**
     * The support group's reference sys_id (Phase 0B §1.8). With {@code sysparm_display_value=all} the flattened row
     * carries it as {@code *_sys_id}; with raw values (an admin field list without display values) the field itself is
     * the sys_id. A display name is never taken for a sys_id.
     */
    static String supportGroupSysId(CmdbHostInventorySupportService.ImportedRow row) {
        for (String key : new String[] {"installed_on_support_group_sys_id", "support_group_sys_id",
                "installed_on_support_group", "support_group"}) {
            String sysId = CiResolutionService.sysIdOrNull(row.get(key));
            if (sysId != null) return sysId;
        }
        return null;
    }
}
