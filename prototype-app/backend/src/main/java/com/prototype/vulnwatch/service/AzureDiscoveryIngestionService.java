package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AzureDiscoveryClient.AzureResourceRecord;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.AzureDiscoveryConfig;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import java.time.Instant;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AzureDiscoveryIngestionService {

    private static final Logger LOG = LoggerFactory.getLogger(AzureDiscoveryIngestionService.class);

    private final AssetRepository assetRepository;
    private final CiRepository ciRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final ObjectMapper objectMapper;

    public AzureDiscoveryIngestionService(
            AssetRepository assetRepository,
            CiRepository ciRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            ObjectMapper objectMapper
    ) {
        this.assetRepository = assetRepository;
        this.ciRepository = ciRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.objectMapper = objectMapper;
    }

    public record IngestionResult(int assetsUpserted, int assetsUpdated, int assetsMarkedInactive) {}

    private record CloudScope(String resourceType, String region) {}

    @Transactional
    public IngestionResult ingestAll(
            List<AzureResourceRecord> records,
            AzureDiscoveryConfig config,
            Tenant tenant,
            Instant runStartTime,
            String targetSubscriptionId
    ) {
        GenericAzureDiscoveryPolicy.requireAvailable();
        if (records == null || records.isEmpty()) {
            return new IngestionResult(0, 0, 0);
        }

        Set<String> seenResourceIdentifiers = new LinkedHashSet<>();
        Set<CloudScope> observedScopes = new HashSet<>();
        int assetsUpserted = 0;
        int assetsUpdated = 0;

        for (AzureResourceRecord record : records) {
            if (!hasText(record.resourceId())) {
                continue;
            }
            seenResourceIdentifiers.add(record.resourceId());
            observedScopes.add(scopeFor(record.resourceType(), record.location()));
            Asset asset = findExistingAsset(record.resourceId()).orElseGet(() -> {
                Asset created = new Asset();
                created.setTenant(tenant);
                created.setCloudProvider("azure");
                return created;
            });
            boolean isNew = asset.getId() == null;
            upsertAsset(asset, record, tenant);
            assetRepository.save(asset);
            if (AssetType.HOST.equals(asset.getType())) {
                upsertCi(record, asset, tenant);
            }
            if (isNew) {
                assetsUpserted++;
            } else {
                assetsUpdated++;
            }
        }

        int markedInactive = markStaleAssetsInactive(
                tenant, targetSubscriptionId, seenResourceIdentifiers, observedScopes, runStartTime);
        return new IngestionResult(assetsUpserted, assetsUpdated, markedInactive);
    }

    private void upsertAsset(Asset asset, AzureResourceRecord record, Tenant tenant) {
        asset.setTenant(tenant);
        asset.setIdentifier(record.resourceId());
        asset.setName(hasText(record.name()) ? record.name() : resourceName(record.resourceId()));
        asset.setType(mapAssetType(record.resourceType(), record.kind()));
        asset.setServiceName(hasText(record.kind()) ? record.kind() : record.resourceType());
        asset.setState(mapState(record.provisioningState()));
        asset.setCloudProvider("azure");
        asset.setCloudRegion(record.location());
        asset.setCloudAvailabilityZone(null);
        asset.setCloudAccountId(record.subscriptionId());
        asset.setCloudResourceType(record.resourceType());
        asset.setCloudInstanceType(record.kind());
        asset.setCloudVpcId(null);
        asset.setCloudSubnetId(null);
        asset.setCloudArn(record.resourceId());
        asset.setCloudLaunchTime(null);
        asset.setMissingIamInstanceProfile(false);
        asset.setSsmManaged(false);
        asset.setSsmInventoryAvailable(false);
        asset.setCloudTagsJson(toJson(record.tags()));
        asset.setLastInventoryAt(Instant.now());
        asset.setLastCmdbSyncAt(Instant.now());
    }

    private void upsertCi(AzureResourceRecord record, Asset asset, Tenant tenant) {
        String sysId = asset.getIdentifier();
        Ci ci = tenantSchemaExecutionService.run(tenant, () -> ciRepository.findBySysId(sysId)
                .or(() -> asset.getId() == null
                        ? Optional.empty()
                        : ciRepository.findByAsset_Id(asset.getId()))
                .orElseGet(() -> {
                    Ci c = new Ci();
                    c.setTenant(tenant);
                    c.setAsset(asset);
                    return c;
                }));
        ci.setSysId(sysId);
        ci.setAsset(asset);
        ci.setDisplayName(hasText(record.name()) ? record.name() : sysId);
        if (hasText(asset.getEnvironment())) {
            ci.setEnvironment(asset.getEnvironment());
        }
        if (asset.getBusinessCriticality() != null) {
            ci.setBusinessCriticality(asset.getBusinessCriticality());
        }
        if (hasText(asset.getOwnerTeam())) {
            ci.setManagedBy(asset.getOwnerTeam());
        }
        ci.setLastCmdbSyncAt(Instant.now());
        ci.touch();
        ciRepository.save(ci);
    }

    private int markStaleAssetsInactive(
            Tenant tenant,
            String targetSubscriptionId,
            Set<String> seenResourceIdentifiers,
            Set<CloudScope> observedScopes,
            Instant runStartTime
    ) {
        if (seenResourceIdentifiers == null || seenResourceIdentifiers.isEmpty() || !hasText(targetSubscriptionId)) {
            return 0;
        }
        List<Asset> candidates = assetRepository.findAll().stream()
                .filter(asset -> "azure".equalsIgnoreCase(asset.getCloudProvider()))
                .filter(asset -> asset.getTenant() != null && asset.getTenant().getId() != null
                        && tenant != null && tenant.getId() != null
                        && tenant.getId().equals(asset.getTenant().getId()))
                .filter(asset -> targetSubscriptionId.equals(asset.getCloudAccountId()))
                .filter(asset -> observedScopes.contains(scopeFor(asset.getCloudResourceType(), asset.getCloudRegion())))
                .filter(asset -> asset.getLastInventoryAt() != null && asset.getLastInventoryAt().isBefore(runStartTime))
                .filter(asset -> asset.getState() != AssetState.DECOMMISSIONED)
                .filter(asset -> !seenResourceIdentifiers.contains(asset.getIdentifier()))
                .toList();

        for (Asset stale : candidates) {
            stale.setState(AssetState.INACTIVE);
            assetRepository.save(stale);
        }
        if (!candidates.isEmpty()) {
            LOG.info("Marked {} stale Azure assets as INACTIVE", candidates.size());
        }
        return candidates.size();
    }

    private CloudScope scopeFor(String resourceType, String region) {
        return new CloudScope(normalizeScopeValue(resourceType), normalizeScopeValue(region));
    }

    private String normalizeScopeValue(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    private Optional<Asset> findExistingAsset(String identifier) {
        return assetRepository.findByIdentifier(identifier);
    }

    private AssetType mapAssetType(String resourceType, String kind) {
        String normalizedType = resourceType == null ? "" : resourceType.trim().toLowerCase(Locale.ROOT);
        String normalizedKind = kind == null ? "" : kind.trim().toLowerCase(Locale.ROOT);
        if (normalizedType.startsWith("microsoft.compute/virtualmachines")) {
            return AssetType.HOST;
        }
        if (normalizedType.startsWith("microsoft.web/sites")
                || normalizedType.startsWith("microsoft.cognitiveservices/accounts")
                || normalizedType.startsWith("microsoft.botservice/botservices")
                || normalizedType.startsWith("microsoft.machinelearningservices/workspaces")
                || normalizedType.startsWith("microsoft.search/searchservices")
                || normalizedKind.contains("app")) {
            return AssetType.APPLICATION;
        }
        return AssetType.CLOUD_RESOURCE;
    }

    private AssetState mapState(String cloudState) {
        if (cloudState == null) {
            return AssetState.ACTIVE;
        }
        String normalized = cloudState.trim().toLowerCase(Locale.ROOT);
        if (normalized.contains("delete") || normalized.contains("fail")) {
            return AssetState.DECOMMISSIONED;
        }
        if (normalized.contains("stop") || normalized.contains("dealloc") || normalized.contains("inactive")) {
            return AssetState.INACTIVE;
        }
        return AssetState.ACTIVE;
    }

    private String resourceName(String resourceId) {
        if (!hasText(resourceId)) {
            return "unknown";
        }
        int slash = resourceId.lastIndexOf('/');
        return slash >= 0 && slash + 1 < resourceId.length() ? resourceId.substring(slash + 1) : resourceId;
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
