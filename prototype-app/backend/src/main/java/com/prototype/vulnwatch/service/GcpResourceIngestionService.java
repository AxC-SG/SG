package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.GcpInstanceRecord;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.GcpResourceRecord;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.InventoryResult;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CmdbInventorySyncResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import jakarta.persistence.EntityManager;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Turns one GCP project's discovery results into assets.
 *
 * <p>VMs become HOST assets with a CI record, and their VM Manager packages flow through
 * {@link CmdbIngestionService} exactly as SSM packages do for EC2, so they correlate to
 * vulnerabilities. Other resources become CLOUD_RESOURCE assets.
 *
 * <p>Stale handling follows the AWS rule: an asset is marked INACTIVE only when its resource type
 * was listed completely in this run, the listing returned at least one resource, and this asset
 * was not among them. A partial or failed listing never deactivates anything.
 */
@Service
public class GcpResourceIngestionService {

    private static final Logger LOG = LoggerFactory.getLogger(GcpResourceIngestionService.class);
    private static final int FLUSH_INTERVAL = 100;
    static final String PROVIDER = "gcp";

    private final AssetRepository assetRepository;
    private final CiRepository ciRepository;
    private final CmdbIngestionService cmdbIngestionService;
    private final ObjectMapper objectMapper;
    private final EntityManager entityManager;

    public GcpResourceIngestionService(
            AssetRepository assetRepository,
            CiRepository ciRepository,
            CmdbIngestionService cmdbIngestionService,
            ObjectMapper objectMapper,
            EntityManager entityManager
    ) {
        this.assetRepository = assetRepository;
        this.ciRepository = ciRepository;
        this.cmdbIngestionService = cmdbIngestionService;
        this.objectMapper = objectMapper;
        this.entityManager = entityManager;
    }

    public record IngestionResult(
            int assetsUpserted,
            int assetsMarkedInactive,
            int hostsWithPackages,
            int softwareInstancesCreated,
            int softwareInstancesUpdated,
            int inventoryComponentsCreated,
            int inventoryComponentsUpdated,
            int findingsGenerated
    ) {
        public static IngestionResult empty() {
            return new IngestionResult(0, 0, 0, 0, 0, 0, 0, 0);
        }
    }

    /**
     * @param completeTypes resource type keys whose listing was complete in this run; only these
     *                      are eligible for stale marking
     */
    @Transactional
    public IngestionResult ingestProject(
            Tenant tenant,
            String projectId,
            List<GcpInstanceRecord> instances,
            InventoryResult inventory,
            List<GcpResourceRecord> resources,
            Set<String> completeTypes,
            Instant runStartTime
    ) {
        Set<String> seen = new HashSet<>();
        Map<String, Integer> seenPerType = new HashMap<>();
        int upserted = 0;
        for (GcpInstanceRecord instance : instances) {
            Asset asset = upsertInstance(tenant, instance);
            seen.add(asset.getIdentifier());
            seenPerType.merge(GcpResourceTypes.COMPUTE_INSTANCE, 1, Integer::sum);
            flushPeriodically(++upserted);
        }
        for (GcpResourceRecord resource : resources) {
            Asset asset = upsertResource(tenant, resource);
            seen.add(asset.getIdentifier());
            seenPerType.merge(resource.resourceType(), 1, Integer::sum);
            flushPeriodically(++upserted);
        }
        entityManager.flush();

        PackageTotals packages = ingestPackages(tenant, instances, inventory);

        Set<String> staleEligible = new HashSet<>();
        for (String type : completeTypes) {
            if (seenPerType.getOrDefault(type, 0) > 0) {
                staleEligible.add(type);
            }
        }
        int inactive = markStale(projectId, staleEligible, seen, runStartTime);
        return new IngestionResult(upserted, inactive, packages.hosts, packages.created, packages.updated,
                packages.componentsCreated, packages.componentsUpdated, packages.findings);
    }

    // ── VMs ──────────────────────────────────────────────────────────────────────────────────

    private Asset upsertInstance(Tenant tenant, GcpInstanceRecord record) {
        String identifier = record.identifier();
        Asset asset = existing(tenant, identifier);
        asset.setIdentifier(identifier);
        asset.setType(AssetType.HOST);
        asset.setName(hasText(record.name()) ? record.name() : record.instanceId());
        asset.setCloudProvider(PROVIDER);
        asset.setCloudAccountId(record.projectId());
        asset.setCloudRegion(record.region());
        asset.setCloudAvailabilityZone(record.zone());
        asset.setCloudResourceType(GcpResourceTypes.COMPUTE_INSTANCE);
        asset.setCloudInstanceType(record.machineType());
        asset.setCloudVpcId(record.network());
        asset.setCloudSubnetId(record.subnetwork());
        asset.setCloudArn(identifier);
        asset.setCloudLaunchTime(record.createdAt());
        asset.setCloudTagsJson(record.labels().isEmpty() ? null : toJson(record.labels()));
        asset.setState(instanceState(record.status()));
        asset.setLastCmdbSyncAt(Instant.now());
        Asset saved = assetRepository.save(asset);
        upsertCi(tenant, saved);
        return saved;
    }

    /** HOST assets need a CI so the host inventory detail page can load, as for EC2. */
    private void upsertCi(Tenant tenant, Asset asset) {
        String sysId = asset.getIdentifier();
        Ci ci = ciRepository.findBySysId(sysId)
                .or(() -> asset.getId() == null ? Optional.empty() : ciRepository.findByAsset_Id(asset.getId()))
                .orElseGet(() -> {
                    Ci created = new Ci();
                    created.setTenant(tenant);
                    created.setAsset(asset);
                    return created;
                });
        ci.setSysId(sysId);
        ci.setAsset(asset);
        ci.setDisplayName(asset.getName());
        ci.setLastCmdbSyncAt(Instant.now());
        ci.touch();
        ciRepository.save(ci);
    }

    private PackageTotals ingestPackages(Tenant tenant, List<GcpInstanceRecord> instances, InventoryResult inventory) {
        PackageTotals totals = new PackageTotals();
        if (inventory == null) {
            return totals;
        }
        for (GcpInstanceRecord instance : instances) {
            List<Map<String, String>> packages = inventory.packagesByInstanceId().get(instance.instanceId());
            if (packages == null || packages.isEmpty()) {
                continue;
            }
            List<Map<String, String>> rows = new ArrayList<>(packages.size());
            String environment = instance.labels().getOrDefault("env", instance.labels().getOrDefault("environment", ""));
            for (Map<String, String> pkg : packages) {
                Map<String, String> row = new HashMap<>(pkg);
                row.put("hostname", instance.name());
                row.put("ci_sys_id", instance.identifier());
                row.put("environment", environment);
                rows.add(row);
            }
            try {
                CmdbInventorySyncResponse response = cmdbIngestionService.ingestRows(
                        tenant,
                        PROVIDER,
                        rows,
                        List.of(),
                        new CmdbIngestionService.HostInventorySourceDescriptor(
                                "gcp-os-inventory",
                                "gcp-vm-manager",
                                PROVIDER,
                                "osconfig.googleapis.com/Inventory",
                                "https://osconfig.googleapis.com",
                                "application/json",
                                null));
                totals.hosts++;
                totals.created += response.softwareInstancesCreated();
                totals.updated += response.softwareInstancesUpdated();
                totals.componentsCreated += response.inventoryComponentsCreated();
                totals.componentsUpdated += response.inventoryComponentsUpdated();
                totals.findings += response.findingsRecomputed();
            } catch (RuntimeException failure) {
                LOG.warn("GCP package ingestion failed for instance {}: {}", instance.instanceId(), failure.getMessage());
            }
        }
        return totals;
    }

    // ── Other resources ──────────────────────────────────────────────────────────────────────

    private Asset upsertResource(Tenant tenant, GcpResourceRecord record) {
        Asset asset = existing(tenant, record.name());
        asset.setIdentifier(record.name());
        asset.setType(AssetType.CLOUD_RESOURCE);
        asset.setName(hasText(record.displayName()) ? record.displayName() : lastSegment(record.name()));
        asset.setCloudProvider(PROVIDER);
        asset.setCloudAccountId(record.projectId());
        asset.setCloudRegion(record.location());
        asset.setCloudAvailabilityZone(null);
        asset.setCloudResourceType(record.resourceType());
        asset.setCloudInstanceType(null);
        asset.setCloudArn(record.name());
        asset.setCloudLaunchTime(record.createdAt());
        asset.setCloudTagsJson(record.labels().isEmpty() ? null : toJson(record.labels()));
        asset.setState(resourceState(record.state()));
        asset.setLastCmdbSyncAt(Instant.now());
        return assetRepository.save(asset);
    }

    // ── Stale handling ───────────────────────────────────────────────────────────────────────

    private int markStale(String projectId, Set<String> eligibleTypes, Set<String> seen, Instant runStartTime) {
        if (eligibleTypes.isEmpty()) {
            return 0;
        }
        List<Asset> stale = assetRepository.findAll().stream()
                .filter(a -> PROVIDER.equals(a.getCloudProvider()))
                .filter(a -> projectId.equals(a.getCloudAccountId()))
                .filter(a -> a.getCloudResourceType() != null && eligibleTypes.contains(a.getCloudResourceType()))
                .filter(a -> a.getLastCmdbSyncAt() != null && a.getLastCmdbSyncAt().isBefore(runStartTime))
                .filter(a -> a.getState() != AssetState.DECOMMISSIONED && a.getState() != AssetState.INACTIVE)
                .filter(a -> !seen.contains(a.getIdentifier()))
                .toList();
        for (Asset asset : stale) {
            asset.setState(AssetState.INACTIVE);
            assetRepository.save(asset);
        }
        if (!stale.isEmpty()) {
            LOG.info("Marked {} stale GCP assets INACTIVE (project={}, types={})", stale.size(), projectId, eligibleTypes);
        }
        return stale.size();
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    private Asset existing(Tenant tenant, String identifier) {
        return assetRepository.findByIdentifier(identifier).orElseGet(() -> {
            Asset created = new Asset();
            created.setTenant(tenant);
            created.setCloudProvider(PROVIDER);
            return created;
        });
    }

    static AssetState instanceState(String status) {
        if (status == null) return AssetState.ACTIVE;
        return switch (status.toUpperCase(Locale.ROOT)) {
            // GCE reports a stopped VM as TERMINATED; a deleted VM simply disappears from the list.
            case "STOPPING", "STOPPED", "SUSPENDING", "SUSPENDED", "TERMINATED" -> AssetState.INACTIVE;
            default -> AssetState.ACTIVE;
        };
    }

    static AssetState resourceState(String state) {
        if (state == null) return AssetState.ACTIVE;
        return switch (state.toUpperCase(Locale.ROOT)) {
            case "DELETING", "DELETED" -> AssetState.DECOMMISSIONED;
            case "STOPPED", "SUSPENDED", "INACTIVE", "DISABLED", "MAINTENANCE" -> AssetState.INACTIVE;
            default -> AssetState.ACTIVE;
        };
    }

    private void flushPeriodically(int count) {
        if (count % FLUSH_INTERVAL == 0) {
            entityManager.flush();
        }
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private static String lastSegment(String value) {
        int slash = value.lastIndexOf('/');
        return slash >= 0 ? value.substring(slash + 1) : value;
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static final class PackageTotals {
        int hosts;
        int created;
        int updated;
        int componentsCreated;
        int componentsUpdated;
        int findings;
    }
}
