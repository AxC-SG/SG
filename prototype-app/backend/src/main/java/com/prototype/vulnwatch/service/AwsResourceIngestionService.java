package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsDiscoveryClient.AwsResourceRecord;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.DescribeInstanceInformationRequest;
import software.amazon.awssdk.services.ssm.model.InstanceInformation;
import software.amazon.awssdk.services.ssm.model.ListInventoryEntriesRequest;
import software.amazon.awssdk.services.ssm.model.ListInventoryEntriesResponse;
import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.Ci;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CmdbInventorySyncResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.CiRepository;
import jakarta.persistence.EntityManager;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Core ingestion service for AWS cloud resources. Upserts {@link Asset} records
 * with cloud metadata for EC2 compute instances.
 * <p>
 * EC2 instances with SSM-sourced package data are delegated to
 * {@link CmdbIngestionService} so they follow the same path as SCCM.
 */
@Service
public class AwsResourceIngestionService {

    private static final Logger LOG = LoggerFactory.getLogger(AwsResourceIngestionService.class);
    private static final int FLUSH_INTERVAL = 100;
    private static final int SSM_FETCH_WINDOW = 4;
    private static final int SSM_MAX_PAGES_PER_HOST = 100;
    private static final int SSM_MAX_APPLICATIONS_PER_HOST = 10_000;

    private final AssetRepository assetRepository;
    private final CiRepository ciRepository;
    private final CmdbIngestionService cmdbIngestionService;
    private final ObjectMapper objectMapper;
    private final EntityManager entityManager;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;

    private final Executor ssmExecutor;
    private final TransactionTemplate ssmMergeTransactions;

    public AwsResourceIngestionService(
            AssetRepository assetRepository,
            CiRepository ciRepository,
            CmdbIngestionService cmdbIngestionService,
            ObjectMapper objectMapper,
            EntityManager entityManager,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            @Qualifier("ssmInventoryExecutor") Executor ssmExecutor,
            TransactionTemplate ssmMergeTransactions
    ) {
        this.assetRepository = assetRepository;
        this.ciRepository = ciRepository;
        this.cmdbIngestionService = cmdbIngestionService;
        this.objectMapper = objectMapper;
        this.entityManager = entityManager;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.ssmExecutor = ssmExecutor;
        this.ssmMergeTransactions = ssmMergeTransactions;
    }

    public record IngestionResult(
            int assetsUpserted,
            int inventoryComponentsCreated,
            int inventoryComponentsUpdated,
            int assetsMarkedInactive
    ) {}

    public record SsmInventoryIngestionSummary(
            int assetsIngested,
            int softwareInstancesCreated,
            int softwareInstancesUpdated,
            int inventoryComponentsCreated,
            int inventoryComponentsUpdated,
            int findingsGenerated,
            int failedInstances
    ) {
        public SsmInventoryIngestionSummary(int assetsIngested, int softwareInstancesCreated, int softwareInstancesUpdated,
                int inventoryComponentsCreated, int inventoryComponentsUpdated, int findingsGenerated) {
            this(assetsIngested, softwareInstancesCreated, softwareInstancesUpdated, inventoryComponentsCreated,
                    inventoryComponentsUpdated, findingsGenerated, 0);
        }

        SsmInventoryIngestionSummary plus(SsmInventoryIngestionSummary other) {
            return new SsmInventoryIngestionSummary(assetsIngested + other.assetsIngested,
                    softwareInstancesCreated + other.softwareInstancesCreated,
                    softwareInstancesUpdated + other.softwareInstancesUpdated,
                    inventoryComponentsCreated + other.inventoryComponentsCreated,
                    inventoryComponentsUpdated + other.inventoryComponentsUpdated,
                    findingsGenerated + other.findingsGenerated, failedInstances + other.failedInstances);
        }
    }

    // ── Main entry point ────────────────────────────────────────────────────────────────────────

    @Transactional
    public IngestionResult ingestAll(
            List<AwsResourceRecord> records,
            AwsDiscoveryConfig config,
            Tenant tenant,
            Instant runStartTime
    ) {
        return ingestAll(records, config, tenant, runStartTime, config == null ? null : config.getAwsAccountId());
    }

    @Transactional
    public IngestionResult ingestAll(
            List<AwsResourceRecord> records,
            AwsDiscoveryConfig config,
            Tenant tenant,
            Instant runStartTime,
            String awsAccountId
    ) {
        if (records == null || records.isEmpty()) {
            return new IngestionResult(0, 0, 0, 0);
        }

        Set<String> seenResourceIdentifiers = new LinkedHashSet<>();
        Set<CloudScope> observedScopes = new HashSet<>();

        int assetsUpserted = 0;
        int componentsCreated = 0;
        int componentsUpdated = 0;
        int index = 0;

        for (AwsResourceRecord record : records) {
            if (!hasText(record.arn()) || !"EC2".equalsIgnoreCase(record.resourceType())) {
                continue;
            }
            String resourceIdentifier = canonicalResourceIdentifier(record, awsAccountId);
            seenResourceIdentifiers.add(resourceIdentifier);
            observedScopes.add(scopeFor(record.resourceType(), record.region()));

            Asset asset = upsertAsset(record, config, tenant, resourceIdentifier);
            assetsUpserted++;

            index++;
            if (index % FLUSH_INTERVAL == 0) {
                entityManager.flush();
                entityManager.clear();
            }
        }

        entityManager.flush();

        // Mark stale assets INACTIVE only inside scopes this run actually observed.
        int markedInactive = markStaleAssetsInactive(
                tenant,
                config,
                seenResourceIdentifiers,
                observedScopes,
                runStartTime,
                awsAccountId
        );

        return new IngestionResult(assetsUpserted, componentsCreated, componentsUpdated, markedInactive);
    }

    // ── Asset upsert ─────────────────────────────────────────────────────────────────────────────

    private Asset upsertAsset(
            AwsResourceRecord record,
            AwsDiscoveryConfig config,
            Tenant tenant,
            String resourceIdentifier
    ) {
        Asset asset = findExistingCloudAsset(tenant, record, resourceIdentifier)
                .orElseGet(() -> {
                    Asset a = new Asset();
                    a.setTenant(tenant);
                    a.setCloudProvider("aws");
                    a.setSsmManaged(false);
                    a.setSsmInventoryAvailable(false);
                    return a;
                });
        asset.setIdentifier(resourceIdentifier);

        asset.setType(AssetType.HOST);
        asset.setName(hasText(record.name()) ? record.name() : record.arn());

        // Cloud metadata
        asset.setCloudProvider("aws");
        asset.setCloudRegion(record.region());
        asset.setCloudAvailabilityZone(record.availabilityZone());
        asset.setCloudAccountId(hasText(record.accountId()) ? record.accountId()
                : config.getAwsAccountId());
        asset.setCloudResourceType(record.resourceType());
        asset.setCloudInstanceType(record.instanceType());
        asset.setCloudVpcId(record.vpcId());
        asset.setCloudSubnetId(record.subnetId());
        asset.setCloudArn(resourceIdentifier);
        asset.setCloudLaunchTime(record.launchTime());
        asset.setMissingIamInstanceProfile(!hasText(record.iamInstanceProfileArn()));

        // Serialize all tags to JSON
        if (record.tags() != null && !record.tags().isEmpty()) {
            asset.setCloudTagsJson(toJson(record.tags()));
        }

        // Map state
        asset.setState(mapState(record.state()));
        asset.setLastCmdbSyncAt(Instant.now());

        asset = assetRepository.save(asset);

        // EC2 instances are typed HOST and must have a Ci record so the
        // Host Inventory view can load their detail page.
        if (AssetType.HOST.equals(asset.getType())) {
            upsertCi(record, asset, tenant);
        }

        return asset;
    }

    private void upsertCi(AwsResourceRecord record, Asset asset, Tenant tenant) {
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
        if (hasText(asset.getEnvironment())) ci.setEnvironment(asset.getEnvironment());
        if (asset.getBusinessCriticality() != null) ci.setBusinessCriticality(asset.getBusinessCriticality());
        if (hasText(asset.getOwnerTeam())) ci.setManagedBy(asset.getOwnerTeam());
        ci.setLastCmdbSyncAt(Instant.now());
        ci.touch();
        ciRepository.save(ci);
    }

    // ── EC2 + SSM package ingestion ───────────────────────────────────────────────────────────────

    /**
     * For EC2 instances that are SSM-managed, fetch the installed package inventory via
     * AWS SSM and feed it into {@link CmdbIngestionService} exactly as SCCM does —
     * enabling full CPE-based vulnerability correlation for those instances.
     */
    public SsmInventoryIngestionSummary ingestEc2SsmPackages(
            List<AwsResourceRecord> ec2Records,
            AwsCredentialsProvider creds,
            List<String> regions,
            Tenant tenant,
            String awsAccountId
    ) {
        var total = new SsmInventoryIngestionSummary(0, 0, 0, 0, 0, 0);
        for (String region : regions) {
            var hosts = ec2Records.stream().filter(record -> "EC2".equals(record.resourceType())
                    && region.equals(record.region()) && hasText(extractInstanceId(record.arn()))).toList();
            if (hosts.isEmpty()) continue;
            int processed = 0;
            try (SsmClient ssm = openSsm(region, creds)) {
                for (int start = 0; start < hosts.size(); start += SSM_FETCH_WINDOW) {
                    var window = hosts.subList(start, Math.min(start + SSM_FETCH_WINDOW, hosts.size()));
                    var fetches = new ArrayList<CompletableFuture<SsmHostInventory>>(window.size());
                    window.forEach(host -> fetches.add(fetchAsync(ssm, host, awsAccountId)));
                    for (int index = 0; index < fetches.size(); index++) {
                        AwsResourceRecord host = window.get(index);
                        try {
                            SsmHostInventory inventory = fetches.get(index).join();
                            var merged = tenantSchemaExecutionService.run(tenant, () -> ssmMergeTransactions.execute(
                                    status -> mergeSsmHost(tenant, host, awsAccountId, inventory)));
                            total = total.plus(merged);
                        } catch (RuntimeException failure) {
                            total = total.plus(ssmFailures(1));
                            LOG.warn("SSM inventory incomplete for EC2 {}: {}", extractInstanceId(host.arn()),
                                    failure.getCause() == null ? failure.getClass().getSimpleName()
                                            : failure.getCause().getClass().getSimpleName());
                        }
                        processed++;
                    }
                }
            } catch (RuntimeException failure) {
                total = total.plus(ssmFailures(hosts.size() - processed));
                LOG.warn("SSM inventory could not finish in region {}: {}", region, failure.getClass().getSimpleName());
            }
        }
        return total;
    }

    SsmClient openSsm(String region, AwsCredentialsProvider credentials) {
        return SsmClient.builder().region(Region.of(region)).credentialsProvider(credentials)
                .overrideConfiguration(config -> config.apiCallTimeout(Duration.ofSeconds(30))
                        .apiCallAttemptTimeout(Duration.ofSeconds(10))).build();
    }

    private CompletableFuture<SsmHostInventory> fetchAsync(SsmClient ssm, AwsResourceRecord host, String awsAccountId) {
        try {
            return CompletableFuture.supplyAsync(() -> {
                String instanceId = extractInstanceId(host.arn());
                long deadline = System.nanoTime() + Duration.ofMinutes(2).toNanos();
                InstanceInformation info = describeSsmInstance(ssm, instanceId);
                var packages = info == null ? null : fetchSsmPackageRows(ssm, instanceId, host, awsAccountId, deadline);
                return new SsmHostInventory(info, packages);
            }, ssmExecutor);
        } catch (RejectedExecutionException saturated) {
            return CompletableFuture.failedFuture(saturated);
        }
    }

    private InstanceInformation describeSsmInstance(SsmClient ssm, String instanceId) {
        var response = ssm.describeInstanceInformation(DescribeInstanceInformationRequest.builder()
                .filters(software.amazon.awssdk.services.ssm.model.InstanceInformationStringFilter.builder()
                        .key("InstanceIds").values(instanceId).build()).build());
        InstanceInformation matched = response.instanceInformationList().stream()
                .filter(info -> instanceId.equals(info.instanceId())).findFirst().orElse(null);
        if (matched == null && hasText(response.nextToken())) {
            throw new IllegalStateException("SSM registration lookup was incomplete");
        }
        return matched;
    }

    private SsmPackageFetch fetchSsmPackageRows(SsmClient ssm, String instanceId, AwsResourceRecord host, String awsAccountId,
            long deadline) {
        var rows = new ArrayList<Map<String, String>>();
        Set<String> seenTokens = new HashSet<>();
        Instant capturedAt = null;
        String ciSysId = canonicalResourceIdentifier(host, awsAccountId);
        String nextToken = null;
        for (int pageNumber = 0; pageNumber < SSM_MAX_PAGES_PER_HOST; pageNumber++) {
            if (System.nanoTime() - deadline >= 0) throw new IllegalStateException("SSM host inventory exceeded its time budget");
            ListInventoryEntriesResponse page = ssm.listInventoryEntries(ListInventoryEntriesRequest.builder()
                    .instanceId(instanceId).typeName("AWS:Application").nextToken(nextToken).build());
            Instant pageCapture = parseInstant(page.captureTime());
            if (capturedAt == null) capturedAt = pageCapture;
            else if (pageCapture != null && !capturedAt.equals(pageCapture)) {
                throw new IllegalStateException("SSM capture changed during pagination");
            }
            if (page.entries().size() > SSM_MAX_APPLICATIONS_PER_HOST - rows.size()) {
                throw new IllegalStateException("SSM host inventory exceeded its application limit");
            }
            for (var item : page.entries()) {
                Map<String, String> row = new HashMap<>();
                row.put("hostname", host.name());
                row.put("ci_sys_id", ciSysId);
                row.put("display_name", item.getOrDefault("Name", ""));
                row.put("publisher", item.getOrDefault("Publisher", ""));
                row.put("version", item.getOrDefault("Version", ""));
                row.put("environment", host.tags() == null ? "" : host.tags().getOrDefault("Environment", ""));
                rows.add(row);
            }
            nextToken = page.nextToken();
            if (!hasText(nextToken)) return new SsmPackageFetch(rows, capturedAt);
            if (!seenTokens.add(nextToken)) throw new IllegalStateException("SSM repeated an inventory continuation token");
        }
        throw new IllegalStateException("SSM host inventory exceeded its page limit");
    }

    private SsmInventoryIngestionSummary mergeSsmHost(Tenant tenant, AwsResourceRecord host, String accountId,
            SsmHostInventory inventory) {
        String identifier = canonicalResourceIdentifier(host, accountId);
        InstanceInformation info = inventory.registration();
        SsmPackageFetch packages = inventory.packages();
        var existing = assetRepository.lockByIdentifier(identifier);
        Instant priorCapture = existing.map(Asset::getSsmInventoryLastCapturedAt).orElse(null);
        if (packages != null && priorCapture != null
                && (packages.captureTime() == null || packages.captureTime().isBefore(priorCapture))) {
            return new SsmInventoryIngestionSummary(0, 0, 0, 0, 0, 0);
        }

        boolean available = packages != null && !packages.rows().isEmpty();
        existing.ifPresent(asset -> {
            asset.setSsmManaged(info != null);
            asset.setSsmPingStatus(info == null ? null : info.pingStatusAsString());
            asset.setSsmLastPingAt(info == null ? null : info.lastPingDateTime());
            asset.setSsmInventoryAvailable(available);
            if (packages != null) asset.setSsmInventoryLastCapturedAt(packages.captureTime());
            assetRepository.save(asset);
        });
        if (!available) return new SsmInventoryIngestionSummary(0, 0, 0, 0, 0, 0);
        CmdbInventorySyncResponse response = cmdbIngestionService.ingestRows(tenant, "aws", packages.rows(), List.of(),
                new CmdbIngestionService.HostInventorySourceDescriptor("aws-ssm-inventory", "aws-ssm", "aws",
                        "AWS:Application", "https://ssm." + host.region() + ".amazonaws.com", "application/json", null));
        return new SsmInventoryIngestionSummary(response.assetsIngested(), response.softwareInstancesCreated(),
                response.softwareInstancesUpdated(), response.inventoryComponentsCreated(), response.inventoryComponentsUpdated(),
                response.findingsRecomputed());
    }

    private static SsmInventoryIngestionSummary ssmFailures(int count) {
        return new SsmInventoryIngestionSummary(0, 0, 0, 0, 0, 0, count);
    }

    private record SsmHostInventory(InstanceInformation registration, SsmPackageFetch packages) {}

    private String extractInstanceId(String arn) {
        if (!hasText(arn)) return null;
        int slash = arn.lastIndexOf('/');
        return slash >= 0 ? arn.substring(slash + 1) : null;
    }

    // ── Stale asset handling ──────────────────────────────────────────────────────────────────────

    private int markStaleAssetsInactive(
            Tenant tenant,
            AwsDiscoveryConfig config,
            Set<String> seenResourceIdentifiers,
            Set<CloudScope> observedScopes,
            Instant runStartTime,
            String targetAccountId
    ) {
        String awsAccountId = hasText(targetAccountId) ? targetAccountId : config.getAwsAccountId();
        if (!hasText(awsAccountId)) return 0;
        if (seenResourceIdentifiers == null || seenResourceIdentifiers.isEmpty()
                || observedScopes == null || observedScopes.isEmpty()) {
            return 0;
        }
        List<Asset> candidates = tenantSchemaExecutionService.run(tenant, () -> assetRepository.findAll()).stream()
                .filter(a -> "aws".equals(a.getCloudProvider()))
                .filter(a -> awsAccountId.equals(a.getCloudAccountId()))
                .filter(a -> observedScopes.contains(scopeFor(a.getCloudResourceType(), a.getCloudRegion())))
                .filter(a -> a.getLastCmdbSyncAt() != null && a.getLastCmdbSyncAt().isBefore(runStartTime))
                .filter(a -> a.getState() != AssetState.DECOMMISSIONED)
                .filter(a -> !seenResourceIdentifiers.contains(a.getIdentifier()))
                .toList();

        for (Asset stale : candidates) {
            stale.setState(AssetState.INACTIVE);
            assetRepository.save(stale);
        }
        if (!candidates.isEmpty()) {
            LOG.info("Marked {} stale AWS assets as INACTIVE (account={}, runStart={})",
                    candidates.size(), awsAccountId, runStartTime);
        }
        return candidates.size();
    }

    private Optional<Asset> findExistingCloudAsset(
            Tenant tenant,
            AwsResourceRecord record,
            String resourceIdentifier
    ) {
        Optional<Asset> exact = tenantSchemaExecutionService.run(tenant, () -> assetRepository.findByIdentifier(resourceIdentifier));
        if (exact.isPresent() || !hasText(record.arn()) || resourceIdentifier.equals(record.arn())) {
            return exact;
        }
        return tenantSchemaExecutionService.run(tenant, () -> assetRepository.findByIdentifier(record.arn()));
    }

    private String canonicalResourceIdentifier(AwsResourceRecord record, String fallbackAccountId) {
        if (record == null || !hasText(record.arn())) {
            return "";
        }
        if (!"EC2".equalsIgnoreCase(record.resourceType())) {
            return record.arn();
        }
        String accountId = hasText(record.accountId()) ? record.accountId().trim() : trimToNull(fallbackAccountId);
        if (!hasText(accountId)) {
            return record.arn();
        }
        String instanceId = extractInstanceId(record.arn());
        if (!hasText(instanceId)) {
            return record.arn();
        }
        String[] parts = record.arn().split(":", -1);
        String partition = parts.length > 1 && hasText(parts[1]) ? parts[1] : "aws";
        String region = hasText(record.region()) ? record.region().trim()
                : (parts.length > 3 && hasText(parts[3]) ? parts[3] : "");
        return "arn:" + partition + ":ec2:" + region + ":" + accountId + ":instance/" + instanceId;
    }

    private CloudScope scopeFor(String resourceType, String region) {
        return new CloudScope(normalizeScopeValue(resourceType), normalizeScopeValue(region));
    }

    private String normalizeScopeValue(String value) {
        return value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
    }

    // ── Mapping helpers ───────────────────────────────────────────────────────────────────────────

    private AssetState mapState(String cloudState) {
        if (cloudState == null) return AssetState.ACTIVE;
        return switch (cloudState.toLowerCase(Locale.ROOT)) {
            case "running", "available", "active", "in-service" -> AssetState.ACTIVE;
            case "stopped", "stopping", "inactive", "paused", "hibernated" -> AssetState.INACTIVE;
            case "terminated", "deleted", "deleting", "failed" -> AssetState.DECOMMISSIONED;
            default -> AssetState.ACTIVE;
        };
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

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private Instant parseInstant(String value) {
        if (!hasText(value)) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (Exception e) {
            return null;
        }
    }

    // ── Inner types ───────────────────────────────────────────────────────────────────────────────

    private record CloudScope(
            String resourceType,
            String region
    ) {}

    private record SsmPackageFetch(
            List<Map<String, String>> rows,
            Instant captureTime
    ) {}
}
