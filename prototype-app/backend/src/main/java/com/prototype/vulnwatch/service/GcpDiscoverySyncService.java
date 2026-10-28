package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GcpDiscoveryClient;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.GcpInstanceRecord;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.GcpResourceRecord;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.InventoryResult;
import com.prototype.vulnwatch.client.GcpDiscoveryClient.ListResult;
import com.prototype.vulnwatch.client.GcpTokenSource;
import com.prototype.vulnwatch.domain.GcpDiscoveryConfig;
import com.prototype.vulnwatch.domain.GcpDiscoveryTarget;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.GcpDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.GcpDiscoveryTargetRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Admission, scheduling and execution of GCP Cloud Discovery runs.
 *
 * <p>Same contract as AWS discovery: the configuration row is the admission lock, one run is
 * active per tenant, work is a durable {@code GCP_DISCOVERY} ingestion job, and each project
 * target succeeds or fails on its own so one broken grant does not stop the rest.
 */
@Service
public class GcpDiscoverySyncService {

    public static final String SYNC_TYPE_GCP_DISCOVERY = "GCP_DISCOVERY";
    private static final Logger LOG = LoggerFactory.getLogger(GcpDiscoverySyncService.class);

    private final GcpDiscoveryConfigRepository configRepository;
    private final GcpDiscoveryTargetRepository targetRepository;
    private final GcpDiscoveryConfigService configService;
    private final GcpDiscoveryTargetService targetService;
    private final GcpDiscoveryClient client;
    private final GcpTokenSource tokens;
    private final GcpResourceIngestionService ingestion;
    private final SyncRunRepository syncRunRepository;
    private final ObjectMapper objectMapper;
    private final TransactionTemplate transactionTemplate;
    private final WorkspaceService workspaceService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final IngestionJobService jobs;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public GcpDiscoverySyncService(
            GcpDiscoveryConfigRepository configRepository,
            GcpDiscoveryTargetRepository targetRepository,
            GcpDiscoveryConfigService configService,
            GcpDiscoveryTargetService targetService,
            GcpDiscoveryClient client,
            GcpTokenSource tokens,
            GcpResourceIngestionService ingestion,
            SyncRunRepository syncRunRepository,
            ObjectMapper objectMapper,
            TransactionTemplate transactionTemplate,
            WorkspaceService workspaceService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            IngestionJobService jobs
    ) {
        this.configRepository = configRepository;
        this.targetRepository = targetRepository;
        this.configService = configService;
        this.targetService = targetService;
        this.client = client;
        this.tokens = tokens;
        this.ingestion = ingestion;
        this.syncRunRepository = syncRunRepository;
        this.objectMapper = objectMapper;
        this.transactionTemplate = transactionTemplate;
        this.workspaceService = workspaceService;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.jobs = jobs;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    // ── Admission ────────────────────────────────────────────────────────────────────────────

    public SyncTriggerResponse trigger() {
        Tenant tenant = workspaceService.getWorkspace();
        ClaimedRun claimed = jobs.withAdmission(tenant, () -> {
            GcpDiscoveryConfig config = configService.findConfig(tenant)
                    .orElseThrow(() -> new IllegalStateException("GCP Cloud Discovery connector is not configured"));
            ClaimedRun admitted = claimRunForConfig(config, "manual", true);
            if (!admitted.reusedActiveRun()) jobs.enqueueConnectorJob(tenant, IngestionJobService.JOB_TYPE_GCP_DISCOVERY,
                    admitted.configId(), admitted.runId(), "manual", null);
            return admitted;
        });
        return response(claimed, "GCP Cloud Discovery sync queued");
    }

    public SyncTriggerResponse triggerTarget(Tenant tenant, UUID targetId) {
        targetService.requireTarget(tenant, targetId);
        ClaimedRun claimed = jobs.withAdmission(tenant, () -> {
            // Re-read inside the admission transaction: the target's config is lazily loaded.
            GcpDiscoveryTarget target = targetRepository.findByIdAndTenant_Id(targetId, tenant.getId())
                    .orElseThrow(() -> new EntityNotFoundException("GCP discovery target not found"));
            ClaimedRun admitted = claimRunForConfig(target.getConfig(), "manual-target", true);
            if (!admitted.reusedActiveRun()) jobs.enqueueConnectorJob(tenant, IngestionJobService.JOB_TYPE_GCP_DISCOVERY,
                    admitted.configId(), admitted.runId(), "manual-target", targetId);
            return admitted;
        });
        return response(claimed, "GCP Cloud Discovery project sync queued");
    }

    private static SyncTriggerResponse response(ClaimedRun claimed, String queuedMessage) {
        if (!claimed.reusedActiveRun()) {
            return new SyncTriggerResponse(claimed.runId(), "queued", queuedMessage);
        }
        return new SyncTriggerResponse(claimed.runId(), "running", "GCP Cloud Discovery sync is already queued or running");
    }

    @Scheduled(zone = "UTC", cron = "0 */5 * * * *")
    public void runScheduledSyncs() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("gcp-discovery.run-scheduled-syncs")) {
            return;
        }
        List<ConfigRef> configs = TenantContext.runAsPlatform(() -> {
            List<ConfigRef> scheduled = new ArrayList<>();
            for (Tenant tenant : tenantService.listActiveTenants()) {
                tenantSchemaExecutionService.run(tenant, () -> {
                    configRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "gcp")
                            .filter(config -> config.isEnabled() && config.isAutoSyncEnabled())
                            .ifPresent(config -> scheduled.add(new ConfigRef(config.getId(), tenant.getId())));
                    return null;
                });
            }
            return scheduled;
        });
        for (ConfigRef ref : configs) {
            try {
                Tenant tenant = tenantService.resolveTenantUuid(ref.tenantId());
                jobs.withAdmission(tenant, () -> {
                    GcpDiscoveryConfig config = configRepository.findById(ref.configId()).orElse(null);
                    ClaimedRun claimed = config == null ? null : claimRunForConfig(config, "scheduled", false);
                    if (claimed != null) jobs.enqueueConnectorJob(tenant, IngestionJobService.JOB_TYPE_GCP_DISCOVERY,
                            claimed.configId(), claimed.runId(), "scheduled", null);
                    return null;
                });
            } catch (RuntimeException failure) {
                LOG.warn("Scheduled connector {} admission deferred", ref.configId());
            }
        }
    }

    @Transactional(readOnly = true)
    public boolean hasActiveRun() {
        Tenant tenant = workspaceService.getWorkspace();
        return !syncRunRepository.findActiveRunsByTenantAndSyncType(
                tenant.getId(), SYNC_TYPE_GCP_DISCOVERY, List.of("queued", "running")).isEmpty();
    }

    private ClaimedRun claimRunForConfig(GcpDiscoveryConfig config, String triggerMode, boolean allowReuseActiveRun) {
        // The configuration row is the admission lock, including when no run exists yet.
        config = configRepository.findByIdAndTenantIdForUpdate(config.getId(), config.getTenant().getId())
                .orElseThrow(() -> new EntityNotFoundException("GCP Cloud Discovery config not found"));
        boolean usable = config.isEnabled() && isBound(config);
        if ("scheduled".equals(triggerMode)) {
            if (!usable || !config.isAutoSyncEnabled() || !isDue(config)) {
                return null;
            }
        } else if (!usable) {
            throw new IllegalStateException("GCP Cloud Discovery connector is disabled or has no service account key");
        }
        UUID tenantId = config.getTenant().getId();
        Optional<SyncRun> active = syncRunRepository.findActiveRunsByTenantAndSyncType(
                tenantId, SYNC_TYPE_GCP_DISCOVERY, List.of("queued", "running")).stream().findFirst();
        if (active.isPresent()) {
            return allowReuseActiveRun ? new ClaimedRun(config.getId(), active.get().getId(), true) : null;
        }
        SyncRun run = new SyncRun();
        run.setTenant(config.getTenant());
        run.setSyncType(SYNC_TYPE_GCP_DISCOVERY);
        run.setRunScope("TENANT_INVENTORY");
        run.setStatus("queued");
        run.setMetadataJson(toJson(Map.of(
                "triggerMode", triggerMode,
                "sourceSystem", "gcp",
                "serviceAccount", config.getServiceAccountEmail() == null ? "" : config.getServiceAccountEmail())));
        run = syncRunRepository.save(run);
        return new ClaimedRun(config.getId(), run.getId(), false);
    }

    private boolean isBound(GcpDiscoveryConfig config) {
        return configService.hasCredential(config);
    }

    private boolean isDue(GcpDiscoveryConfig config) {
        SyncRun latest = syncRunRepository
                .findTopBySyncTypeIgnoreCaseAndTenant_IdOrderByStartedAtDesc(SYNC_TYPE_GCP_DISCOVERY, config.getTenant().getId())
                .orElse(null);
        if (latest == null) {
            return true;
        }
        Instant reference = latest.getCompletedAt() != null ? latest.getCompletedAt() : latest.getStartedAt();
        if (reference == null) {
            return true;
        }
        int minutes = config.getIntervalMinutes() == null ? 1440 : Math.max(60, config.getIntervalMinutes());
        return Duration.between(reference, Instant.now()).toMinutes() >= minutes;
    }

    // ── Execution ────────────────────────────────────────────────────────────────────────────

    public void executeQueuedRun(UUID tenantId, UUID configId, UUID runId, String triggerMode, UUID onlyTargetId) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            Instant runStart = Instant.now();
            markRun(runId, "running", null, Map.of("triggerMode", triggerMode, "state", "running", "sourceSystem", "gcp"));
            try {
                GcpDiscoveryConfig config = configRepository.findById(configId)
                        .orElseThrow(() -> new EntityNotFoundException("GCP Discovery config not found: " + configId));
                if (!tenantId.equals(config.getTenant().getId()) || !config.isEnabled()) {
                    throw new IllegalStateException("GCP connector is disabled or no longer matches the queued work");
                }
                String credentialJson = configService.credentialJson(config);
                List<GcpDiscoveryTarget> targets = targetRepository.findByConfigAndEnabledTrueOrderByProjectIdAsc(config).stream()
                        .filter(t -> onlyTargetId == null || onlyTargetId.equals(t.getId()))
                        .filter(t -> t.getTenant() != null && tenantId.equals(t.getTenant().getId()))
                        .toList();
                if (targets.isEmpty()) {
                    throw new IllegalStateException("No enabled GCP project targets to discover");
                }

                RunTotals totals = new RunTotals();
                List<Map<String, Object>> targetResults = new ArrayList<>();
                for (GcpDiscoveryTarget target : targets) {
                    TargetOutcome outcome = executeTarget(config, credentialJson, target, runStart);
                    totals.add(outcome);
                    targetResults.add(outcome.metadata());
                }
                finishRun(configId, runId, triggerMode, totals, targetResults, targets.size());
            } catch (Exception failure) {
                LOG.error("GCP Discovery run {} failed: {}", runId, failure.getMessage(), failure);
                markRun(runId, "failed", failure.getMessage(), Map.of("triggerMode", triggerMode, "state", "failed", "sourceSystem", "gcp"));
            }
            return null;
        });
    }

    private TargetOutcome executeTarget(GcpDiscoveryConfig config, String credentialJson, GcpDiscoveryTarget target,
                                        Instant runStart) {
        String projectId = target.getProjectId();
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("targetId", target.getId());
        metadata.put("projectId", projectId);
        try {
            String token = tokens.token(credentialJson);
            List<String> types = targetService.resourceTypes(target);
            Map<String, String> errors = new LinkedHashMap<>();
            Set<String> completeTypes = new HashSet<>();

            List<GcpInstanceRecord> instances = List.of();
            InventoryResult inventory = null;
            if (types.contains(GcpResourceTypes.COMPUTE_INSTANCE)) {
                ListResult<GcpInstanceRecord> listed = client.listInstances(token, projectId);
                instances = listed.records();
                errors.putAll(listed.errors());
                if (listed.complete()) completeTypes.add(GcpResourceTypes.COMPUTE_INSTANCE);
                Set<String> zones = new LinkedHashSet<>();
                instances.forEach(instance -> zones.add(instance.zone()));
                inventory = client.listInventories(token, projectId, zones);
                inventory.errors().forEach((zone, message) -> errors.put("packages " + zone, message));
            }

            Map<String, List<String>> assetTypes = GcpResourceTypes.cloudAssetTypes(types);
            List<GcpResourceRecord> resources = List.of();
            if (!assetTypes.isEmpty()) {
                ListResult<GcpResourceRecord> searched = client.searchResources(token, projectId, assetTypes);
                resources = searched.records();
                errors.putAll(searched.errors());
                if (searched.complete()) completeTypes.addAll(assetTypes.keySet());
            }

            boolean nothingListed = instances.isEmpty() && resources.isEmpty()
                    && completeTypes.isEmpty() && !errors.isEmpty();
            if (nothingListed) {
                metadata.put("status", "failed");
                metadata.put("errors", errors);
                return TargetOutcome.failed(metadata, projectId + ": " + String.join("; ", errors.values()));
            }

            GcpResourceIngestionService.IngestionResult result = ingestion.ingestProject(
                    config.getTenant(), projectId, instances, inventory, resources, completeTypes, runStart);
            boolean warning = !errors.isEmpty();
            metadata.put("status", warning ? "completed_with_errors" : "completed");
            metadata.put("recordsFetched", instances.size() + resources.size());
            metadata.put("assetsUpserted", result.assetsUpserted());
            metadata.put("assetsMarkedInactive", result.assetsMarkedInactive());
            metadata.put("hostsWithPackages", result.hostsWithPackages());
            metadata.put("findingsGenerated", result.findingsGenerated());
            if (warning) metadata.put("errors", errors);
            Instant completedAt = Instant.now();
            transactionTemplate.executeWithoutResult(status -> targetRepository.findById(target.getId()).ifPresent(existing -> {
                existing.setLastSyncAt(completedAt);
                existing.touch();
                targetRepository.save(existing);
            }));
            return new TargetOutcome(instances.size() + resources.size(), false, warning, result, metadata,
                    warning ? projectId + ": " + String.join("; ", errors.values()) : null);
        } catch (Exception failure) {
            LOG.warn("GCP Discovery target {} failed: {}", projectId, failure.getMessage());
            metadata.put("status", "failed");
            metadata.put("error", failure.getMessage());
            return TargetOutcome.failed(metadata, projectId + ": " + failure.getMessage());
        }
    }

    private void finishRun(UUID configId, UUID runId, String triggerMode, RunTotals totals,
                           List<Map<String, Object>> targetResults, int targetCount) {
        boolean allFailed = totals.failedTargets == targetCount;
        String status = allFailed ? "failed" : "completed";
        transactionTemplate.executeWithoutResult(tx -> {
            SyncRun run = requireRun(runId);
            run.setStatus(status);
            run.setRecordsFetched(totals.fetched);
            run.setRecordsInserted(totals.result.assetsUpserted() + totals.result.inventoryComponentsCreated());
            run.setRecordsUpdated(totals.result.softwareInstancesUpdated() + totals.result.inventoryComponentsUpdated());
            run.setRecordsFailed(totals.failedTargets);
            run.setErrorMessage(totals.messages.isEmpty() ? null : truncate(String.join(" | ", totals.messages)));
            run.setCompletedAt(Instant.now());
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("triggerMode", triggerMode);
            metadata.put("sourceSystem", "gcp");
            metadata.put("assetType", "CLOUD");
            metadata.put("state", allFailed ? "failed" : totals.warningTargets > 0 || totals.failedTargets > 0
                    ? "completed_with_errors" : "completed");
            metadata.put("assetsIngested", totals.result.assetsUpserted());
            metadata.put("assetsMarkedInactive", totals.result.assetsMarkedInactive());
            metadata.put("hostsWithPackages", totals.result.hostsWithPackages());
            metadata.put("softwareInstancesCreated", totals.result.softwareInstancesCreated());
            metadata.put("findingsGenerated", totals.result.findingsGenerated());
            metadata.put("targets", targetResults);
            run.setMetadataJson(toJson(metadata));
            syncRunRepository.save(run);
            if (!allFailed) {
                configRepository.findById(configId).ifPresent(config -> {
                    config.setLastSyncAt(Instant.now());
                    configRepository.save(config);
                });
            }
        });
    }

    private void markRun(UUID runId, String status, String error, Map<String, Object> metadata) {
        transactionTemplate.executeWithoutResult(tx -> {
            SyncRun run = requireRun(runId);
            Map<String, Object> merged = readMetadata(run.getMetadataJson());
            merged.putAll(metadata);
            run.setStatus(status);
            run.setMetadataJson(toJson(merged));
            if ("failed".equals(status)) {
                run.setErrorMessage(error == null ? "GCP discovery failed" : truncate(error));
                run.setRecordsFailed(Math.max(1, run.getRecordsFailed()));
                run.setCompletedAt(Instant.now());
            }
            syncRunRepository.save(run);
        });
    }

    private SyncRun requireRun(UUID runId) {
        return syncRunRepository.findById(runId)
                .orElseThrow(() -> new EntityNotFoundException("Sync run not found: " + runId));
    }

    private Map<String, Object> readMetadata(String json) {
        try {
            return json == null ? new LinkedHashMap<>() : objectMapper.readValue(json, new TypeReference<LinkedHashMap<String, Object>>() { });
        } catch (Exception unreadable) {
            return new LinkedHashMap<>();
        }
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private static String truncate(String value) {
        return value.length() <= 2000 ? value : value.substring(0, 2000);
    }

    private record ClaimedRun(UUID configId, UUID runId, boolean reusedActiveRun) {}

    private record ConfigRef(UUID configId, UUID tenantId) {}

    private record TargetOutcome(
            int fetched,
            boolean failed,
            boolean warning,
            GcpResourceIngestionService.IngestionResult result,
            Map<String, Object> metadata,
            String message
    ) {
        static TargetOutcome failed(Map<String, Object> metadata, String message) {
            return new TargetOutcome(0, true, false, GcpResourceIngestionService.IngestionResult.empty(), metadata, message);
        }
    }

    private static final class RunTotals {
        int fetched;
        int failedTargets;
        int warningTargets;
        GcpResourceIngestionService.IngestionResult result = GcpResourceIngestionService.IngestionResult.empty();
        final List<String> messages = new ArrayList<>();

        void add(TargetOutcome outcome) {
            fetched += outcome.fetched();
            if (outcome.failed()) failedTargets++;
            if (outcome.warning()) warningTargets++;
            if (outcome.message() != null) messages.add(outcome.message());
            var r = outcome.result();
            result = new GcpResourceIngestionService.IngestionResult(
                    result.assetsUpserted() + r.assetsUpserted(),
                    result.assetsMarkedInactive() + r.assetsMarkedInactive(),
                    result.hostsWithPackages() + r.hostsWithPackages(),
                    result.softwareInstancesCreated() + r.softwareInstancesCreated(),
                    result.softwareInstancesUpdated() + r.softwareInstancesUpdated(),
                    result.inventoryComponentsCreated() + r.inventoryComponentsCreated(),
                    result.inventoryComponentsUpdated() + r.inventoryComponentsUpdated(),
                    result.findingsGenerated() + r.findingsGenerated());
        }
    }
}
