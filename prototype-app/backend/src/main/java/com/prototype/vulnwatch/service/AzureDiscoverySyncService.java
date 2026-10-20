package com.prototype.vulnwatch.service;

import com.azure.core.credential.TokenCredential;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AzureCredentialProvider;
import com.prototype.vulnwatch.client.AzureDiscoveryClient;
import com.prototype.vulnwatch.client.AzureDiscoveryClient.AzureResourceFetchResult;
import com.prototype.vulnwatch.client.AzureDiscoveryClient.AzureResourceRecord;
import com.prototype.vulnwatch.domain.AzureDiscoveryConfig;
import com.prototype.vulnwatch.domain.AzureDiscoveryTarget;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.AzureDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AzureDiscoveryTargetRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.service.AzureDiscoveryIngestionService.IngestionResult;
import jakarta.persistence.EntityNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class AzureDiscoverySyncService {

    public static final String SYNC_TYPE_AZURE_DISCOVERY = "AZURE_DISCOVERY";
    private static final Logger LOG = LoggerFactory.getLogger(AzureDiscoverySyncService.class);

    private final AzureDiscoveryConfigRepository configRepository;
    private final AzureDiscoveryTargetRepository targetRepository;
    private final AzureDiscoveryConfigService configService;
    private final AzureDiscoveryTargetService azureDiscoveryTargetService;
    private final AzureDiscoveryClient azureDiscoveryClient;
    private final AzureDiscoveryIngestionService azureDiscoveryIngestionService;
    private final SyncRunRepository syncRunRepository;
    private final ObjectMapper objectMapper;
    private final TaskExecutor integrationQueueExecutor;
    private final TransactionTemplate transactionTemplate;
    private final WorkspaceService workspaceService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public AzureDiscoverySyncService(
            AzureDiscoveryConfigRepository configRepository,
            AzureDiscoveryTargetRepository targetRepository,
            AzureDiscoveryConfigService configService,
            AzureDiscoveryTargetService azureDiscoveryTargetService,
            AzureDiscoveryClient azureDiscoveryClient,
            AzureDiscoveryIngestionService azureDiscoveryIngestionService,
            SyncRunRepository syncRunRepository,
            ObjectMapper objectMapper,
            @Qualifier("integrationQueueExecutor") TaskExecutor integrationQueueExecutor,
            TransactionTemplate transactionTemplate,
            WorkspaceService workspaceService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.configRepository = configRepository;
        this.targetRepository = targetRepository;
        this.configService = configService;
        this.azureDiscoveryTargetService = azureDiscoveryTargetService;
        this.azureDiscoveryClient = azureDiscoveryClient;
        this.azureDiscoveryIngestionService = azureDiscoveryIngestionService;
        this.syncRunRepository = syncRunRepository;
        this.objectMapper = objectMapper;
        this.integrationQueueExecutor = integrationQueueExecutor;
        this.transactionTemplate = transactionTemplate;
        this.workspaceService = workspaceService;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    public SyncTriggerResponse trigger() {
        GenericAzureDiscoveryPolicy.requireAvailable();

        Tenant tenant = workspaceService.getWorkspace();
        ClaimedRun claimed = tenantSchemaExecutionService.run(
                tenant,
                () -> transactionTemplate.execute(status -> claimManualRun(tenant))
        );
        if (!claimed.reusedActiveRun()) {
            integrationQueueExecutor.execute(() -> executeRun(tenant.getId(), claimed.configId(), claimed.runId(), "manual", null));
            return new SyncTriggerResponse(claimed.runId(), "queued", "Azure Cloud Discovery sync queued");
        }
        return new SyncTriggerResponse(claimed.runId(), "running", "Azure Cloud Discovery sync is already queued or running");
    }

    public SyncTriggerResponse triggerTarget(Tenant tenant, UUID targetId) {
        GenericAzureDiscoveryPolicy.requireAvailable();

        AzureDiscoveryTarget target = azureDiscoveryTargetService.requireTarget(tenant, targetId);
        ClaimedRun claimed = tenantSchemaExecutionService.run(
                tenant,
                () -> transactionTemplate.execute(status -> claimRunForConfig(target.getConfig(), "manual-target", true))
        );
        if (!claimed.reusedActiveRun()) {
            integrationQueueExecutor.execute(() -> executeRun(tenant.getId(), claimed.configId(), claimed.runId(), "manual-target", targetId));
            return new SyncTriggerResponse(claimed.runId(), "queued", "Azure Cloud Discovery sync queued");
        }
        return new SyncTriggerResponse(claimed.runId(), "running", "Azure Cloud Discovery sync is already queued or running");
    }

    @Scheduled(zone = "UTC", cron = "0 */5 * * * *")
    public void runScheduledSyncs() {
        if (!GenericAzureDiscoveryPolicy.available()) return;

        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("azure-discovery.run-scheduled-syncs")) {
            return;
        }
        List<ConfigRef> configs = TenantContext.runAsPlatform(() -> {
            List<ConfigRef> scheduledConfigs = new ArrayList<>();
            for (Tenant tenant : tenantService.listActiveTenants()) {
                tenantSchemaExecutionService.run(tenant, () -> {
                    configRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "azure")
                            .filter(config -> config.isEnabled() && config.isAutoSyncEnabled())
                            .ifPresent(config -> scheduledConfigs.add(new ConfigRef(config.getId(), tenant.getId())));
                    return null;
                });
            }
            return scheduledConfigs;
        });
        for (ConfigRef configRef : configs) {
            ClaimedRun claimed = tenantSchemaExecutionService.run(configRef.tenantId(), () -> {
                AzureDiscoveryConfig config = configRepository.findById(configRef.configId()).orElse(null);
                return transactionTemplate.execute(status -> config == null ? null : claimScheduledRun(config));
            });
            if (claimed == null) {
                continue;
            }
            integrationQueueExecutor.execute(() -> executeRun(configRef.tenantId(), claimed.configId(), claimed.runId(), "scheduled", null));
        }
    }

    public boolean hasActiveRun() {
        if (!GenericAzureDiscoveryPolicy.available()) return false;

        var tenant = workspaceService.getWorkspace();
        return !syncRunRepository.findActiveRunsByTenantAndSyncType(
                tenant.getId(), SYNC_TYPE_AZURE_DISCOVERY, List.of("queued", "running")).isEmpty();
    }

    private ClaimedRun claimManualRun(Tenant tenant) {
        AzureDiscoveryConfig config = configService.findConfig(tenant)
                .filter(this::isConfigured)
                .orElseThrow(() -> new IllegalStateException("Azure Cloud Discovery connector is not configured"));
        if (!config.isEnabled()) {
            throw new IllegalStateException("Azure Cloud Discovery connector is disabled");
        }
        return claimRunForConfig(config, "manual", true);
    }

    private ClaimedRun claimScheduledRun(AzureDiscoveryConfig config) {
        return claimRunForConfig(config, "scheduled", false);
    }

    private ClaimedRun claimRunForConfig(AzureDiscoveryConfig config, String triggerMode, boolean allowReuseActiveRun) {
        // The configuration row is the admission lock, including when no run exists yet.
        // Tenant context and the transaction are established by every caller before this lock.
        config = configRepository.findByIdAndTenantIdForUpdate(config.getId(), config.getTenant().getId())
                .orElseThrow(() -> new EntityNotFoundException("Azure Cloud Discovery config not found"));
        if ("scheduled".equals(triggerMode)
                && (!isConfigured(config) || !config.isEnabled() || !config.isAutoSyncEnabled() || !isDue(config))) {
            return null;
        }
        if ("manual".equals(triggerMode) && (!isConfigured(config) || !config.isEnabled())) {
            throw new IllegalStateException("Azure Cloud Discovery connector is not configured or is disabled");
        }
        UUID tenantId = config.getTenant().getId();
        Optional<SyncRun> active = syncRunRepository.findActiveRunsByTenantAndSyncType(
                tenantId, SYNC_TYPE_AZURE_DISCOVERY,
                List.of("queued", "running")
        ).stream().findFirst();
        if (active.isPresent()) {
            if (!allowReuseActiveRun) {
                return null;
            }
            return new ClaimedRun(config.getId(), active.get().getId(), true);
        }

        SyncRun run = new SyncRun();
        run.setTenant(config.getTenant());
        run.setSyncType(SYNC_TYPE_AZURE_DISCOVERY);
        run.setRunScope("TENANT_INVENTORY");
        run.setStatus("queued");
        run.setMetadataJson(toJson(Map.of(
                "triggerMode", triggerMode,
                "sourceSystem", "azure",
                "azureTenantId", defaultIfBlank(config.getAzureTenantId(), "unknown"),
                "subscriptionIds", parseList(config.getSubscriptionIdsJson()),
                "regions", parseList(config.getRegionsJson())
        )));
        run = syncRunRepository.save(run);
        return new ClaimedRun(config.getId(), run.getId(), false);
    }

    private boolean isDue(AzureDiscoveryConfig config) {
        SyncRun latest = syncRunRepository
                .findTopBySyncTypeIgnoreCaseAndTenant_IdOrderByStartedAtDesc(SYNC_TYPE_AZURE_DISCOVERY, config.getTenant().getId())
                .orElse(null);
        if (latest == null) {
            return true;
        }
        Instant reference = latest.getCompletedAt() != null ? latest.getCompletedAt() : latest.getStartedAt();
        if (reference == null) {
            return true;
        }
        int minutes = config.getIntervalMinutes() == null ? 1440 : Math.max(5, config.getIntervalMinutes());
        return Duration.between(reference, Instant.now()).toMinutes() >= minutes;
    }

    private void executeRun(UUID tenantId, UUID configId, UUID runId, String triggerMode, UUID onlyTargetId) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            Instant runStartTime = Instant.now();
            markRunRunning(runId, triggerMode);
            try {
                GenericAzureDiscoveryPolicy.requireAvailable();
                AzureDiscoveryConfig config = configRepository.findById(configId)
                        .orElseThrow(() -> new EntityNotFoundException("Azure Discovery config not found: " + configId));

                LOG.info("Azure Discovery sync run {} starting (trigger={})", runId, triggerMode);

                azureDiscoveryTargetService.ensureLegacyTarget(config);
                List<AzureDiscoveryTarget> targets = resolveTargets(config, onlyTargetId);

                AzureDiscoveryConfig runtimeConfig = configService.runtimeConfig(config);
                TokenCredential credential = AzureCredentialProvider.from(runtimeConfig);

                int totalFetched = 0;
                int totalUpserted = 0;
                int totalUpdated = 0;
                int totalMarkedInactive = 0;
                Map<String, String> subscriptionErrors = new LinkedHashMap<>();
                List<Map<String, Object>> targetResults = new ArrayList<>();

                for (AzureDiscoveryTarget target : targets) {
                    TargetRunResult result = executeTarget(config, target, credential, runStartTime);
                    totalFetched += result.recordsFetched();
                    totalUpserted += result.ingestionResult().assetsUpserted();
                    totalUpdated += result.ingestionResult().assetsUpdated();
                    totalMarkedInactive += result.ingestionResult().assetsMarkedInactive();
                    if (result.error() != null) {
                        subscriptionErrors.put(defaultIfBlank(target.getSubscriptionId(), "unknown"), result.error());
                    }
                    targetResults.add(result.metadata());
                }

                completeRun(
                        configId,
                        runId,
                        totalFetched,
                        new IngestionResult(totalUpserted, totalUpdated, totalMarkedInactive),
                        subscriptionErrors,
                        triggerMode,
                        config,
                        targetResults
                );
            } catch (Exception e) {
                LOG.error("Azure Discovery sync run {} failed: {}", runId, e.getMessage(), e);
                failRun(runId, e.getMessage(), triggerMode);
            }
            return null;
        });
    }

    private List<AzureDiscoveryTarget> resolveTargets(AzureDiscoveryConfig config, UUID onlyTargetId) {
        if (onlyTargetId != null) {
            return targetRepository.findByIdAndTenant_Id(onlyTargetId, config.getTenant().getId())
                    .filter(target -> target.getConfig() != null && target.getConfig().getId().equals(config.getId()))
                    .map(List::of)
                    .orElse(List.of());
        }
        return targetRepository.findByConfigAndEnabledTrueOrderBySubscriptionNameAscSubscriptionIdAsc(config);
    }

    private TargetRunResult executeTarget(
            AzureDiscoveryConfig config,
            AzureDiscoveryTarget target,
            TokenCredential credential,
            Instant runStartTime
    ) {
        List<String> regions = parseList(target.getRegionsJson());
        AzureResourceFetchResult fetchResult = azureDiscoveryClient.fetchResources(credential, target.getSubscriptionId(), regions);
        if (fetchResult.error() != null) {
            throw new IllegalStateException("Azure resource retrieval is incomplete; previous subscription inventory is retained");
        }
        List<AzureResourceRecord> records = fetchResult.records();

        IngestionResult ingestionResult = azureDiscoveryIngestionService.ingestAll(
                records,
                config,
                config.getTenant(),
                runStartTime,
                target.getSubscriptionId()
        );

        Instant completedAt = Instant.now();
        if (target.getId() != null) {
            transactionTemplate.executeWithoutResult(status -> targetRepository.findById(target.getId()).ifPresent(t -> {
                t.setLastSyncAt(completedAt);
                targetRepository.save(t);
            }));
        }

        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("subscriptionId", target.getSubscriptionId());
        metadata.put("subscriptionName", target.getSubscriptionName());
        metadata.put("recordsFetched", records.size());
        metadata.put("assetsUpserted", ingestionResult.assetsUpserted());
        metadata.put("assetsUpdated", ingestionResult.assetsUpdated());
        metadata.put("assetsMarkedInactive", ingestionResult.assetsMarkedInactive());
        if (fetchResult.error() != null) {
            metadata.put("error", fetchResult.error());
        }

        return new TargetRunResult(records.size(), fetchResult.error(), ingestionResult, metadata);
    }

    private void markRunRunning(UUID runId, String triggerMode) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setStatus("running");
            Map<String, Object> metadata = readMetadata(run.getMetadataJson());
            metadata.put("triggerMode", triggerMode);
            metadata.put("state", "running");
            metadata.put("sourceSystem", "azure");
            run.setMetadataJson(toJson(metadata));
            syncRunRepository.save(run);
        });
    }

    private void completeRun(
            UUID configId,
            UUID runId,
            int fetched,
            IngestionResult ingestionResult,
            Map<String, String> subscriptionErrors,
            String triggerMode,
            AzureDiscoveryConfig config,
            List<Map<String, Object>> targetResults
    ) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            boolean hasWarnings = subscriptionErrors != null && !subscriptionErrors.isEmpty();
            boolean allTargetsFailed = !targetResults.isEmpty() && hasWarnings
                    && subscriptionErrors.size() == targetResults.size() && fetched == 0;
            run.setStatus(allTargetsFailed ? "failed" : hasWarnings ? "completed_with_errors" : "completed");
            run.setRecordsFetched(fetched);
            run.setRecordsInserted(ingestionResult.assetsUpserted());
            run.setRecordsUpdated(ingestionResult.assetsUpdated());
            run.setRecordsFailed(subscriptionErrors == null ? 0 : subscriptionErrors.size());
            run.setErrorMessage(hasWarnings ? String.join(" ", subscriptionErrors.values()) : null);
            run.setCompletedAt(Instant.now());

            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("triggerMode", triggerMode);
            metadata.put("sourceSystem", "azure");
            metadata.put("azureTenantId", defaultIfBlank(config.getAzureTenantId(), "unknown"));
            metadata.put("subscriptionIds", parseList(config.getSubscriptionIdsJson()));
            metadata.put("regions", parseList(config.getRegionsJson()));
            metadata.put("assetsIngested", ingestionResult.assetsUpserted());
            metadata.put("assetsUpserted", ingestionResult.assetsUpserted());
            metadata.put("assetsUpdated", ingestionResult.assetsUpdated());
            metadata.put("assetsMarkedInactive", ingestionResult.assetsMarkedInactive());
            metadata.put("recordsFetched", fetched);
            metadata.put("subscriptionErrors", subscriptionErrors);
            metadata.put("targets", targetResults);
            run.setMetadataJson(toJson(metadata));

            syncRunRepository.save(run);
            configRepository.findById(configId).ifPresent(cfg -> {
                cfg.setLastSyncAt(Instant.now());
                configRepository.save(cfg);
            });
        });
    }

    private void failRun(UUID runId, String errorMessage, String triggerMode) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setStatus("failed");
            run.setRecordsFailed(Math.max(1, run.getRecordsFailed()));
            run.setErrorMessage(errorMessage);
            run.setCompletedAt(Instant.now());
            Map<String, Object> metadata = readMetadata(run.getMetadataJson());
            metadata.put("triggerMode", triggerMode);
            metadata.put("state", "failed");
            metadata.put("sourceSystem", "azure");
            metadata.put("error", errorMessage);
            run.setMetadataJson(toJson(metadata));
            syncRunRepository.save(run);
        });
    }

    private SyncRun requireRun(UUID runId) {
        return syncRunRepository.findById(runId)
                .orElseThrow(() -> new IllegalStateException("Azure Discovery sync run not found: " + runId));
    }

    private boolean isConfigured(AzureDiscoveryConfig config) {
        if (config == null) {
            return false;
        }
        if (!hasText(config.getSubscriptionIdsJson()) || parseList(config.getSubscriptionIdsJson()).isEmpty()) {
            return false;
        }
        return switch (config.getAuthType() == null ? com.prototype.vulnwatch.domain.AzureAuthType.CLIENT_SECRET : config.getAuthType()) {
            case MANAGED_IDENTITY -> true;
            case CLIENT_SECRET -> hasText(config.getAzureTenantId())
                    && hasText(config.getClientId())
                    && hasText(config.getClientSecret());
        };
    }

    private List<String> parseList(String json) {
        if (!hasText(json)) {
            return List.of();
        }
        try {
            return objectMapper.readValue(json, new com.fasterxml.jackson.core.type.TypeReference<List<String>>() {});
        } catch (Exception e) {
            return List.of();
        }
    }

    private String defaultIfBlank(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }

    private Map<String, Object> readMetadata(String json) {
        if (!hasText(json)) {
            return new LinkedHashMap<>();
        }
        try {
            return new LinkedHashMap<>(objectMapper.readValue(
                    json,
                    new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {}));
        } catch (Exception ignored) {
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

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record ClaimedRun(UUID configId, UUID runId, boolean reusedActiveRun) {}

    private record ConfigRef(UUID configId, UUID tenantId) {}

    private record TargetRunResult(
            int recordsFetched,
            String error,
            IngestionResult ingestionResult,
            Map<String, Object> metadata
    ) {}
}
