package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsCredentialProvider;
import com.prototype.vulnwatch.client.AwsCustomerBinding;
import com.prototype.vulnwatch.client.AwsDiscoveryClient;
import com.prototype.vulnwatch.client.AwsDiscoveryClient.AwsEc2FetchResult;
import com.prototype.vulnwatch.client.AwsDiscoveryClient.AwsResourceRecord;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.AwsDiscoveryTarget;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryTargetRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.service.AwsResourceIngestionService.IngestionResult;
import com.prototype.vulnwatch.service.AwsResourceIngestionService.SsmInventoryIngestionSummary;
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
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

@Service
public class AwsDiscoverySyncService {

    public static final String SYNC_TYPE_AWS_DISCOVERY = "AWS_DISCOVERY";
    private static final Logger LOG = LoggerFactory.getLogger(AwsDiscoverySyncService.class);

    private final AwsDiscoveryConfigRepository awsDiscoveryConfigRepository;
    private final AwsDiscoveryTargetRepository awsDiscoveryTargetRepository;
    private final AwsDiscoveryConfigService awsDiscoveryConfigService;
    private final AwsDiscoveryTargetService awsDiscoveryTargetService;
    private final AwsDiscoveryClient awsDiscoveryClient;
    private final AwsResourceIngestionService awsResourceIngestionService;
    private final SyncRunRepository syncRunRepository;
    private final ObjectMapper objectMapper;
    private final TaskExecutor integrationQueueExecutor;
    private final TransactionTemplate transactionTemplate;
    private final IngestionJobService jobs;
    private final ConnectorScheduleProgress scheduleProgress;
    private final CredentialEncryptionService credentialEncryptionService;
    private final WorkspaceService workspaceService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public AwsDiscoverySyncService(
            AwsDiscoveryConfigRepository awsDiscoveryConfigRepository,
            AwsDiscoveryTargetRepository awsDiscoveryTargetRepository,
            AwsDiscoveryConfigService awsDiscoveryConfigService,
            AwsDiscoveryTargetService awsDiscoveryTargetService,
            AwsDiscoveryClient awsDiscoveryClient,
            AwsResourceIngestionService awsResourceIngestionService,
            SyncRunRepository syncRunRepository,
            ObjectMapper objectMapper,
            @Qualifier("integrationQueueExecutor") TaskExecutor integrationQueueExecutor,
            TransactionTemplate transactionTemplate,
            CredentialEncryptionService credentialEncryptionService,
            WorkspaceService workspaceService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            IngestionJobService jobs,
            ConnectorScheduleProgress scheduleProgress
    ) {
        this.awsDiscoveryConfigRepository = awsDiscoveryConfigRepository;
        this.awsDiscoveryTargetRepository = awsDiscoveryTargetRepository;
        this.awsDiscoveryConfigService = awsDiscoveryConfigService;
        this.awsDiscoveryTargetService = awsDiscoveryTargetService;
        this.awsDiscoveryClient = awsDiscoveryClient;
        this.awsResourceIngestionService = awsResourceIngestionService;
        this.syncRunRepository = syncRunRepository;
        this.objectMapper = objectMapper;
        this.integrationQueueExecutor = integrationQueueExecutor;
        this.transactionTemplate = transactionTemplate;
        this.credentialEncryptionService = credentialEncryptionService;
        this.workspaceService = workspaceService;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.jobs = jobs;
        this.scheduleProgress = scheduleProgress;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    public SyncTriggerResponse trigger() {
        Tenant tenant = workspaceService.getWorkspace();
        ClaimedRun claimed = jobs.withAdmission(tenant, () -> {
            ClaimedRun admitted = claimManualRun(tenant);
            if (!admitted.reusedActiveRun()) jobs.enqueueConnectorJob(tenant, IngestionJobService.JOB_TYPE_AWS_DISCOVERY,
                    admitted.configId(), admitted.runId(), "manual", null);
            return admitted;
        });
        if (!claimed.reusedActiveRun()) {
            return new SyncTriggerResponse(claimed.runId(), "queued", "AWS Cloud Discovery sync queued");
        }
        return new SyncTriggerResponse(claimed.runId(), "running", "AWS Cloud Discovery sync is already queued or running");
    }

    public SyncTriggerResponse triggerTarget(Tenant tenant, UUID targetId) {
        AwsDiscoveryTarget target = awsDiscoveryTargetService.requireTarget(tenant, targetId);
        ClaimedRun claimed = jobs.withAdmission(tenant, () -> {
            ClaimedRun admitted = claimRunForConfig(target.getConfig().getId(), tenant.getId(), "manual-target", null);
            if (!admitted.reusedActiveRun()) jobs.enqueueConnectorJob(tenant, IngestionJobService.JOB_TYPE_AWS_DISCOVERY,
                    admitted.configId(), admitted.runId(), "manual-target", targetId);
            return admitted;
        });
        if (!claimed.reusedActiveRun()) {
            return new SyncTriggerResponse(claimed.runId(), "queued", "AWS Cloud Discovery target sync queued");
        }
        return new SyncTriggerResponse(claimed.runId(), "running", "AWS Cloud Discovery sync is already queued or running");
    }

    @Scheduled(zone = "UTC", cron = "0 */5 * * * *")
    public void runScheduledSyncs() {
        runScheduledSyncs(Instant.now());
    }

    void runScheduledSyncs(Instant sweepStartedAt) {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("aws-discovery.run-scheduled-syncs")) {
            return;
        }
        List<Tenant> tenants = TenantContext.runAsPlatform(tenantService::listActiveTenants);
        for (Tenant tenant : tenants) {
            try {
                if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("aws-discovery.run-scheduled-syncs")) {
                    break;
                }
                UUID configId = tenantSchemaExecutionService.run(tenant, () -> awsDiscoveryConfigRepository
                        .findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws")
                        .filter(config -> config.isEnabled() && config.isAutoSyncEnabled())
                        .map(AwsDiscoveryConfig::getId).orElse(null));
                if (configId == null) {
                    continue;
                }
                jobs.withAdmission(tenant, () -> {
                    ClaimedRun claimed = claimRunForConfig(configId, tenant.getId(), "scheduled", sweepStartedAt);
                    if (claimed != null) jobs.enqueueConnectorJob(tenant, IngestionJobService.JOB_TYPE_AWS_DISCOVERY,
                            claimed.configId(), claimed.runId(), "scheduled", null);
                    return null;
                });
            } catch (RuntimeException failure) {
                LOG.warn("Scheduled AWS discovery admission deferred for tenant {}", tenant.getId());
            }
        }
    }

    @Transactional(readOnly = true)
    public boolean hasActiveRun() {
        var tenant = workspaceService.getWorkspace();
        return !syncRunRepository.findActiveRunsByTenantAndSyncType(
                tenant.getId(), SYNC_TYPE_AWS_DISCOVERY, List.of("queued", "running")).isEmpty();
    }

    // ── Run claiming ───────────────────────────────────────────────────────────────────────────

    private ClaimedRun claimManualRun(Tenant tenant) {
        AwsDiscoveryConfig config = awsDiscoveryConfigService.findConfig(tenant)
                .filter(this::isConfigured)
                .orElseThrow(() -> new IllegalStateException("AWS Cloud Discovery connector is not configured"));
        if (!config.isEnabled()) {
            throw new IllegalStateException("AWS Cloud Discovery connector is disabled");
        }
        return claimRunForConfig(config.getId(), tenant.getId(), "manual", null);
    }

    private ClaimedRun claimRunForConfig(UUID configId, UUID tenantId, String triggerMode, Instant sweepStartedAt) {
        // The configuration row is the admission lock, including when no run exists yet.
        // Tenant context and the transaction are established by every caller before this lock.
        AwsDiscoveryConfig config = awsDiscoveryConfigRepository.findByIdAndTenantIdForUpdate(configId, tenantId)
                .orElseThrow(() -> new EntityNotFoundException("AWS Cloud Discovery config not found"));
        if (!isConfigured(config) || !config.isEnabled()) {
            throw new IllegalStateException("AWS customer connector is disabled or requires a server binding");
        }
        if (sweepStartedAt != null && (!config.isAutoSyncEnabled() || !isDue(config, sweepStartedAt))) {
            return null;
        }
        Optional<SyncRun> active = syncRunRepository.findActiveRunsByTenantAndSyncType(
                tenantId, SYNC_TYPE_AWS_DISCOVERY,
                List.of("queued", "running")
        ).stream().findFirst();
        if (active.isPresent()) {
            if (sweepStartedAt != null) {
                return null;
            }
            return new ClaimedRun(config.getId(), active.get().getId(), true);
        }

        if (sweepStartedAt != null && !scheduleProgress.advance(
                tenantId, ConnectorScheduleProgress.Kind.AWS_DISCOVERY, config.getId(), sweepStartedAt)) {
            return null;
        }
        List<String> regions = parseRegions(config.getRegionsJson());
        List<String> resourceTypes = parseResourceTypes(config.getResourceTypesJson());

        SyncRun run = new SyncRun();
        run.setTenant(config.getTenant());
        run.setSyncType(SYNC_TYPE_AWS_DISCOVERY);
        run.setRunScope("TENANT_INVENTORY");
        run.setStatus("queued");
        run.setMetadataJson(toJson(Map.of(
                "triggerMode", triggerMode,
                "awsAccountId", defaultIfBlank(config.getAwsAccountId(), "unknown"),
                "regions", regions,
                "resourceTypes", resourceTypes
        )));
        run = syncRunRepository.save(run);
        return new ClaimedRun(config.getId(), run.getId(), false);
    }

    private boolean isDue(AwsDiscoveryConfig config, Instant sweepStartedAt) {
        SyncRun latest = syncRunRepository
                .findTopBySyncTypeIgnoreCaseAndTenant_IdOrderByStartedAtDesc(SYNC_TYPE_AWS_DISCOVERY, config.getTenant().getId())
                .orElse(null);
        if (latest == null) {
            return true;
        }
        Instant reference = latest.getCompletedAt() != null ? latest.getCompletedAt() : latest.getStartedAt();
        if (reference == null) {
            return true;
        }
        int minutes = config.getIntervalMinutes() == null ? 1440 : Math.max(5, config.getIntervalMinutes());
        return Duration.between(reference, sweepStartedAt).toMinutes() >= minutes;
    }

    // ── Execution ──────────────────────────────────────────────────────────────────────────────

    public void executeQueuedRun(UUID tenantId, UUID configId, UUID runId, String triggerMode, UUID onlyTargetId) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            Instant runStartTime = Instant.now();
            markRunRunning(runId, triggerMode);
            try {
                AwsDiscoveryConfig config = awsDiscoveryConfigRepository.findById(configId)
                        .orElseThrow(() -> new EntityNotFoundException("AWS Discovery config not found: " + configId));
                if (!tenantId.equals(config.getTenant().getId()) || !config.isEnabled() || !isConfigured(config)) {
                    throw new IllegalStateException("AWS customer connector is disabled or no longer matches the queued work");
                }
                awsDiscoveryTargetService.ensureLegacyTarget(config);

                LOG.info("AWS Discovery sync run {} starting (trigger={})", runId, triggerMode);

                List<AwsDiscoveryTarget> targets = resolveTargets(config, onlyTargetId);
                if (targets.isEmpty()) {
                    targets = List.of(legacyVirtualTarget(config));
                }

                int totalFetched = 0;
                int recordsFailed = 0;
                int assetsUpserted = 0;
                int softwareInstancesCreated = 0;
                int softwareInstancesUpdated = 0;
                int componentsCreated = 0;
                int componentsUpdated = 0;
                int findingsGenerated = 0;
                int warningTargets = 0;
                int assetsMarkedInactive = 0;
                List<String> visibleMessages = new ArrayList<>();
                List<Map<String, Object>> targetResults = new ArrayList<>();

                for (AwsDiscoveryTarget target : targets) {
                    TargetRunResult targetResult = executeTarget(config, target, runId, triggerMode, runStartTime);
                    totalFetched += targetResult.recordsFetched();
                    recordsFailed += targetResult.failed() ? 1 : 0;
                    warningTargets += targetResult.warning() ? 1 : 0;
                    assetsUpserted += targetResult.ingestionResult().assetsUpserted();
                    softwareInstancesCreated += targetResult.ssmSummary().softwareInstancesCreated();
                    softwareInstancesUpdated += targetResult.ssmSummary().softwareInstancesUpdated();
                    componentsCreated += targetResult.ingestionResult().inventoryComponentsCreated();
                    componentsCreated += targetResult.ssmSummary().inventoryComponentsCreated();
                    componentsUpdated += targetResult.ingestionResult().inventoryComponentsUpdated();
                    componentsUpdated += targetResult.ssmSummary().inventoryComponentsUpdated();
                    findingsGenerated += targetResult.ssmSummary().findingsGenerated();
                    assetsMarkedInactive += targetResult.ingestionResult().assetsMarkedInactive();
                    if (hasText(targetResult.visibleMessage())) {
                        visibleMessages.add(targetResult.visibleMessage());
                    }
                    targetResults.add(targetResult.metadata());
                    updateRunProgress(runId, totalFetched, "ingesting-targets", triggerMode, config, targetResults);
                }

                completeRun(
                        configId,
                        runId,
                        new IngestionResult(assetsUpserted, componentsCreated, componentsUpdated, assetsMarkedInactive),
                        new SsmInventoryIngestionSummary(
                                0,
                                softwareInstancesCreated,
                                softwareInstancesUpdated,
                                componentsCreated,
                                componentsUpdated,
                                findingsGenerated
                        ),
                        totalFetched,
                        recordsFailed,
                        warningTargets,
                        summarizeVisibleMessages(visibleMessages),
                        triggerMode,
                        config,
                        targetResults
                );
            } catch (Exception e) {
                LOG.error("AWS Discovery sync run {} failed: {}", runId, e.getMessage(), e);
                failRun(runId, e.getMessage(), triggerMode);
            }
            return null;
        });
    }

    private TargetRunResult executeTarget(
            AwsDiscoveryConfig config,
            AwsDiscoveryTarget target,
            UUID runId,
            String triggerMode,
            Instant runStartTime
    ) {
        String accountId = defaultIfBlank(target.getAccountId(), defaultIfBlank(config.getAwsAccountId(), ""));
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("targetId", target.getId());
        metadata.put("accountId", defaultIfBlank(accountId, "unknown"));
        metadata.put("accountName", defaultIfBlank(target.getAccountName(), "AWS Account"));
        try {
            if (target.getTenant() == null || !config.getTenant().getId().equals(target.getTenant().getId()) || !target.isEnabled()) {
                throw new IllegalStateException("AWS discovery target is disabled or belongs to a different tenant");
            }
            AwsDiscoveryConfig runtimeConfig = configWithDecryptedCredential(config);
            AwsCredentialsProvider creds = target.getId() == null
                    ? AwsCredentialProvider.from(runtimeConfig)
                    : AwsCredentialProvider.from(runtimeConfig, target);
            awsDiscoveryClient.verifyCustomerIdentity(creds, accountId, target.getRoleArn());
            List<String> regions = parseRegions(defaultIfBlank(target.getRegionsJson(), config.getRegionsJson()));
            List<String> resourceTypes = parseResourceTypes(defaultIfBlank(target.getResourceTypesJson(), config.getResourceTypesJson()));
            AwsEc2FetchResult fetchResult = fetchTargetRecords(creds, regions);
            List<AwsResourceRecord> allRecords = fetchResult.records();
            String regionErrorSummary = summarizeRegionErrors(fetchResult.regionErrors());

            if (allRecords.isEmpty() && !regions.isEmpty() && fetchResult.regionErrors().size() == regions.size()) {
                String errorMessage = appendExternalIdHint(
                        "AWS target discovery failed for all configured regions. " + regionErrorSummary,
                        target.getRoleArn(),
                        target.getExternalId()
                );
                metadata.put("status", "failed");
                metadata.put("error", errorMessage);
                metadata.put("regionErrors", fetchResult.regionErrors());
                return new TargetRunResult(
                        0,
                        true,
                        false,
                        new IngestionResult(0, 0, 0, 0),
                        new SsmInventoryIngestionSummary(0, 0, 0, 0, 0, 0),
                        metadata,
                        errorMessage
                );
            }

            LOG.info("AWS Discovery run {} target {} fetched {} records", runId, accountId, allRecords.size());
            IngestionResult result = awsResourceIngestionService.ingestAll(
                    allRecords, config, config.getTenant(), runStartTime, accountId);

            List<AwsResourceRecord> ec2Records = allRecords.stream()
                    .filter(r -> "EC2".equalsIgnoreCase(r.resourceType()))
                    .toList();
            SsmInventoryIngestionSummary ssmSummary = new SsmInventoryIngestionSummary(0, 0, 0, 0, 0, 0);
            if (!ec2Records.isEmpty()) {
                ssmSummary = awsResourceIngestionService.ingestEc2SsmPackages(
                        ec2Records, creds, regions, config.getTenant(), accountId);
            }

            Instant completedAt = Instant.now();
            boolean warning = !fetchResult.regionErrors().isEmpty();
            metadata.put("status", warning ? "completed_with_errors" : "completed");
            metadata.put("recordsFetched", allRecords.size());
            metadata.put("assetsIngested", result.assetsUpserted());
            metadata.put("assetsUpserted", result.assetsUpserted());
            metadata.put("ssmAssetsIngested", ssmSummary.assetsIngested());
            metadata.put("softwareInstancesCreated", ssmSummary.softwareInstancesCreated());
            metadata.put("softwareInstancesUpdated", ssmSummary.softwareInstancesUpdated());
            metadata.put("componentsIngested", ssmSummary.inventoryComponentsCreated() + ssmSummary.inventoryComponentsUpdated());
            metadata.put("inventoryComponentsCreated", result.inventoryComponentsCreated() + ssmSummary.inventoryComponentsCreated());
            metadata.put("inventoryComponentsUpdated", result.inventoryComponentsUpdated() + ssmSummary.inventoryComponentsUpdated());
            metadata.put("findingsGenerated", ssmSummary.findingsGenerated());
            metadata.put("assetsMarkedInactive", result.assetsMarkedInactive());
            if (warning) {
                metadata.put("regionErrors", fetchResult.regionErrors());
                metadata.put("warning", regionErrorSummary);
            }
            if (target.getId() != null) {
                transactionTemplate.executeWithoutResult(status -> {
                    awsDiscoveryTargetRepository.findById(target.getId()).ifPresent(existing -> {
                        if (hasText(accountId)) existing.setAccountId(accountId);
                        existing.setLastSyncAt(completedAt);
                        existing.touch();
                        awsDiscoveryTargetRepository.save(existing);
                    });
                });
            }
            return new TargetRunResult(allRecords.size(), false, warning, result, ssmSummary, metadata, warning ? regionErrorSummary : null);
        } catch (Exception e) {
            LOG.warn("AWS Discovery run {} target {} failed: {}", runId, accountId, e.getMessage(), e);
            metadata.put("status", "failed");
            metadata.put("error", e.getMessage());
            return new TargetRunResult(
                    0,
                    true,
                    false,
                    new IngestionResult(0, 0, 0, 0),
                    new SsmInventoryIngestionSummary(0, 0, 0, 0, 0, 0),
                    metadata,
                    e.getMessage()
            );
        }
    }

    private AwsEc2FetchResult fetchTargetRecords(
            AwsCredentialsProvider creds,
            List<String> regions
    ) {
        try {
            return awsDiscoveryClient.fetchEc2Instances(creds, regions);
        } catch (Exception e) {
            LOG.warn("AWS Discovery: error fetching EC2 resources: {}", e.getMessage(), e);
            return new AwsEc2FetchResult(List.of(), Map.of("global", e.getMessage()));
        }
    }

    // ── Run lifecycle state transitions ───────────────────────────────────────────────────────

    private void markRunRunning(UUID runId, String triggerMode) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setStatus("running");
            Map<String, Object> metadata = readMetadata(run.getMetadataJson());
            metadata.put("triggerMode", triggerMode);
            metadata.put("state", "running");
            metadata.put("sourceSystem", "aws");
            run.setMetadataJson(toJson(metadata));
            syncRunRepository.save(run);
        });
    }

    private void updateRunProgress(
            UUID runId,
            int recordsFetched,
            String stage,
            String triggerMode,
            AwsDiscoveryConfig config,
            List<Map<String, Object>> targetResults
    ) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setRecordsFetched(recordsFetched);
            Map<String, Object> metadata = readMetadata(run.getMetadataJson());
            metadata.put("triggerMode", triggerMode);
            metadata.put("sourceSystem", "aws");
            metadata.put("awsAccountId", defaultIfBlank(config.getAwsAccountId(), "unknown"));
            metadata.put("stage", stage);
            metadata.put("recordsFetched", recordsFetched);
            metadata.put("targets", targetResults);
            run.setMetadataJson(toJson(metadata));
            syncRunRepository.save(run);
        });
    }

    private void completeRun(
            UUID configId,
            UUID runId,
            IngestionResult result,
            SsmInventoryIngestionSummary ssmSummary,
            int fetched,
            int failedTargets,
            int warningTargets,
            String visibleMessage,
            String triggerMode,
            AwsDiscoveryConfig config,
            List<Map<String, Object>> targetResults
    ) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            boolean allTargetsFailed = !targetResults.isEmpty() && failedTargets == targetResults.size() && fetched == 0;
            boolean hasWarnings = failedTargets > 0 || warningTargets > 0;
            run.setStatus(allTargetsFailed ? "failed" : hasWarnings ? "completed_with_errors" : "completed");
            run.setRecordsFetched(fetched);
            run.setRecordsInserted(result.assetsUpserted() + ssmSummary.inventoryComponentsCreated());
            run.setRecordsUpdated(ssmSummary.inventoryComponentsUpdated());
            run.setRecordsFailed(failedTargets);
            run.setErrorMessage(hasText(visibleMessage)
                    ? visibleMessage
                    : failedTargets > 0 ? failedTargets + " AWS discovery target(s) failed"
                    : warningTargets > 0 ? warningTargets + " AWS discovery target(s) completed with region errors"
                    : null);
            run.setCompletedAt(Instant.now());

            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("triggerMode", triggerMode);
            metadata.put("sourceSystem", "aws");
            metadata.put("awsAccountId", defaultIfBlank(config.getAwsAccountId(), "unknown"));
            metadata.put("regions", parseRegions(config.getRegionsJson()));
            metadata.put("resourceTypes", parseResourceTypes(config.getResourceTypesJson()));
            metadata.put("assetsIngested", result.assetsUpserted());
            metadata.put("assetsUpserted", result.assetsUpserted());
            metadata.put("ssmAssetsIngested", ssmSummary.assetsIngested());
            metadata.put("softwareInstancesCreated", ssmSummary.softwareInstancesCreated());
            metadata.put("softwareInstancesUpdated", ssmSummary.softwareInstancesUpdated());
            metadata.put("componentsIngested", ssmSummary.inventoryComponentsCreated() + ssmSummary.inventoryComponentsUpdated());
            metadata.put("inventoryComponentsCreated", ssmSummary.inventoryComponentsCreated());
            metadata.put("inventoryComponentsUpdated", ssmSummary.inventoryComponentsUpdated());
            metadata.put("findingsGenerated", ssmSummary.findingsGenerated());
            metadata.put("assetsMarkedInactive", result.assetsMarkedInactive());
            metadata.put("totalRecordsFetched", fetched);
            metadata.put("failedTargets", failedTargets);
            metadata.put("warningTargets", warningTargets);
            metadata.put("targets", targetResults);
            run.setMetadataJson(toJson(metadata));

            syncRunRepository.save(run);
            awsDiscoveryConfigRepository.findById(configId).ifPresent(cfg -> {
                cfg.setLastSyncAt(Instant.now());
                awsDiscoveryConfigRepository.save(cfg);
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
            metadata.put("sourceSystem", "aws");
            metadata.put("error", errorMessage);
            run.setMetadataJson(toJson(metadata));
            syncRunRepository.save(run);
        });
    }

    // ── Utilities ──────────────────────────────────────────────────────────────────────────────

    private boolean isConfigured(AwsDiscoveryConfig config) {
        if (config == null || config.getTenant() == null) return false;
        try {
            AwsCustomerBinding.validate(config.getTenant().getId(), config.getAwsAccountId(), config.getCrossAccountRoleArn(),
                    config.getExternalId(), config.getCredentialBindingVersion());
            return true;
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private AwsDiscoveryConfig configWithDecryptedCredential(AwsDiscoveryConfig config) {
        if (config == null || !hasText(config.getCredentialSecret())) {
            return config;
        }
        AwsDiscoveryConfig runtimeConfig = new AwsDiscoveryConfig();
        runtimeConfig.setTenant(config.getTenant());
        runtimeConfig.setSourceSystem(config.getSourceSystem());
        runtimeConfig.setAuthType(config.getAuthType());
        runtimeConfig.setAccessKeyId(config.getAccessKeyId());
        runtimeConfig.setCredentialSecret(credentialEncryptionService.decrypt(config.getCredentialSecret()));
        runtimeConfig.setCrossAccountRoleArn(config.getCrossAccountRoleArn());
        runtimeConfig.setExternalId(config.getExternalId());
        runtimeConfig.setCredentialBindingVersion(config.getCredentialBindingVersion());
        runtimeConfig.setAwsAccountId(config.getAwsAccountId());
        runtimeConfig.setRegionsJson(config.getRegionsJson());
        runtimeConfig.setResourceTypesJson(config.getResourceTypesJson());
        runtimeConfig.setEnabled(config.isEnabled());
        runtimeConfig.setAutoSyncEnabled(config.isAutoSyncEnabled());
        runtimeConfig.setIntervalMinutes(config.getIntervalMinutes());
        return runtimeConfig;
    }

    private List<AwsDiscoveryTarget> resolveTargets(AwsDiscoveryConfig config, UUID onlyTargetId) {
        if (onlyTargetId != null) {
            return awsDiscoveryTargetRepository.findById(onlyTargetId)
                    .filter(target -> target.getConfig() != null && config.getId().equals(target.getConfig().getId()))
                    .filter(AwsDiscoveryTarget::isEnabled)
                    .map(List::of)
                    .orElseThrow(() -> new IllegalStateException("AWS target is disabled or no longer belongs to the queued connector"));
        }
        return awsDiscoveryTargetRepository.findByConfigAndEnabledTrueOrderByAccountNameAscAccountIdAsc(config);
    }

    private AwsDiscoveryTarget legacyVirtualTarget(AwsDiscoveryConfig config) {
        AwsDiscoveryTarget target = new AwsDiscoveryTarget();
        target.setTenant(config.getTenant());
        target.setConfig(config);
        target.setAccountId(config.getAwsAccountId());
        target.setAccountName(hasText(config.getAwsAccountId()) ? "AWS Account " + config.getAwsAccountId() : "AWS Account");
        target.setRoleArn(config.getCrossAccountRoleArn());
        target.setExternalId(config.getExternalId());
        target.setCredentialBindingVersion(config.getCredentialBindingVersion());
        target.setEnabled(config.isEnabled());
        target.setRegionsJson(config.getRegionsJson());
        target.setResourceTypesJson(config.getResourceTypesJson());
        return target;
    }

    private List<String> parseRegions(String regionsJson) {
        if (!hasText(regionsJson)) return List.of("us-east-1");
        try {
            return objectMapper.readValue(regionsJson, new TypeReference<>() {});
        } catch (Exception e) {
            return List.of("us-east-1");
        }
    }

    private List<String> parseResourceTypes(String resourceTypesJson) {
        return List.of("EC2");
    }

    private SyncRun requireRun(UUID runId) {
        return syncRunRepository.findById(runId)
                .orElseThrow(() -> new EntityNotFoundException("Sync run not found: " + runId));
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private Map<String, Object> readMetadata(String json) {
        if (!hasText(json)) {
            return new LinkedHashMap<>();
        }
        try {
            return new LinkedHashMap<>(objectMapper.readValue(
                    json,
                    new TypeReference<Map<String, Object>>() {}));
        } catch (Exception ignored) {
            return new LinkedHashMap<>();
        }
    }

    private String defaultIfBlank(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String summarizeRegionErrors(Map<String, String> regionErrors) {
        if (regionErrors == null || regionErrors.isEmpty()) {
            return null;
        }
        return "Region errors: " + regionErrors.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .toList();
    }

    private String summarizeVisibleMessages(List<String> messages) {
        if (messages == null) {
            return null;
        }
        return messages.stream()
                .filter(this::hasText)
                .distinct()
                .limit(3)
                .reduce((left, right) -> left + " | " + right)
                .orElse(null);
    }

    private String appendExternalIdHint(String message, String roleArn, String externalId) {
        if (!hasText(roleArn) || hasText(externalId)) {
            return message;
        }
        String lower = message == null ? "" : message.toLowerCase(java.util.Locale.ROOT);
        if (!lower.contains("assumerole") && !lower.contains("accessdenied") && !lower.contains("not authorized")) {
            return message;
        }
        return message + " Role may require External ID; configure it in the connector if the trust policy uses sts:ExternalId.";
    }

    private record ClaimedRun(
            UUID configId,
            UUID runId,
            boolean reusedActiveRun
    ) {}


    private record TargetRunResult(
            int recordsFetched,
            boolean failed,
            boolean warning,
            IngestionResult ingestionResult,
            SsmInventoryIngestionSummary ssmSummary,
            Map<String, Object> metadata,
            String visibleMessage
    ) {}
}
