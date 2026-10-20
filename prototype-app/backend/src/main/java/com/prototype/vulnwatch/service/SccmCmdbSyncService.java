package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.dto.CmdbInventorySyncResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import jakarta.persistence.EntityNotFoundException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class SccmCmdbSyncService {

    public static final String SYNC_TYPE_SCCM_CMDB = "SCCM_CMDB";
    private static final Logger LOG = LoggerFactory.getLogger(SccmCmdbSyncService.class);

    private final SccmCmdbConfigRepository sccmCmdbConfigRepository;
    private final SccmCmdbConfigService sccmCmdbConfigService;
    private final SccmQueryService sccmQueryService;
    private final SyncRunRepository syncRunRepository;
    private final CmdbIngestionService cmdbIngestionService;
    private final ObjectMapper objectMapper;
    private final TaskExecutor integrationQueueExecutor;
    private final TransactionTemplate transactionTemplate;
    private final WorkspaceService workspaceService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public SccmCmdbSyncService(
            SccmCmdbConfigRepository sccmCmdbConfigRepository,
            SccmCmdbConfigService sccmCmdbConfigService,
            SccmQueryService sccmQueryService,
            SyncRunRepository syncRunRepository,
            CmdbIngestionService cmdbIngestionService,
            ObjectMapper objectMapper,
            @Qualifier("integrationQueueExecutor") TaskExecutor integrationQueueExecutor,
            TransactionTemplate transactionTemplate,
            WorkspaceService workspaceService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.sccmCmdbConfigRepository = sccmCmdbConfigRepository;
        this.sccmCmdbConfigService = sccmCmdbConfigService;
        this.sccmQueryService = sccmQueryService;
        this.syncRunRepository = syncRunRepository;
        this.cmdbIngestionService = cmdbIngestionService;
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
        SccmPilotPolicy.requireEnabled();
        var tenant = workspaceService.getWorkspace();
        ClaimedRun claimed = tenantSchemaExecutionService.run(
                tenant,
                () -> transactionTemplate.execute(status -> claimManualRun(tenant))
        );
        if (!claimed.reusedActiveRun()) {
            integrationQueueExecutor.execute(() -> executeRun(tenant.getId(), claimed.configId(), claimed.runId(), "manual"));
            return new SyncTriggerResponse(claimed.runId(), "queued", "SCCM CMDB sync queued");
        }
        return new SyncTriggerResponse(claimed.runId(), "running", "SCCM CMDB sync is already queued or running");
    }

    @Scheduled(zone = "UTC", cron = "0 */5 * * * *")
    public void runScheduledSyncs() {
        // Contained for the assisted pilot, including configurations saved before containment.
        if (isPilotDisabled()) return;
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("sccm-cmdb.run-scheduled-syncs")) {
            return;
        }
        List<ConfigRef> configs = TenantContext.runAsPlatform(() -> {
            List<ConfigRef> scheduledConfigs = new java.util.ArrayList<>();
            for (var tenant : tenantService.listActiveTenants()) {
                tenantSchemaExecutionService.run(tenant, () -> {
                    sccmCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm")
                            .filter(config -> config.isEnabled() && config.isAutoSyncEnabled())
                            .ifPresent(config -> scheduledConfigs.add(new ConfigRef(config.getId(), tenant.getId())));
                    return null;
                });
            }
            return scheduledConfigs;
        });
        for (ConfigRef configRef : configs) {
            ClaimedRun claimed = tenantSchemaExecutionService.run(configRef.tenantId(), () -> {
                SccmCmdbConfig config = sccmCmdbConfigRepository.findById(configRef.configId()).orElse(null);
                return transactionTemplate.execute(status -> config == null ? null : claimScheduledRun(config));
            });
            if (claimed == null) {
                continue;
            }
            integrationQueueExecutor.execute(() -> executeRun(configRef.tenantId(), claimed.configId(), claimed.runId(), "scheduled"));
        }
    }

    @Transactional(readOnly = true)
    public boolean hasActiveRun() {
        var tenant = workspaceService.getWorkspace();
        return !syncRunRepository.findActiveRunsByTenantAndSyncType(
                tenant.getId(), SYNC_TYPE_SCCM_CMDB, List.of("queued", "running")).isEmpty();
    }

    private boolean isPilotDisabled() {
        return true;
    }

    // ── Run claiming ───────────────────────────────────────────────────────────────────────────

    private ClaimedRun claimManualRun(com.prototype.vulnwatch.domain.Tenant tenant) {
        SccmCmdbConfig config = sccmCmdbConfigService.findConfig(tenant)
                .filter(this::isConfigured)
                .orElseThrow(() -> new IllegalStateException("SCCM CMDB connector is not configured"));
        if (!config.isEnabled()) {
            throw new IllegalStateException("SCCM CMDB connector is disabled");
        }
        return claimRunForConfig(config, "manual", true);
    }

    private ClaimedRun claimScheduledRun(SccmCmdbConfig config) {
        return claimRunForConfig(config, "scheduled", false);
    }

    private ClaimedRun claimRunForConfig(SccmCmdbConfig config, String triggerMode, boolean allowReuseActiveRun) {
        SccmPilotPolicy.requireEnabled();
        // The configuration row is the admission lock, including when no run exists yet.
        // Tenant context and the transaction are established by every caller before this lock.
        config = sccmCmdbConfigRepository.findByIdAndTenantIdForUpdate(config.getId(), config.getTenant().getId())
                .orElseThrow(() -> new EntityNotFoundException("SCCM CMDB config not found"));
        if ("scheduled".equals(triggerMode)
                && (!isConfigured(config) || !config.isEnabled() || !config.isAutoSyncEnabled() || !isDue(config))) {
            return null;
        }
        if ("manual".equals(triggerMode) && (!isConfigured(config) || !config.isEnabled())) {
            throw new IllegalStateException("SCCM CMDB connector is not configured or is disabled");
        }
        UUID tenantId = config.getTenant().getId();
        Optional<SyncRun> active = syncRunRepository.findActiveRunsByTenantAndSyncType(
                tenantId, SYNC_TYPE_SCCM_CMDB,
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
        run.setSyncType(SYNC_TYPE_SCCM_CMDB);
        run.setRunScope("TENANT_INVENTORY");
        run.setStatus("queued");
        run.setMetadataJson(toJson(Map.of(
                "triggerMode", triggerMode,
                "sourceSystem", defaultIfBlank(config.getSourceSystem(), "sccm"),
                "jdbcUrl", defaultIfBlank(config.getJdbcUrl(), ""),
                "mockMode", config.isMockMode()
        )));
        run = syncRunRepository.save(run);
        return new ClaimedRun(config.getId(), run.getId(), false);
    }

    private boolean isDue(SccmCmdbConfig config) {
        SyncRun latest = syncRunRepository
                .findTopBySyncTypeIgnoreCaseAndTenant_IdOrderByStartedAtDesc(SYNC_TYPE_SCCM_CMDB, config.getTenant().getId())
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

    // ── Execution ──────────────────────────────────────────────────────────────────────────────

    private void executeRun(UUID tenantId, UUID configId, UUID runId, String triggerMode) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            markRunRunning(runId, triggerMode);
            try {
                SccmPilotPolicy.requireEnabled();
                SccmCmdbConfig config = sccmCmdbConfigRepository.findById(configId)
                        .orElseThrow(() -> new EntityNotFoundException("SCCM CMDB config not found: " + configId));

                LOG.info("SCCM sync run {} starting (trigger={})", runId, triggerMode);
                List<Map<String, String>> installRows = sccmQueryService.fetchInstallRows(config);
                updateRunProgress(runId, installRows.size(), "building-discovery");

                List<Map<String, String>> discoveryRows = sccmQueryService.buildDiscoveryRows(installRows);
                updateRunProgress(runId, installRows.size() + discoveryRows.size(), "ingesting");

                CmdbInventorySyncResponse response = cmdbIngestionService.ingestRows(
                        config.getTenant(),
                        defaultIfBlank(config.getSourceSystem(), "sccm"),
                        installRows,
                        discoveryRows,
                        new CmdbIngestionService.HostInventorySourceDescriptor(
                                "sccm-live-sync",
                                "sccm-jdbc",
                                defaultIfBlank(config.getSourceSystem(), "sccm"),
                                "v_GS_INSTALLED_SOFTWARE",
                                defaultIfBlank(config.getJdbcUrl(), ""),
                                MediaType.APPLICATION_JSON_VALUE,
                                null
                        )
                );

                completeRun(configId, runId, response, installRows.size() + discoveryRows.size(), triggerMode);
            } catch (Exception e) {
                LOG.error("SCCM sync run {} failed: {}", runId, e.getMessage(), e);
                failRun(runId, e.getMessage(), triggerMode);
            }
            return null;
        });
    }

    // ── Run lifecycle state transitions ───────────────────────────────────────────────────────

    private void markRunRunning(UUID runId, String triggerMode) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setStatus("running");
            run.setMetadataJson(toJson(Map.of(
                    "triggerMode", triggerMode,
                    "state", "running",
                    "sourceSystem", "sccm",
                    "assetType", "HOST"
            )));
            syncRunRepository.save(run);
        });
    }

    private void updateRunProgress(UUID runId, int recordsFetched, String stage) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setRecordsFetched(recordsFetched);
            run.setMetadataJson(toJson(Map.of(
                    "sourceSystem", "sccm",
                    "assetType", "HOST",
                    "stage", stage,
                    "recordsFetched", recordsFetched
            )));
            syncRunRepository.save(run);
        });
    }

    private void completeRun(UUID configId, UUID runId, CmdbInventorySyncResponse response, int fetched, String triggerMode) {
        transactionTemplate.executeWithoutResult(status -> {
            SyncRun run = requireRun(runId);
            run.setStatus("completed");
            run.setRecordsFetched(fetched);
            run.setRecordsInserted(response.ciCreated() + response.softwareInstancesCreated() + response.inventoryComponentsCreated());
            run.setRecordsUpdated(response.softwareInstancesUpdated() + response.inventoryComponentsUpdated());
            run.setRecordsFailed(0);
            run.setErrorMessage(null);
            run.setCompletedAt(Instant.now());
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("triggerMode", triggerMode);
            metadata.put("sourceSystem", response.sourceSystem());
            metadata.put("assetType", "HOST");
            metadata.put("assetsIngested", response.assetsIngested());
            metadata.put("installRowsProcessed", response.installRowsProcessed());
            metadata.put("discoveryRowsProcessed", response.discoveryRowsProcessed());
            metadata.put("unmatchedDiscoveryRows", response.unmatchedDiscoveryRows());
            metadata.put("ciCreated", response.ciCreated());
            metadata.put("ciAliasesCreated", response.ciAliasesCreated());
            metadata.put("softwareInstancesCreated", response.softwareInstancesCreated());
            metadata.put("softwareInstancesUpdated", response.softwareInstancesUpdated());
            metadata.put("inventoryComponentsCreated", response.inventoryComponentsCreated());
            metadata.put("inventoryComponentsUpdated", response.inventoryComponentsUpdated());
            metadata.put("findingsGenerated", response.findingsRecomputed());
            metadata.put("message", response.message());
            run.setMetadataJson(toJson(metadata));
            syncRunRepository.save(run);
            sccmCmdbConfigRepository.findById(configId).ifPresent(cfg -> {
                cfg.setLastSyncAt(Instant.now());
                sccmCmdbConfigRepository.save(cfg);
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
            run.setMetadataJson(toJson(Map.of(
                    "triggerMode", triggerMode,
                    "state", "failed",
                    "sourceSystem", "sccm",
                    "assetType", "HOST"
            )));
            syncRunRepository.save(run);
        });
    }

    // ── Utilities ──────────────────────────────────────────────────────────────────────────────

    private boolean isConfigured(SccmCmdbConfig config) {
        return config != null
                && config.getTenant() != null
                && (config.isMockMode() || hasText(config.getJdbcUrl()));
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

    private String defaultIfBlank(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record ClaimedRun(
            UUID configId,
            UUID runId,
            boolean reusedActiveRun
    ) {}

    private record ConfigRef(UUID configId, UUID tenantId) {}
}
