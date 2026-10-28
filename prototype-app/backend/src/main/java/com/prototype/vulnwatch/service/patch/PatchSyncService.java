package com.prototype.vulnwatch.service.patch;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.PatchConnectorConfig;
import com.prototype.vulnwatch.domain.PatchProviderType;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.FixAssetEventRepository;
import com.prototype.vulnwatch.repo.PatchConnectorConfigRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.WorkspaceService;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Admission, scheduling and execution of patch syncs, for every provider.
 *
 * <p>Same contract as the inventory connectors: the configuration row is the admission lock,
 * one run is active per tenant per provider, the work is a durable {@code PATCH_SYNC} ingestion
 * job, and queued work is re-checked against its tenant before it runs. Background callers
 * establish the tenant context before opening any transaction.
 */
@Service
public class PatchSyncService {

    private static final Logger LOG = LoggerFactory.getLogger(PatchSyncService.class);

    private final PatchConnectorConfigRepository configs;
    private final PatchConnectorService connectorService;
    private final PatchProviderRegistry registry;
    private final PatchIngestionService ingestion;
    private final FixAssetEventRepository events;
    private final SyncRunRepository syncRuns;
    private final ObjectMapper objectMapper;
    private final TransactionTemplate transactionTemplate;
    private final WorkspaceService workspaceService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final IngestionJobService jobs;
    private final int eventRetentionDays;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public PatchSyncService(
            PatchConnectorConfigRepository configs,
            PatchConnectorService connectorService,
            PatchProviderRegistry registry,
            PatchIngestionService ingestion,
            FixAssetEventRepository events,
            SyncRunRepository syncRuns,
            ObjectMapper objectMapper,
            TransactionTemplate transactionTemplate,
            WorkspaceService workspaceService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            IngestionJobService jobs,
            @Value("${app.patch.event-retention-days:400}") int eventRetentionDays
    ) {
        this.configs = configs;
        this.connectorService = connectorService;
        this.registry = registry;
        this.ingestion = ingestion;
        this.events = events;
        this.syncRuns = syncRuns;
        this.objectMapper = objectMapper;
        this.transactionTemplate = transactionTemplate;
        this.workspaceService = workspaceService;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.jobs = jobs;
        this.eventRetentionDays = Math.max(30, eventRetentionDays);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy policy) {
        this.backgroundTaskExecutionPolicy = policy == null ? BackgroundTaskExecutionPolicy.allowAll() : policy;
    }

    // ── Admission ────────────────────────────────────────────────────────────────────────────

    public SyncTriggerResponse trigger(PatchProviderType type) {
        Tenant tenant = workspaceService.getWorkspace();
        PatchProvider provider = registry.require(type);
        ClaimedRun claimed = jobs.withAdmission(tenant, () -> {
            PatchConnectorConfig config = connectorService.findConfig(tenant, type)
                    .orElseThrow(() -> new IllegalStateException(type.displayName() + " patch connector is not configured"));
            ClaimedRun admitted = claim(provider, config, "manual", true);
            if (!admitted.reusedActiveRun()) jobs.enqueueConnectorJob(tenant, IngestionJobService.JOB_TYPE_PATCH_SYNC,
                    admitted.configId(), admitted.runId(), "manual", null);
            return admitted;
        });
        return claimed.reusedActiveRun()
                ? new SyncTriggerResponse(claimed.runId(), "running", type.displayName() + " patch sync is already queued or running")
                : new SyncTriggerResponse(claimed.runId(), "queued", type.displayName() + " patch sync queued");
    }

    @Scheduled(zone = "UTC", cron = "0 */5 * * * *")
    public void runScheduledSyncs() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("patch-sync.run-scheduled-syncs")) {
            return;
        }
        List<ConfigRef> due = TenantContext.runAsPlatform(() -> {
            List<ConfigRef> refs = new ArrayList<>();
            for (Tenant tenant : tenantService.listActiveTenants()) {
                tenantSchemaExecutionService.run(tenant, () -> {
                    for (PatchProviderType type : registry.types()) {
                        configs.findByTenant_IdAndProvider(tenant.getId(), type)
                                .filter(config -> config.isEnabled() && config.isAutoSyncEnabled())
                                .ifPresent(config -> refs.add(new ConfigRef(config.getId(), tenant.getId(), type)));
                    }
                    return null;
                });
            }
            return refs;
        });
        for (ConfigRef ref : due) {
            try {
                Tenant tenant = tenantService.resolveTenantUuid(ref.tenantId());
                PatchProvider provider = registry.require(ref.type());
                jobs.withAdmission(tenant, () -> {
                    PatchConnectorConfig config = configs.findById(ref.configId()).orElse(null);
                    ClaimedRun claimed = config == null ? null : claim(provider, config, "scheduled", false);
                    if (claimed != null) jobs.enqueueConnectorJob(tenant, IngestionJobService.JOB_TYPE_PATCH_SYNC,
                            claimed.configId(), claimed.runId(), "scheduled", null);
                    return null;
                });
            } catch (RuntimeException deferred) {
                LOG.warn("Scheduled patch connector {} admission deferred", ref.configId());
            }
        }
    }

    @Transactional(readOnly = true)
    public boolean hasActiveRun(PatchProviderType type) {
        Tenant tenant = workspaceService.getWorkspace();
        return !syncRuns.findActiveRunsByTenantAndSyncType(tenant.getId(), type.syncType(), List.of("queued", "running")).isEmpty();
    }

    private ClaimedRun claim(PatchProvider provider, PatchConnectorConfig config, String triggerMode, boolean allowReuse) {
        config = configs.findByIdAndTenantIdForUpdate(config.getId(), config.getTenant().getId())
                .orElseThrow(() -> new EntityNotFoundException("Patch connector config not found"));
        boolean usable = connectorService.isUsable(provider, config);
        if ("scheduled".equals(triggerMode)) {
            if (!usable || !config.isAutoSyncEnabled() || !isDue(config)) return null;
        } else if (!usable) {
            throw new IllegalStateException(provider.type().displayName() + " patch connector is disabled or has no credentials");
        }
        UUID tenantId = config.getTenant().getId();
        String syncType = provider.type().syncType();
        Optional<SyncRun> active = syncRuns.findActiveRunsByTenantAndSyncType(tenantId, syncType, List.of("queued", "running"))
                .stream().findFirst();
        if (active.isPresent()) {
            return allowReuse ? new ClaimedRun(config.getId(), active.get().getId(), true) : null;
        }
        SyncRun run = new SyncRun();
        run.setTenant(config.getTenant());
        run.setSyncType(syncType);
        run.setRunScope("TENANT_INVENTORY");
        run.setStatus("queued");
        run.setMetadataJson(toJson(Map.of("triggerMode", triggerMode, "provider", provider.type().name())));
        run = syncRuns.save(run);
        return new ClaimedRun(config.getId(), run.getId(), false);
    }

    private boolean isDue(PatchConnectorConfig config) {
        SyncRun latest = syncRuns.findTopBySyncTypeIgnoreCaseAndTenant_IdOrderByStartedAtDesc(
                config.getProvider().syncType(), config.getTenant().getId()).orElse(null);
        if (latest == null) return true;
        Instant reference = latest.getCompletedAt() != null ? latest.getCompletedAt() : latest.getStartedAt();
        if (reference == null) return true;
        int minutes = config.getIntervalMinutes() == null ? 1440 : Math.max(60, config.getIntervalMinutes());
        return Duration.between(reference, Instant.now()).toMinutes() >= minutes;
    }

    // ── Execution ────────────────────────────────────────────────────────────────────────────

    public void executeQueuedRun(UUID tenantId, UUID configId, UUID runId, String triggerMode) {
        tenantSchemaExecutionService.run(tenantId, () -> {
            markRun(runId, "running", null, Map.of("triggerMode", triggerMode, "state", "running"));
            try {
                PatchConnectorConfig config = configs.findById(configId)
                        .orElseThrow(() -> new EntityNotFoundException("Patch connector config not found: " + configId));
                if (!tenantId.equals(config.getTenant().getId())) {
                    throw new IllegalStateException("Queued patch sync does not belong to this tenant");
                }
                PatchProvider provider = registry.require(config.getProvider());
                if (!connectorService.isUsable(provider, config)) {
                    throw new IllegalStateException(provider.type().displayName() + " patch connector is disabled or has no credentials");
                }
                Tenant tenant = config.getTenant();
                PatchSnapshot snapshot = provider.fetch(tenant, config, connectorService.secret(provider, config));
                PatchIngestionService.Result result = ingestion.ingest(tenant, provider.type(), snapshot);
                finish(configId, runId, triggerMode, snapshot, result);
            } catch (Exception failure) {
                LOG.warn("Patch sync run {} failed: {}", runId, failure.getClass().getSimpleName());
                markRun(runId, "failed", PatchConnectorService.sanitize(failure.getMessage()),
                        Map.of("triggerMode", triggerMode, "state", "failed"));
            }
            return null;
        });
    }

    private void finish(UUID configId, UUID runId, String triggerMode, PatchSnapshot snapshot, PatchIngestionService.Result result) {
        transactionTemplate.executeWithoutResult(tx -> {
            SyncRun run = requireRun(runId);
            boolean warnings = !snapshot.complete() || !result.warnings().isEmpty();
            run.setStatus("completed");
            run.setRecordsFetched(snapshot.devices().size() + snapshot.patches().size() + snapshot.statuses().size());
            run.setRecordsInserted(result.hostsCreated() + result.cveLinks());
            run.setRecordsUpdated(result.patchesUpserted() + result.statusesUpserted());
            run.setRecordsFailed(result.devicesSkipped());
            run.setErrorMessage(warnings ? truncate(PatchConnectorService.sanitize(String.join(" | ", result.warnings())), 2000) : null);
            run.setCompletedAt(Instant.now());
            Map<String, Object> metadata = new LinkedHashMap<>();
            metadata.put("triggerMode", triggerMode);
            metadata.put("state", warnings ? "completed_with_errors" : "completed");
            metadata.put("complete", snapshot.complete());
            metadata.put("devicesMatched", result.devicesMatched());
            metadata.put("hostsCreated", result.hostsCreated());
            metadata.put("devicesSkipped", result.devicesSkipped());
            metadata.put("patchesUpserted", result.patchesUpserted());
            metadata.put("cveLinks", result.cveLinks());
            metadata.put("deployments", result.deploymentsUpserted());
            metadata.put("statuses", result.statusesUpserted());
            metadata.put("statusChanges", result.statusChanges());
            run.setMetadataJson(toJson(metadata));
            syncRuns.save(run);
            configs.findById(configId).ifPresent(config -> {
                config.setLastSyncAt(Instant.now());
                configs.save(config);
            });
        });
    }

    private void markRun(UUID runId, String status, String error, Map<String, Object> metadata) {
        transactionTemplate.executeWithoutResult(tx -> {
            SyncRun run = requireRun(runId);
            run.setStatus(status);
            run.setMetadataJson(toJson(metadata));
            if ("failed".equals(status)) {
                run.setErrorMessage(error == null ? "Patch sync failed" : truncate(error, 2000));
                run.setRecordsFailed(Math.max(1, run.getRecordsFailed()));
                run.setCompletedAt(Instant.now());
            }
            syncRuns.save(run);
        });
    }

    // ── Retention ────────────────────────────────────────────────────────────────────────────

    /** Patch status history is kept for a bounded window per tenant. */
    @Scheduled(zone = "UTC", cron = "0 40 3 * * *")
    public void purgeOldStatusEvents() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("patch-sync.purge-status-events")) {
            return;
        }
        Instant cutoff = Instant.now().minus(Duration.ofDays(eventRetentionDays));
        List<Tenant> tenants = TenantContext.runAsPlatform(tenantService::listActiveTenants);
        for (Tenant tenant : tenants) {
            try {
                tenantSchemaExecutionService.run(tenant, () -> transactionTemplate.execute(tx -> events.deleteOlderThan(cutoff)));
            } catch (RuntimeException failure) {
                LOG.warn("Patch status history purge deferred for tenant {}", tenant.getId());
            }
        }
    }

    private SyncRun requireRun(UUID runId) {
        return syncRuns.findById(runId).orElseThrow(() -> new EntityNotFoundException("Sync run not found: " + runId));
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception e) {
            return "{}";
        }
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }

    private record ClaimedRun(UUID configId, UUID runId, boolean reusedActiveRun) {}

    private record ConfigRef(UUID configId, UUID tenantId, PatchProviderType type) {}
}
