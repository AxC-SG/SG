package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.FindingDeltaQueueEntry;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingDeltaQueueEntryRepository;
import jakarta.annotation.PostConstruct;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * BLG-006: Durable delta queue backed by PostgreSQL.
 *
 * Replaces the previous in-memory ThreadPoolTaskExecutor approach, which lost events
 * on application restart and dropped them silently under backpressure.
 *
 * Events are written transactionally to finding_delta_queue and processed by a
 * scheduled poller using SELECT FOR UPDATE SKIP LOCKED, with automatic retry on failure. Effective writes must remain idempotent.
 */
@Service
public class FindingDeltaQueueService {

    private static final Logger LOG = LoggerFactory.getLogger(FindingDeltaQueueService.class);
    private static final String INTERRUPTED_PROCESSING_MESSAGE =
            "Delta processing interrupted by service restart or stalled worker";
    static final String SOFTWARE_DELTA = "SOFTWARE_DELTA";
    static final String CVE_DELTA = "CVE_DELTA";
    static final String CVE_METADATA_DELTA = "CVE_METADATA_DELTA";
    static final String VEX_DELTA = "VEX_DELTA";
    static final String LIFECYCLE_DELTA = "LIFECYCLE_DELTA";
    static final String NOISE_REDUCTION_REFRESH = "NOISE_REDUCTION_REFRESH";

    private static final int POLL_BATCH_SIZE = 100;
    private static final int SOFTWARE_BATCH_SIZE = 250;
    private static final int CVE_BATCH_SIZE = 100;
    private static final int CVE_METADATA_BATCH_SIZE = 250;
    private static final int LIFECYCLE_BATCH_SIZE = 500;

    private final FindingDeltaQueueEntryRepository repository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final FindingRecomputeService findingRecomputeService;
    private final DashboardNoiseReductionProjectionService dashboardNoiseReductionProjectionService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    @org.springframework.beans.factory.annotation.Value("${app.correlation.delta-queue-stale-processing-threshold-minutes:30}")
    private long staleProcessingThresholdMinutes;
    @org.springframework.beans.factory.annotation.Value("${app.correlation.delta-queue-max-batches-per-tenant-per-poll:5}")
    private int maxBatchesPerTenantPerPoll;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();
    private TransactionTemplate writeTransactionTemplate;
    private TransactionTemplate enqueueTransactionTemplate;

    public FindingDeltaQueueService(
            FindingDeltaQueueEntryRepository repository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            FindingRecomputeService findingRecomputeService,
            DashboardNoiseReductionProjectionService dashboardNoiseReductionProjectionService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.repository = repository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.findingRecomputeService = findingRecomputeService;
        this.dashboardNoiseReductionProjectionService = dashboardNoiseReductionProjectionService;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager == null) {
            this.writeTransactionTemplate = null;
            this.enqueueTransactionTemplate = null;
            return;
        }
        this.enqueueTransactionTemplate = new TransactionTemplate(transactionManager);
        this.enqueueTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRED);
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @PostConstruct
    public void recoverInterruptedProcessingEntries() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-delta-queue.recover-interrupted-processing")) {
            return;
        }
        int recovered = recoverStaleProcessingEntries();
        if (recovered > 0) {
            LOG.warn("Recovered {} finding delta entries left PROCESSING by a previous worker lifecycle", recovered);
        }
    }

    @Scheduled(fixedDelayString = "${app.correlation.delta-queue-stale-recovery-interval-ms:60000}")
    public void recoverStaleProcessingEntriesOnSchedule() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-delta-queue.recover-stale-processing")) {
            return;
        }
        try {
            int recovered = recoverStaleProcessingEntries();
            if (recovered > 0) {
                LOG.warn("Recovered {} stale finding delta entries during scheduled recovery", recovered);
            }
        } catch (Exception ex) {
            LOG.warn("Delta queue stale-processing recovery failed: {}", ex.getMessage(), ex);
        }
    }

    // -------------------------------------------------------------------------
    // Public enqueueing API — same signatures as before
    // -------------------------------------------------------------------------

    public int enqueueSoftwareDeltas(UUID tenantId, Collection<UUID> componentIds, String sourceTag) {
        if (tenantId == null || componentIds == null || componentIds.isEmpty()) {
            return 0;
        }
        return executeEnqueue(() -> {
            int queued = 0;
            for (UUID componentId : sortedUniqueIds(componentIds)) {
                String key = "software:" + tenantId + ":" + componentId + ":" + normalizeTag(sourceTag);
                int inserted = repository.insertIfNotDuplicate(
                        SOFTWARE_DELTA, tenantId, componentId, null, null, normalizeTag(sourceTag), key);
                queued += inserted;
            }
            return queued;
        });
    }

    public int enqueueCveDeltas(Collection<UUID> vulnerabilityIds, String sourceTag) {
        if (vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return 0;
        }
        if (TenantContext.isPlatformContext()) return publishToActiveTenants(ids -> enqueueCveDeltas(ids, sourceTag), vulnerabilityIds);
        return executeEnqueue(() -> {
            int queued = 0;
            for (UUID vulnerabilityId : sortedUniqueIds(vulnerabilityIds)) {
                String key = "cve:" + vulnerabilityId + ":" + normalizeTag(sourceTag);
                int inserted = repository.insertIfNotDuplicate(
                        CVE_DELTA, null, null, vulnerabilityId, null, normalizeTag(sourceTag), key);
                queued += inserted;
            }
            return queued;
        });
    }

    public int enqueueCveMetadataDeltas(Collection<UUID> vulnerabilityIds, String sourceTag) {
        if (vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return 0;
        }
        if (TenantContext.isPlatformContext()) return publishToActiveTenants(ids -> enqueueCveMetadataDeltas(ids, sourceTag), vulnerabilityIds);
        return executeEnqueue(() -> {
            int queued = 0;
            for (UUID vulnerabilityId : sortedUniqueIds(vulnerabilityIds)) {
                String key = "cve-metadata:" + vulnerabilityId + ":" + normalizeTag(sourceTag);
                int inserted = repository.insertIfNotDuplicate(
                        CVE_METADATA_DELTA, null, null, vulnerabilityId, null, normalizeTag(sourceTag), key);
                queued += inserted;
            }
            return queued;
        });
    }

    public int enqueueVexDeltas(Collection<UUID> vulnerabilityIds, String sourceKey, String sourceTag) {
        if (vulnerabilityIds == null || vulnerabilityIds.isEmpty()) {
            return 0;
        }
        if (TenantContext.isPlatformContext()) return publishToActiveTenants(ids -> enqueueVexDeltas(ids, sourceKey, sourceTag), vulnerabilityIds);
        return executeEnqueue(() -> {
            int queued = 0;
            for (UUID vulnerabilityId : sortedUniqueIds(vulnerabilityIds)) {
                String normalizedSourceKey = normalizeTag(sourceKey);
                String normalizedTag = normalizeTag(sourceTag);
                String key = "vex:" + vulnerabilityId + ":" + normalizedSourceKey + ":" + normalizedTag;
                int inserted = repository.insertIfNotDuplicate(
                        VEX_DELTA, null, null, vulnerabilityId, normalizedSourceKey, normalizedTag, key);
                queued += inserted;
            }
            return queued;
        });
    }

    /** Global feed changes use the existing per-tenant outboxes. Never certify complete fanout after a tenant failure. */
    private int publishToActiveTenants(java.util.function.ToIntFunction<Collection<UUID>> enqueue,Collection<UUID> ids) {
        if (org.springframework.transaction.support.TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Platform delta fanout must select the tenant before opening its publication transaction");
        }
        int published=0,failed=0;
        for (Tenant tenant:tenantService.listActiveTenants()) {
            try { published+=tenantSchemaExecutionService.run(tenant,() -> enqueue.applyAsInt(ids)); }
            catch (RuntimeException unavailable) { failed++; LOG.warn("Platform delta publication is pending for tenant {}",tenant.getId()); }
        }
        if (failed>0) throw new IllegalStateException("Platform delta publication is incomplete for "+failed+" tenant(s); replay the retained feed run");
        return published;
    }

    public int enqueueLifecycleDeltas(UUID tenantId, Collection<UUID> componentIds, String sourceTag) {
        if (tenantId == null || componentIds == null || componentIds.isEmpty()) {
            return 0;
        }
        return executeEnqueue(() -> {
            int queued = 0;
            for (UUID componentId : sortedUniqueIds(componentIds)) {
                String key = "lifecycle:" + tenantId + ":" + componentId + ":" + normalizeTag(sourceTag);
                int inserted = repository.insertIfNotDuplicate(
                        LIFECYCLE_DELTA, tenantId, componentId, null, null, normalizeTag(sourceTag), key);
                queued += inserted;
            }
            return queued;
        });
    }

    public int enqueueNoiseReductionRefresh(UUID tenantId, String sourceTag) {
        if (tenantId == null) {
            return 0;
        }
        return executeEnqueue(() -> repository.insertIfNotDuplicate(
                NOISE_REDUCTION_REFRESH,
                tenantId,
                null,
                null,
                null,
                normalizeTag(sourceTag),
                "noise:" + tenantId
        ));
    }

    public long queueDepth() {
        return repository.countPending();
    }

    int recoverStaleProcessingEntries() {
        return TenantContext.runAsPlatform(() -> {
            Instant recoveredAt = Instant.now();
            Instant cutoff = recoveredAt.minus(staleProcessingThresholdMinutes, ChronoUnit.MINUTES);
            int recovered = 0;
            for (Tenant tenant : tenantService.listActiveTenants()) {
                try {
                    int tenantRecovered = tenantSchemaExecutionService.run(tenant,
                            () -> recoverStaleProcessingEntriesForTenant(cutoff, recoveredAt));
                    recovered += tenantRecovered;
                    if (tenantRecovered > 0) {
                        LOG.warn("Recovered {} stale PROCESSING delta entries for tenant {}", tenantRecovered, tenant.getId());
                    }
                } catch (Exception ex) {
                    LOG.warn("Delta queue stale-processing recovery failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                }
            }
            return recovered;
        });
    }

    // -------------------------------------------------------------------------
    // Scheduled poller — runs every 2 s by default, configurable
    // -------------------------------------------------------------------------

    @Scheduled(fixedDelayString = "${app.correlation.delta-queue-poll-interval-ms:2000}")
    public void processPendingDeltas() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-delta-queue.process-pending-deltas")) {
            return;
        }
        // finding_delta_queue is per-tenant. The scheduler thread carries no tenant context, so the
        // queue claim + status updates land in the default schema — without iterating tenants this only
        // ever drained tenant_default and left every other tenant's deltas PENDING forever (so their
        // findings/projections never recomputed). Drain each tenant's queue inside its own schema
        // context. Never let an exception escape: a @Scheduled task that throws is not rescheduled.
        try {
            TenantContext.runAsPlatform(() -> {
                for (Tenant tenant : tenantService.listActiveTenants()) {
                    try {
                        tenantSchemaExecutionService.run(tenant, () -> {
                            int batchesProcessed = 0;
                            int maxBatches = Math.max(1, maxBatchesPerTenantPerPoll);
                            while (batchesProcessed < maxBatches) {
                                if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-delta-queue.claim")) break;
                                List<FindingDeltaQueueEntry> claimed = claimBatch();
                                if (claimed.isEmpty()) {
                                    break;
                                }
                                LOG.debug("Delta queue: claimed {} entries for tenant {} (batch {}/{})",
                                        claimed.size(),
                                        tenant.getId(),
                                        batchesProcessed + 1,
                                        maxBatches);
                                processClaimedBatch(claimed);
                                batchesProcessed += 1;
                            }
                            if (batchesProcessed == maxBatches) {
                                LOG.debug("Delta queue: paused tenant {} after {} batches to keep one poll cycle bounded",
                                        tenant.getId(),
                                        maxBatches);
                            }
                            return null;
                        });
                    } catch (Exception ex) {
                        LOG.warn("Delta queue processing failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                    }
                }
            });
        } catch (Exception ex) {
            LOG.warn("Delta queue poll cycle failed before tenant iteration: {}", ex.getMessage(), ex);
        }
    }

    // -------------------------------------------------------------------------
    // Internal — transactional helpers called via Spring proxy
    // -------------------------------------------------------------------------

    List<FindingDeltaQueueEntry> claimBatch() {
        return executeWrite(() -> {
            if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-delta-queue.claim")) return List.of();
            List<FindingDeltaQueueEntry> entries = repository.pollPending(POLL_BATCH_SIZE);
            if (entries.isEmpty()) {
                return entries;
            }
            Instant now = Instant.now();
            for (FindingDeltaQueueEntry e : entries) {
                e.setStatus("PROCESSING");
                e.setProcessingStartedAt(now);
                e.setAttemptCount(e.getAttemptCount() + 1);
            }
            repository.saveAll(entries);
            return entries;
        });
    }

    // Not @Transactional — manages its own sub-transactions via findingRecomputeService
    void processClaimedBatch(List<FindingDeltaQueueEntry> claimed) {
        if (writeTransactionTemplate == null) { processOwnedBatch(claimed); return; }
        try {
            executeWrite(() -> {
                List<FindingDeltaQueueEntry> owned = claimed.stream()
                        .sorted(java.util.Comparator.comparing(FindingDeltaQueueEntry::getId))
                        .map(entry -> repository.lockProcessingAttempt(entry.getId(),entry.getAttemptCount()))
                        .flatMap(java.util.Optional::stream).toList();
                // Locks fence both domain effects and acknowledgments. Recovery
                // skips these healthy owners even after the stale-time threshold.
                processOwnedBatch(owned);
                return null;
            });
        } catch (RuntimeException failure) {
            // A joined domain transaction may mark the batch rollback-only.
            // Record retry only after its effects and row locks have rolled back.
            markFailedOrRetry(claimed,failure.getMessage());
        }
    }

    private void processOwnedBatch(List<FindingDeltaQueueEntry> claimed) {
        Map<String, List<FindingDeltaQueueEntry>> byType = claimed.stream()
                .collect(Collectors.groupingBy(FindingDeltaQueueEntry::getEventType, java.util.LinkedHashMap::new, Collectors.toList()));
        byType.forEach((eventType, entries) -> {
            switch (eventType) {
                case SOFTWARE_DELTA -> processSoftwareEntries(entries);
                case CVE_DELTA -> processVulnerabilityEntries(entries, CVE_BATCH_SIZE, ids -> findingRecomputeService.recomputeOnCveDeltaBatch(ids));
                case CVE_METADATA_DELTA -> processVulnerabilityEntries(entries, CVE_METADATA_BATCH_SIZE, ids -> findingRecomputeService.refreshMetadataForVulnerabilityBatch(ids));
                case VEX_DELTA -> processVexEntries(entries);
                case LIFECYCLE_DELTA -> processLifecycleEntries(entries);
                case NOISE_REDUCTION_REFRESH -> processNoiseReductionEntries(entries);
                default -> entries.forEach(this::processEntryIndividually);
            }
        });
    }

    private void processSoftwareEntries(List<FindingDeltaQueueEntry> entries) {
        Map<UUID, List<FindingDeltaQueueEntry>> byTenant = entries.stream()
                .filter(entry -> entry.getTenantId() != null && entry.getComponentId() != null)
                .collect(Collectors.groupingBy(FindingDeltaQueueEntry::getTenantId, java.util.LinkedHashMap::new, Collectors.toList()));
        byTenant.values().forEach(tenantEntries -> processComponentEntries(tenantEntries, SOFTWARE_BATCH_SIZE, false));
        entries.stream()
                .filter(entry -> entry.getTenantId() == null || entry.getComponentId() == null)
                .forEach(entry -> markDone(entry.getId(), 0));
    }

    private void processLifecycleEntries(List<FindingDeltaQueueEntry> entries) {
        Map<UUID, List<FindingDeltaQueueEntry>> byTenant = entries.stream()
                .filter(entry -> entry.getTenantId() != null && entry.getComponentId() != null)
                .collect(Collectors.groupingBy(FindingDeltaQueueEntry::getTenantId, java.util.LinkedHashMap::new, Collectors.toList()));
        byTenant.values().forEach(tenantEntries -> processComponentEntries(tenantEntries, LIFECYCLE_BATCH_SIZE, true));
        entries.stream()
                .filter(entry -> entry.getTenantId() == null || entry.getComponentId() == null)
                .forEach(entry -> markDone(entry.getId(), 0));
    }

    private void processComponentEntries(
            List<FindingDeltaQueueEntry> entries,
            int batchSize,
            boolean lifecycleOnly
    ) {
        UUID tenantId = entries.get(0).getTenantId();
        for (List<FindingDeltaQueueEntry> chunk : chunk(entries, batchSize)) {
            try {
                List<UUID> componentIds = chunk.stream()
                        .map(FindingDeltaQueueEntry::getComponentId)
                        .filter(Objects::nonNull)
                        .distinct()
                        .toList();
                int affected = runInTenantSchema(
                        tenantId,
                        () -> lifecycleOnly
                                ? findingRecomputeService.refreshLifecycleForComponents(tenantId, componentIds)
                                : findingRecomputeService.recomputeOnSoftwareDeltaBatch(tenantId, componentIds)
                );
                markDone(chunk.stream().map(FindingDeltaQueueEntry::getId).toList(), affected);
                if (!lifecycleOnly) {
                    enqueueNoiseReductionRefresh(tenantId, "software-delta");
                }
            } catch (RuntimeException ex) {
                LOG.warn("Failed processing {} component delta entries for tenant {}: {}",
                        lifecycleOnly ? "lifecycle" : "software", tenantId, ex.getMessage(), ex);
                markFailedOrRetry(chunk, ex.getMessage());
            }
        }
    }

    private void processVulnerabilityEntries(
            List<FindingDeltaQueueEntry> entries,
            int batchSize,
            java.util.function.Function<Collection<UUID>, Integer> processor
    ) {
        List<FindingDeltaQueueEntry> validEntries = entries.stream()
                .filter(entry -> entry.getVulnerabilityId() != null)
                .toList();
        for (List<FindingDeltaQueueEntry> chunk : chunk(validEntries, batchSize)) {
            try {
                List<UUID> vulnerabilityIds = chunk.stream()
                        .map(FindingDeltaQueueEntry::getVulnerabilityId)
                        .filter(Objects::nonNull)
                        .distinct()
                        .toList();
                int affected = processor.apply(vulnerabilityIds);
                markDone(chunk.stream().map(FindingDeltaQueueEntry::getId).toList(), affected);
                enqueueNoiseReductionRefreshForTenants(
                        componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(vulnerabilityIds),
                        "vulnerability-delta"
                );
            } catch (RuntimeException ex) {
                LOG.warn("Failed processing vulnerability delta entries type={}: {}",
                        validEntries.isEmpty() ? "unknown" : validEntries.get(0).getEventType(), ex.getMessage(), ex);
                markFailedOrRetry(chunk, ex.getMessage());
            }
        }
        entries.stream()
                .filter(entry -> entry.getVulnerabilityId() == null)
                .forEach(entry -> markDone(entry.getId(), 0));
    }

    private void processVexEntries(List<FindingDeltaQueueEntry> entries) {
        Map<String, List<FindingDeltaQueueEntry>> bySourceKey = entries.stream()
                .collect(Collectors.groupingBy(entry -> normalizeTag(entry.getSourceKey()), java.util.LinkedHashMap::new, Collectors.toList()));
        bySourceKey.forEach((sourceKey, sourceEntries) -> {
            List<FindingDeltaQueueEntry> validEntries = sourceEntries.stream()
                    .filter(entry -> entry.getVulnerabilityId() != null)
                    .toList();
            for (List<FindingDeltaQueueEntry> chunk : chunk(validEntries, CVE_BATCH_SIZE)) {
                try {
                    List<UUID> vulnerabilityIds = chunk.stream()
                            .map(FindingDeltaQueueEntry::getVulnerabilityId)
                            .filter(Objects::nonNull)
                            .distinct()
                            .toList();
                    int affected = findingRecomputeService.applyVexDeltaBatch(vulnerabilityIds, sourceKey);
                    markDone(chunk.stream().map(FindingDeltaQueueEntry::getId).toList(), affected);
                    enqueueNoiseReductionRefreshForTenants(
                            componentVulnerabilityStateRepository.findDistinctTenantIdsByVulnerabilityIds(vulnerabilityIds),
                            "vex-delta"
                    );
                } catch (RuntimeException ex) {
                    LOG.warn("Failed processing VEX delta entries sourceKey={}: {}", sourceKey, ex.getMessage(), ex);
                    markFailedOrRetry(chunk, ex.getMessage());
                }
            }
            sourceEntries.stream()
                    .filter(entry -> entry.getVulnerabilityId() == null)
                    .forEach(entry -> markDone(entry.getId(), 0));
        });
    }

    private void processNoiseReductionEntries(List<FindingDeltaQueueEntry> entries) {
        Map<UUID, List<FindingDeltaQueueEntry>> byTenant = entries.stream()
                .filter(entry -> entry.getTenantId() != null)
                .collect(Collectors.groupingBy(FindingDeltaQueueEntry::getTenantId, java.util.LinkedHashMap::new, Collectors.toList()));
        byTenant.forEach((tenantId, tenantEntries) -> {
            try {
                int refreshed = runInTenantSchema(tenantId, () -> dashboardNoiseReductionProjectionService.refreshTenant(tenantId));
                markDone(tenantEntries.stream().map(FindingDeltaQueueEntry::getId).toList(), refreshed);
            } catch (RuntimeException ex) {
                LOG.warn("Failed processing noise reduction refresh for tenant {}: {}", tenantId, ex.getMessage(), ex);
                markFailedOrRetry(tenantEntries, ex.getMessage());
            }
        });
        entries.stream()
                .filter(entry -> entry.getTenantId() == null)
                .forEach(entry -> markDone(entry.getId(), 0));
    }

    void processEntryIndividually(FindingDeltaQueueEntry entry) {
        try {
            int affected = switch (entry.getEventType()) {
                case SOFTWARE_DELTA -> runInTenantSchema(
                        entry.getTenantId(),
                        () -> findingRecomputeService.recomputeOnSoftwareDelta(entry.getTenantId(), entry.getComponentId()));
                case CVE_DELTA -> findingRecomputeService.recomputeOnCveDelta(
                        entry.getVulnerabilityId());
                case CVE_METADATA_DELTA -> findingRecomputeService.refreshMetadataForVulnerabilityBatch(
                        entry.getVulnerabilityId() == null ? List.of() : List.of(entry.getVulnerabilityId()));
                case VEX_DELTA -> findingRecomputeService.applyVexDeltaForVulnerability(
                        entry.getVulnerabilityId(), entry.getSourceKey());
                case LIFECYCLE_DELTA -> runInTenantSchema(
                        entry.getTenantId(),
                        () -> findingRecomputeService.refreshLifecycleForComponents(
                                entry.getTenantId(),
                                entry.getComponentId() == null ? List.of() : List.of(entry.getComponentId())));
                case NOISE_REDUCTION_REFRESH -> runInTenantSchema(
                        entry.getTenantId(),
                        () -> dashboardNoiseReductionProjectionService.refreshTenant(entry.getTenantId()));
                default -> {
                    LOG.warn("Unknown delta event type '{}' for entry id={}", entry.getEventType(), entry.getId());
                    yield 0;
                }
            };
            markDone(entry.getId(), affected);
        } catch (RuntimeException ex) {
            LOG.warn("Failed processing delta entry id={} type={}: {}",
                    entry.getId(), entry.getEventType(), ex.getMessage(), ex);
            markFailedOrRetry(entry.getId(), entry.getAttemptCount(), entry.getMaxAttempts(), ex.getMessage());
        }
    }

    void markDone(Long id, int affected) {
        markDone(List.of(id), affected);
    }

    void markDone(Collection<Long> ids, int affected) {
        executeEnqueue(() -> {
            Instant completedAt = Instant.now();
            for (Long id : ids) {
                repository.findById(id).ifPresent(e -> {
                    e.setStatus("DONE");
                    e.setCompletedAt(completedAt);
                    repository.save(e);
                    LOG.debug("Delta entry id={} type={} marked DONE, affected={}", id, e.getEventType(), affected);
                });
            }
            return null;
        });
    }

    void markFailedOrRetry(Long id, int attemptCount, int maxAttempts, String errorMessage) {
        executeEnqueue(() -> {
            (writeTransactionTemplate == null ? repository.findById(id)
                    : repository.lockProcessingAttempt(id,attemptCount)).ifPresent(e -> {
                e.setErrorMessage(errorMessage);
                e.setProcessingStartedAt(null);
                if (attemptCount >= maxAttempts || repository.existsByDedupeKeyAndStatus(e.getDedupeKey(),"PENDING")) {
                    e.setStatus("FAILED");
                    e.setCompletedAt(Instant.now());
                    LOG.error("Delta entry id={} type={} FAILED after {} attempts: {}",
                            id, e.getEventType(), attemptCount, errorMessage);
                } else {
                    long backoffSeconds = 60L * (1L << (attemptCount - 1));
                    e.setStatus("PENDING");
                    e.setVisibleAfter(Instant.now().plusSeconds(backoffSeconds));
                    LOG.warn("Delta entry id={} type={} scheduled for retry in {}s (attempt {}/{})",
                            id, e.getEventType(), backoffSeconds, attemptCount, maxAttempts);
                }
                repository.save(e);
            });
            return null;
        });
    }

    void markFailedOrRetry(List<FindingDeltaQueueEntry> entries, String errorMessage) {
        entries.forEach(entry ->
                markFailedOrRetry(entry.getId(), entry.getAttemptCount(), entry.getMaxAttempts(), errorMessage));
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private List<UUID> sortedUniqueIds(Collection<UUID> ids) {
        return ids.stream()
                .filter(id -> id != null)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new))
                .stream()
                .sorted(UUID::compareTo)
                .toList();
    }

    private <T> List<List<T>> chunk(List<T> entries, int chunkSize) {
        if (entries == null || entries.isEmpty()) {
            return List.of();
        }
        List<List<T>> chunks = new java.util.ArrayList<>();
        for (int start = 0; start < entries.size(); start += chunkSize) {
            int end = Math.min(start + chunkSize, entries.size());
            chunks.add(entries.subList(start, end));
        }
        return chunks;
    }

    private static String normalizeTag(String value) {
        if (value == null || value.isBlank()) {
            return "default";
        }
        return value.trim().toLowerCase(Locale.ROOT);
    }

    private int recoverStaleProcessingEntriesForTenant(Instant cutoff, Instant recoveredAt) {
        return executeWrite(() -> {
            List<FindingDeltaQueueEntry> staleEntries = repository.findStaleProcessingEntries(cutoff);
            if (staleEntries.isEmpty()) {
                return 0;
            }
            for (FindingDeltaQueueEntry entry : staleEntries) {
                entry.setProcessingStartedAt(null);
                if (entry.getErrorMessage() == null || entry.getErrorMessage().isBlank()) {
                    entry.setErrorMessage(INTERRUPTED_PROCESSING_MESSAGE);
                }
                if (entry.getAttemptCount() >= entry.getMaxAttempts()
                        || repository.existsByDedupeKeyAndStatus(entry.getDedupeKey(),"PENDING")) {
                    entry.setStatus("FAILED");
                    if (entry.getCompletedAt() == null) {
                        entry.setCompletedAt(recoveredAt);
                    }
                } else {
                    entry.setStatus("PENDING");
                    entry.setVisibleAfter(recoveredAt);
                }
            }
            repository.saveAll(staleEntries);
            return staleEntries.size();
        });
    }

    private void enqueueNoiseReductionRefreshForTenants(Collection<UUID> tenantIds, String sourceTag) {
        if (tenantIds == null || tenantIds.isEmpty()) {
            return;
        }
        for (UUID tenantId : tenantIds) {
            enqueueNoiseReductionRefresh(tenantId, sourceTag);
        }
    }

    private int runInTenantSchema(UUID tenantId, java.util.function.IntSupplier supplier) {
        if (tenantId == null) {
            return supplier.getAsInt();
        }
        var tenant = tenantService.resolveTenantUuid(tenantId);
        UUID previousTenantId = TenantContext.getCurrentTenantId();
        String previousSchema = TenantContext.getCurrentSchemaName();
        try {
            TenantContext.setCurrentTenantId(tenantId);
            TenantContext.setCurrentSchemaName(tenant.getSchemaName());
            return supplier.getAsInt();
        } finally {
            if (previousTenantId == null) {
                TenantContext.clear();
            } else {
                TenantContext.setCurrentTenantId(previousTenantId);
                TenantContext.setCurrentSchemaName(previousSchema);
            }
        }
    }

    private <T> T executeEnqueue(Supplier<T> work) {
        // Publication participates in the source transaction. Claims and acknowledgments
        // deliberately keep their independent short transactions below.
        return enqueueTransactionTemplate == null ? work.get()
                : enqueueTransactionTemplate.execute(status -> work.get());
    }

    private <T> T executeWrite(Supplier<T> work) {
        if (writeTransactionTemplate == null) {
            return work.get();
        }
        return writeTransactionTemplate.execute(status -> work.get());
    }
}
