package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.client.JvnApiClient;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.ObservationIngestionService;
import com.prototype.vulnwatch.service.VulnerabilityIntelligenceService;
import java.util.List;
import java.util.LinkedHashSet;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskExecutor;
import org.springframework.stereotype.Service;

@Service
public class JvnSyncService {

    private final JvnApiClient jvnApiClient;
    private final ObservationIngestionService observationIngestionService;
    private final VulnerabilitySyncRunService syncRunService;
    private final VulnerabilityIngestionEffectsService effectsService;
    private final TaskExecutor ingestionExecutor;
    private final VulnerabilityRepository vulnerabilityRepository;

    @Value("${app.jvn.max-pages-per-sync:100}")
    private int maxPagesPerSync;

    private FeedRunCheckpointService checkpoints;

    @org.springframework.beans.factory.annotation.Autowired
    void configureCheckpoints(FeedRunCheckpointService checkpoints) {
        this.checkpoints = checkpoints;
    }

    private record Scope(JvnApiClient.Scan request, int maxPages) {}

    public JvnSyncService(
            JvnApiClient jvnApiClient,
            ObservationIngestionService observationIngestionService,
            VulnerabilitySyncRunService syncRunService,
            VulnerabilityIngestionEffectsService effectsService,
            @Qualifier("integrationQueueExecutor") TaskExecutor ingestionExecutor,
            VulnerabilityRepository vulnerabilityRepository
    ) {
        this.jvnApiClient = jvnApiClient;
        this.observationIngestionService = observationIngestionService;
        this.syncRunService = syncRunService;
        this.effectsService = effectsService;
        this.ingestionExecutor = ingestionExecutor;
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    public SyncTriggerResponse triggerJvnSync() {
        VulnerabilitySyncRunService.TriggerDecision decision =
                syncRunService.prepareQueuedRun("JVN", List.of("JVN"));
        return decision.toResponse("JVN sync is already in progress", "JVN sync queued");
    }

    public void executeJvnSyncAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeJvnSync(run);
    }

    public IngestionResult syncJvn() {
        SyncRun run = syncRunService.createRunningRun("JVN");
        return executeJvnSync(run);
    }

    private IngestionResult executeJvnSync(SyncRun run) {
        var progress = FeedRunCheckpointService.Progress.initial();
        Set<UUID> changedVulnerabilityIds = new LinkedHashSet<>();
        Set<String> seen = new HashSet<>();
        try {
            var scope = checkpoints == null
                    ? new FeedRunCheckpointService.RunScope<>(new Scope(null, Math.max(1, maxPagesPerSync)), progress)
                    : checkpoints.open(run, "jvn", Scope.class,
                            () -> new Scope(jvnApiClient.scan(), Math.max(1, maxPagesPerSync)));
            progress = scope.progress();
            Map<String, Object> metadata = new java.util.LinkedHashMap<>();
            metadata.put("pageSize", scope.input().request() == null ? jvnApiClient.perPage() : scope.input().request().pageSize());
            metadata.put("maxPagesPerSync", scope.input().maxPages());
            syncRunService.applyRunMetadata(run, "jvn", metadata);

            while (!progress.finished() && progress.nextBatch() < scope.input().maxPages()) {
                int position = Math.addExact(Math.multiplyExact(progress.nextBatch(),
                        checkpoints == null ? jvnApiClient.perPage() : scope.input().request().pageSize()), 1);
                var page = checkpoints == null ? jvnApiClient.fetchPage(position) : jvnApiClient.fetchPage(position, scope.input().request());
                if (page.startItem() != position) throw new IllegalStateException("JVN returned an unexpected page position");
                Integer total = page.totalResults();
                if (progress.reportedTotal() != null && !progress.reportedTotal().equals(total)) {
                    throw new IllegalStateException("JVN reported total changed during pagination");
                }
                int fetched = Math.addExact(progress.fetched(), page.records().size());
                if (total != null && fetched > total) throw new IllegalStateException("JVN returned more records than its reported total");
                boolean finished = total != null && fetched == total;
                if (page.records().isEmpty() || page.records().size() < page.maxCountItem()) {
                    if (total != null && fetched < total) throw new IllegalStateException("JVN returned an incomplete page");
                    finished = true;
                }
                var keys = page.records().stream().map(JvnApiClient.JvnRecord::sourceRecordId).toList();
                java.util.function.Supplier<FeedRunCheckpointService.Counts> stage =
                        () -> stagePage(page.records(), changedVulnerabilityIds);
                if (checkpoints != null) {
                    progress = checkpoints.commit(run, progress, null, keys, null, total, finished, stage);
                } else {
                    for (String key : keys) {
                        if (key == null || key.isBlank() || !seen.add(key)) {
                            throw new IllegalStateException("JVN returned a missing or repeated source record ID");
                        }
                    }
                    progress = progress.advance(null, total, stage.get(), finished);
                    run.setRecordsFetched(progress.fetched());
                    run.setRecordsInserted(progress.inserted());
                    run.setRecordsUpdated(progress.updated());
                    syncRunService.save(run);
                }
            }
            if (!progress.finished()) throw new IllegalStateException("JVN page limit reached before the feed ended");
            effectsService.enqueueCveMetadataDeltas(changedVulnerabilityIds);
            return complete(run, progress, "completed", "JVN sync complete");
        } catch (VulnerabilityAttemptService.StaleAttemptException stale) {
            throw stale;
        } catch (Exception failure) {
            return complete(run, progress, "failed", failure.getMessage());
        }
    }

    private FeedRunCheckpointService.Counts stagePage(List<JvnApiClient.JvnRecord> records, Set<UUID> changed) {
        int inserted = 0;
        int updated = 0;
        for (var record : records) {
            VulnerabilityIntelligenceService.ObservationUpsertResult result =
                observationIngestionService.upsertObservation(
                        new VulnerabilityIntelligenceService.ObservationUpsertRequest(
                                record.externalId(),
                                "japan-vulndb",
                                record.sourceRecordId(),
                                record.sourceUrl(),
                                record.title(),
                                record.description(),
                                record.severity() == null ? "UNKNOWN" : record.severity(),
                                record.cvssScore(),
                                record.cvssVector(),
                                null,
                                Boolean.FALSE,
                                null,
                                null,
                                null,
                                record.sourceRecordId(),
                                record.publishedAt(),
                                record.lastModifiedAt(),
                                record.rawJson()
                        )
                );
            Vulnerability vulnerability = result.vulnerability();
            if (vulnerability != null && vulnerability.getId() != null) changed.add(vulnerability.getId());
            if (result.vulnerabilityCreated()) inserted++;
            else updated++;
        }
        return new FeedRunCheckpointService.Counts(records.size(), inserted, updated, 0);
    }

    private IngestionResult complete(SyncRun run, FeedRunCheckpointService.Progress progress, String status, String message) {
        boolean ok = "completed".equals(status);
        syncRunService.completeRun(run, status, progress.fetched(), progress.inserted(), progress.updated(), 0, ok ? null : message);
        return new IngestionResult(ok ? "ok" : status, progress.fetched(), progress.inserted(), progress.updated(), message);
    }
}
