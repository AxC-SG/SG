package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.client.EuvdApiClient;
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
import org.springframework.core.task.TaskExecutor;
import org.springframework.stereotype.Service;

@Service
public class EuvdSyncService {

    private final EuvdApiClient euvdApiClient;
    private final ObservationIngestionService observationIngestionService;
    private final VulnerabilitySyncRunService syncRunService;
    private final VulnerabilityIngestionEffectsService effectsService;
    private final TaskExecutor ingestionExecutor;
    private final VulnerabilityRepository vulnerabilityRepository;

    @org.springframework.beans.factory.annotation.Value("${app.euvd.max-pages-per-sync:200}")
    private int maxPagesPerSync;

    private FeedRunCheckpointService checkpoints;

    @org.springframework.beans.factory.annotation.Autowired
    void configureCheckpoints(FeedRunCheckpointService checkpoints) {
        this.checkpoints = checkpoints;
    }

    private record Scope(EuvdApiClient.Scan request, int maxPages) {}

    public EuvdSyncService(
            EuvdApiClient euvdApiClient,
            ObservationIngestionService observationIngestionService,
            VulnerabilitySyncRunService syncRunService,
            VulnerabilityIngestionEffectsService effectsService,
            @Qualifier("integrationQueueExecutor") TaskExecutor ingestionExecutor,
            VulnerabilityRepository vulnerabilityRepository
    ) {
        this.euvdApiClient = euvdApiClient;
        this.observationIngestionService = observationIngestionService;
        this.syncRunService = syncRunService;
        this.effectsService = effectsService;
        this.ingestionExecutor = ingestionExecutor;
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    public SyncTriggerResponse triggerEuvdSync() {
        VulnerabilitySyncRunService.TriggerDecision decision =
                syncRunService.prepareQueuedRun("EUVD", List.of("EUVD"));
        return decision.toResponse("EUVD sync is already in progress", "EUVD sync queued");
    }

    public void executeEuvdSyncAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeEuvdSync(run);
    }

    public IngestionResult syncEuvd() {
        SyncRun run = syncRunService.createRunningRun("EUVD");
        return executeEuvdSync(run);
    }

    private IngestionResult executeEuvdSync(SyncRun run) {
        var progress = FeedRunCheckpointService.Progress.initial();
        Set<UUID> changedVulnerabilityIds = new LinkedHashSet<>();
        Set<String> seen = new HashSet<>();
        try {
            var scope = checkpoints == null
                    ? new FeedRunCheckpointService.RunScope<>(new Scope(null, Math.max(1, maxPagesPerSync)), progress)
                    : checkpoints.open(run, "euvd", Scope.class,
                            () -> new Scope(euvdApiClient.scan(), Math.max(1, maxPagesPerSync)));
            progress = scope.progress();
            Map<String, Object> metadata = new java.util.LinkedHashMap<>();
            metadata.put("pageSize", scope.input().request() == null ? euvdApiClient.perPage() : scope.input().request().pageSize());
            metadata.put("maxPagesPerSync", scope.input().maxPages());
            if (scope.input().request() != null && scope.input().request().fromUpdatedDate() != null) {
                metadata.put("fromUpdatedDate", scope.input().request().fromUpdatedDate());
                metadata.put("toUpdatedDate", scope.input().request().toUpdatedDate());
            } else if (checkpoints == null) {
                metadata.put("updatedWindowDays", euvdApiClient.updatedWindowDays());
            }
            syncRunService.applyRunMetadata(run, "euvd", metadata);

            while (!progress.finished() && progress.nextBatch() < scope.input().maxPages()) {
                int position = progress.nextBatch();
                var page = checkpoints == null ? euvdApiClient.fetchPage(position) : euvdApiClient.fetchPage(position, scope.input().request());
                if (page.pageNumber() != position) throw new IllegalStateException("EUVD returned an unexpected page position");
                Integer total = page.totalResults();
                if (progress.reportedTotal() != null && !progress.reportedTotal().equals(total)) {
                    throw new IllegalStateException("EUVD reported total changed during pagination");
                }
                int fetched = Math.addExact(progress.fetched(), page.records().size());
                if (total != null && fetched > total) throw new IllegalStateException("EUVD returned more records than its reported total");
                boolean finished = total != null && fetched == total;
                if (page.records().isEmpty() || page.records().size() < page.pageSize()) {
                    if (total != null && fetched < total) throw new IllegalStateException("EUVD returned an incomplete page");
                    finished = true;
                }
                var keys = page.records().stream().map(EuvdApiClient.EuvdRecord::sourceRecordId).toList();
                java.util.function.Supplier<FeedRunCheckpointService.Counts> stage =
                        () -> stagePage(page.records(), changedVulnerabilityIds);
                if (checkpoints != null) {
                    progress = checkpoints.commit(run, progress, null, keys, null, total, finished, stage);
                } else {
                    for (String key : keys) {
                        if (key == null || key.isBlank() || !seen.add(key)) {
                            throw new IllegalStateException("EUVD returned a missing or repeated source record ID");
                        }
                    }
                    progress = progress.advance(null, total, stage.get(), finished);
                    run.setRecordsFetched(progress.fetched());
                    run.setRecordsInserted(progress.inserted());
                    run.setRecordsUpdated(progress.updated());
                    syncRunService.save(run);
                }
            }
            if (!progress.finished()) throw new IllegalStateException("EUVD page limit reached before the feed ended");
            effectsService.recomputeCveDeltas(changedVulnerabilityIds);
            return complete(run, progress, "completed", "EUVD sync complete");
        } catch (VulnerabilityAttemptService.StaleAttemptException stale) {
            throw stale;
        } catch (Exception failure) {
            return complete(run, progress, "failed", failure.getMessage());
        }
    }

    private FeedRunCheckpointService.Counts stagePage(List<EuvdApiClient.EuvdRecord> records, Set<UUID> changed) {
        int inserted = 0;
        int updated = 0;
        for (var record : records) {
            VulnerabilityIntelligenceService.ObservationUpsertResult result =
                observationIngestionService.upsertObservation(
                        new VulnerabilityIntelligenceService.ObservationUpsertRequest(
                                record.externalId(),
                                "euvd",
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
                                record.referencesJson(),
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
