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
        int fetched = 0;
        int inserted = 0;
        int updated = 0;
        Set<UUID> changedVulnerabilityIds = new LinkedHashSet<>();
        syncRunService.applyRunMetadata(
                run,
                "euvd",
                Map.of(
                        "pageSize", euvdApiClient.perPage(),
                        "maxPagesPerSync", maxPagesPerSync
                )
        );
        try {
            int pageNumber = 0;
            while (pageNumber < Math.max(1, maxPagesPerSync)) {
                EuvdApiClient.EuvdPage page = euvdApiClient.fetchPage(pageNumber);
                if (page.records().isEmpty()) {
                    break;
                }

                fetched += page.records().size();
                for (EuvdApiClient.EuvdRecord record : page.records()) {
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
                    if (vulnerability != null && vulnerability.getId() != null) {
                        changedVulnerabilityIds.add(vulnerability.getId());
                    }
                    if (result.vulnerabilityCreated()) {
                        inserted++;
                    } else {
                        updated++;
                    }
                }

                run.setRecordsFetched(fetched);
                run.setRecordsInserted(inserted);
                run.setRecordsUpdated(updated);
                syncRunService.save(run);

                if (page.records().size() < page.pageSize() && page.totalResults() <= fetched) {
                    break;
                }
                pageNumber++;
                if (page.totalResults() > 0 && pageNumber * page.pageSize() >= page.totalResults()) {
                    break;
                }
            }

            effectsService.recomputeCveDeltas(changedVulnerabilityIds);
            syncRunService.completeRun(run, "completed", fetched, inserted, updated, 0, null);
            return new IngestionResult("ok", fetched, inserted, updated, "EUVD sync complete");
        } catch (Exception e) {
            syncRunService.completeRun(run, "failed", fetched, inserted, updated, 0, e.getMessage());
            return new IngestionResult("failed", fetched, inserted, updated, e.getMessage());
        }
    }
}
