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
        int fetched = 0;
        int inserted = 0;
        int updated = 0;
        Set<UUID> changedVulnerabilityIds = new LinkedHashSet<>();
        syncRunService.applyRunMetadata(
                run,
                "jvn",
                Map.of(
                        "pageSize", jvnApiClient.perPage(),
                        "maxPagesPerSync", maxPagesPerSync
                )
        );
        try {
            int pageIndex = 0;
            while (pageIndex < Math.max(1, maxPagesPerSync)) {
                int startItem = pageIndex * jvnApiClient.perPage() + 1;
                JvnApiClient.JvnPage page = jvnApiClient.fetchPage(startItem);
                if (page.records().isEmpty()) {
                    break;
                }

                fetched += page.records().size();
                for (JvnApiClient.JvnRecord record : page.records()) {
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

                int pageSize = page.maxCountItem();
                int totalResults = page.totalResults();
                if (page.records().size() < pageSize) {
                    break;
                }
                pageIndex++;
                if (totalResults > 0 && startItem + pageSize - 1 >= totalResults) {
                    break;
                }
            }

            effectsService.enqueueCveMetadataDeltas(changedVulnerabilityIds);
            syncRunService.completeRun(run, "completed", fetched, inserted, updated, 0, null);
            return new IngestionResult("ok", fetched, inserted, updated, "JVN sync complete");
        } catch (Exception e) {
            syncRunService.completeRun(run, "failed", fetched, inserted, updated, 0, e.getMessage());
            return new IngestionResult("failed", fetched, inserted, updated, e.getMessage());
        }
    }
}
