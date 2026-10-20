package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.dto.VexAssertionRepairSummaryResponse;
import com.prototype.vulnwatch.dto.VexRolloutComparisonResponse;
import com.prototype.vulnwatch.dto.VexRolloutMetricsSnapshotResponse;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.repo.VexAssertionRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.service.VexAssertionService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskExecutor;
import org.springframework.stereotype.Service;

@Service
public class VexMaintenanceService {

    private final VulnerabilitySyncRunService syncRunService;
    private final TaskExecutor ingestionExecutor;
    private final CsafSyncService csafSyncService;
    private final VexAssertionService vexAssertionService;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final VexAssertionRepository vexAssertionRepository;
    private final ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;
    private final VulnerabilityIngestionEffectsService effectsService;
    private final SyncRunRepository syncRunRepository;
    private final ObjectMapper objectMapper;

    @Value("${app.features.vex-policy-enabled:true}")
    private boolean vexPolicyEnabled;

    @Value("${app.features.vex-risk-modifiers-enabled:true}")
    private boolean vexRiskModifiersEnabled;

    @Value("${app.features.vex-rollout-controls-enabled:true}")
    private boolean vexRolloutControlsEnabled;

    @Value("${app.features.vex-rollout-backfill-enabled:true}")
    private boolean vexRolloutBackfillEnabled;

    public VexMaintenanceService(
            VulnerabilitySyncRunService syncRunService,
            @Qualifier("integrationQueueExecutor") TaskExecutor ingestionExecutor,
            CsafSyncService csafSyncService,
            VexAssertionService vexAssertionService,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            VexAssertionRepository vexAssertionRepository,
            ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository,
            VulnerabilityIngestionEffectsService effectsService,
            SyncRunRepository syncRunRepository,
            ObjectMapper objectMapper
    ) {
        this.syncRunService = syncRunService;
        this.ingestionExecutor = ingestionExecutor;
        this.csafSyncService = csafSyncService;
        this.vexAssertionService = vexAssertionService;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.vexAssertionRepository = vexAssertionRepository;
        this.componentVulnerabilityStateRepository = componentVulnerabilityStateRepository;
        this.effectsService = effectsService;
        this.syncRunRepository = syncRunRepository;
        this.objectMapper = objectMapper;
    }

    public SyncTriggerResponse triggerVexAssertionRepair() {
        ensureVexRolloutControlsEnabled();
        return syncRunService.prepareQueuedRun("VEX_ASSERTION_REPAIR",List.of("VEX_ASSERTION_REPAIR","VEX_ROLLOUT_BACKFILL","CSAF_MICROSOFT","CSAF_REDHAT"))
                .toResponse("VEX assertion repair is already in progress","VEX assertion repair queued");
    }

    public SyncTriggerResponse triggerVexRolloutBackfill() {
        ensureVexRolloutControlsEnabled();
        if (!vexRolloutBackfillEnabled) throw new IllegalStateException("Vendor VEX backfill is disabled by feature flag");
        return syncRunService.prepareQueuedRun("VEX_ROLLOUT_BACKFILL",List.of("VEX_ROLLOUT_BACKFILL","CSAF_MICROSOFT","CSAF_REDHAT","VEX_ASSERTION_REPAIR"))
                .toResponse("A VEX backfill-related run is already in progress","Vendor VEX backfill queued");
    }

    public void executeVexAssertionRepairAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeVexAssertionRepair(run);
    }

    public void executeVexRolloutBackfillAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeVexRolloutBackfill(run);
    }

    public VexAssertionRepairSummaryResponse getVexAssertionRepairSummary() {
        SyncRun latestRepairRun = syncRunRepository.findTopBySyncTypeIgnoreCaseOrderByStartedAtDesc("VEX_ASSERTION_REPAIR")
                .orElse(null);
        SyncRun latestMicrosoftRun = syncRunRepository.findTopBySyncTypeIgnoreCaseOrderByStartedAtDesc("CSAF_MICROSOFT")
                .orElse(null);
        SyncRun latestRedhatRun = syncRunRepository.findTopBySyncTypeIgnoreCaseOrderByStartedAtDesc("CSAF_REDHAT")
                .orElse(null);
        SyncRun latestBackfillRun = syncRunRepository.findTopBySyncTypeIgnoreCaseOrderByStartedAtDesc("VEX_ROLLOUT_BACKFILL")
                .orElse(null);
        Set<String> sourceSystems = vexAssertionRepository.findDistinctSourceSystems().stream()
                .filter(value -> value != null && !value.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));
        VexRolloutComparisonResponse latestBackfillComparison = parseRolloutComparison(latestBackfillRun);
        return new VexAssertionRepairSummaryResponse(
                vulnerabilityTargetRepository.countAllVexLikeTargets(),
                vexAssertionRepository.countAllAssertions(),
                componentVulnerabilityStateRepository.countActiveStatesWithMatchedVexAssertion(),
                componentVulnerabilityStateRepository.countActiveApplicableStatesAwaitingMatchedVexAssertion(),
                sourceSystems,
                vexPolicyEnabled,
                vexRiskModifiersEnabled,
                vexRolloutControlsEnabled,
                vexRolloutBackfillEnabled,
                syncRunService.toSnapshot(latestRepairRun),
                syncRunService.toSnapshot(latestMicrosoftRun),
                syncRunService.toSnapshot(latestRedhatRun),
                syncRunService.toSnapshot(latestBackfillRun),
                latestBackfillComparison,
                Instant.now()
        );
    }

    public IngestionResult syncVexAssertionRepair() {
        SyncRun run = syncRunService.createRunningRun("VEX_ASSERTION_REPAIR");
        return executeVexAssertionRepair(run);
    }

    private IngestionResult executeVexAssertionRepair(SyncRun run) {
        int fetched = 0;
        int inserted = 0;
        int updated = 0;
        int failed = 0;
        try {
            fetched = Math.toIntExact(Math.min(Integer.MAX_VALUE, vulnerabilityTargetRepository.countAllVexLikeTargets()));
            VexAssertionService.RefreshResult refreshResult = vexAssertionService.refreshAllAssertionsDetailed();
            inserted = refreshResult.assertionCount();
            run.setRecordsFetched(fetched);
            run.setRecordsInserted(inserted);
            syncRunService.save(run);

            if (!refreshResult.changedVulnerabilityIds().isEmpty()) {
                updated = effectsService.applyVexDeltas(
                        new LinkedHashSet<>(refreshResult.changedVulnerabilityIds()),
                        "vex-assertion-repair"
                );
                run.setRecordsUpdated(updated);
                syncRunService.save(run);
            }

            syncRunService.completeRun(run, "completed", fetched, inserted, updated, failed, null);
            return new IngestionResult("ok", fetched, inserted, updated, "VEX assertion repair complete");
        } catch (Exception e) {
            syncRunService.completeRun(run, "failed", fetched, inserted, updated, failed, e.getMessage());
            return new IngestionResult("failed", fetched, inserted, updated, e.getMessage());
        }
    }

    private IngestionResult executeVexRolloutBackfill(SyncRun run) {
        int fetched = 0;
        int inserted = 0;
        int updated = 0;
        int failed = 0;
        List<String> failures = new ArrayList<>();
        try {
            VexRolloutMetricsSnapshotResponse beforeSnapshot = captureVexRolloutMetrics();
            IngestionResult microsoftResult = csafSyncService.syncMicrosoftCsaf();
            fetched += microsoftResult.fetched();
            inserted += microsoftResult.inserted();
            updated += microsoftResult.updated();
            if (!isOk(microsoftResult)) {
                failed++;
                failures.add("Microsoft CSAF/VEX sync: " + microsoftResult.message());
            }
            run.setRecordsFetched(fetched);
            run.setRecordsInserted(inserted);
            run.setRecordsUpdated(updated);
            run.setRecordsFailed(failed);
            syncRunService.save(run);

            IngestionResult redhatResult = csafSyncService.syncRedhatCsaf();
            fetched += redhatResult.fetched();
            inserted += redhatResult.inserted();
            updated += redhatResult.updated();
            if (!isOk(redhatResult)) {
                failed++;
                failures.add("Red Hat CSAF/VEX sync: " + redhatResult.message());
            }
            run.setRecordsFetched(fetched);
            run.setRecordsInserted(inserted);
            run.setRecordsUpdated(updated);
            run.setRecordsFailed(failed);
            syncRunService.save(run);

            IngestionResult repairResult = syncVexAssertionRepair();
            fetched += repairResult.fetched();
            inserted += repairResult.inserted();
            updated += repairResult.updated();
            if (!isOk(repairResult)) {
                failed++;
                failures.add("VEX assertion repair: " + repairResult.message());
            }

            VexRolloutMetricsSnapshotResponse afterSnapshot = captureVexRolloutMetrics();
            syncRunService.setMetadata(run, new VexRolloutComparisonResponse(beforeSnapshot, afterSnapshot));
            String errorSummary = failures.isEmpty() ? null : String.join(" | ", failures);
            syncRunService.completeRun(run, failures.isEmpty() ? "completed" : "failed", fetched, inserted, updated, failed, errorSummary);
            return new IngestionResult(
                    failures.isEmpty() ? "ok" : "failed",
                    fetched,
                    inserted,
                    updated,
                    failures.isEmpty() ? "Vendor VEX backfill complete" : errorSummary
            );
        } catch (Exception e) {
            syncRunService.completeRun(run, "failed", fetched, inserted, updated, failed, e.getMessage());
            return new IngestionResult("failed", fetched, inserted, updated, e.getMessage());
        }
    }

    private void ensureVexRolloutControlsEnabled() {
        if (!vexRolloutControlsEnabled) {
            throw new IllegalStateException("VEX rollout controls are disabled by feature flag");
        }
    }

    private VexRolloutMetricsSnapshotResponse captureVexRolloutMetrics() {
        return new VexRolloutMetricsSnapshotResponse(
                vulnerabilityTargetRepository.countAllVexLikeTargets(),
                vexAssertionRepository.countAllAssertions(),
                componentVulnerabilityStateRepository.countActiveStatesWithMatchedVexAssertion(),
                componentVulnerabilityStateRepository.countActiveApplicableStatesAwaitingMatchedVexAssertion(),
                Instant.now()
        );
    }

    private VexRolloutComparisonResponse parseRolloutComparison(SyncRun run) {
        if (run == null || run.getMetadataJson() == null || run.getMetadataJson().isBlank()) {
            return null;
        }
        try {
            return objectMapper.readValue(run.getMetadataJson(), VexRolloutComparisonResponse.class);
        } catch (Exception ignored) {
            return null;
        }
    }

    private boolean isOk(IngestionResult result) {
        return result != null && "ok".equalsIgnoreCase(result.status());
    }
}
