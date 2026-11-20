package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.prototype.vulnwatch.util.LogUtil;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskExecutor;
import org.springframework.stereotype.Service;

@Service
public class CsafSyncService {

    private static final Logger LOG = LoggerFactory.getLogger(CsafSyncService.class);

    private final VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService;
    private final TenantService tenantService;
    private final TaskExecutor ingestionExecutor;
    private final VulnerabilitySyncRunService syncRunService;
    private final VulnerabilityIngestionEffectsService effectsService;
    private final CsafDiscoveryService discoveryService;
    private final CsafDocumentFetcher documentFetcher;
    private final CsafDocumentIngestor documentIngestor;
    private final ObjectMapper objectMapper;
    private final VulnerabilityRepository vulnerabilityRepository;

    private FeedRunCheckpointService checkpoints;

    @org.springframework.beans.factory.annotation.Autowired
    void configureCheckpoints(FeedRunCheckpointService checkpoints) {
        this.checkpoints = checkpoints;
    }

    private record Scope(List<CsafDocumentRef> documents, int discovered,
                         VulnerabilitySourceFilterConfigService.RedhatFilters filters) {}

    @Value("${app.csaf.max-documents-per-sync:300}")
    private int csafMaxDocumentsPerSync;

    public CsafSyncService(
            VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService,
            TenantService tenantService,
            @Qualifier("integrationQueueExecutor") TaskExecutor ingestionExecutor,
            VulnerabilitySyncRunService syncRunService,
            VulnerabilityIngestionEffectsService effectsService,
            CsafDiscoveryService discoveryService,
            CsafDocumentFetcher documentFetcher,
            CsafDocumentIngestor documentIngestor,
            ObjectMapper objectMapper,
            VulnerabilityRepository vulnerabilityRepository
    ) {
        this.vulnerabilitySourceFilterConfigService = vulnerabilitySourceFilterConfigService;
        this.tenantService = tenantService;
        this.ingestionExecutor = ingestionExecutor;
        this.syncRunService = syncRunService;
        this.effectsService = effectsService;
        this.discoveryService = discoveryService;
        this.documentFetcher = documentFetcher;
        this.documentIngestor = documentIngestor;
        this.objectMapper = objectMapper;
        this.vulnerabilityRepository = vulnerabilityRepository;
    }

    public void runScheduledMicrosoftSync() {
        triggerMicrosoftCsafSync();
    }

    public void runScheduledRedhatSync() {
        triggerRedhatCsafSync();
    }

    public SyncTriggerResponse triggerMicrosoftCsafSync() {
        VulnerabilitySyncRunService.TriggerDecision decision =
                syncRunService.prepareQueuedRun("CSAF_MICROSOFT", List.of("CSAF_MICROSOFT", "VEX_ROLLOUT_BACKFILL"));
        return decision.toResponse("Microsoft CSAF/VEX sync is already in progress", "Microsoft CSAF/VEX sync queued");
    }

    public void executeMicrosoftCsafSyncAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeCsafSync(run, CsafProvider.MICROSOFT);
    }

    public IngestionResult syncMicrosoftCsaf() {
        SyncRun run = syncRunService.createRunningRun("CSAF_MICROSOFT");
        return executeCsafSync(run, CsafProvider.MICROSOFT);
    }

    public SyncTriggerResponse triggerRedhatCsafSync() {
        VulnerabilitySyncRunService.TriggerDecision decision =
                syncRunService.prepareQueuedRun("CSAF_REDHAT", List.of("CSAF_REDHAT", "VEX_ROLLOUT_BACKFILL"));
        return decision.toResponse("Red Hat CSAF/VEX sync is already in progress", "Red Hat CSAF/VEX sync queued");
    }

    public void executeRedhatCsafSyncAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeCsafSync(run, CsafProvider.REDHAT);
    }

    public IngestionResult syncRedhatCsaf() {
        SyncRun run = syncRunService.createRunningRun("CSAF_REDHAT");
        return executeCsafSync(run, CsafProvider.REDHAT);
    }

    private IngestionResult executeCsafSync(SyncRun run, CsafProvider provider) {
        var progress = FeedRunCheckpointService.Progress.initial();
        Set<UUID> changed = new LinkedHashSet<>();
        Set<UUID> vexChanged = new LinkedHashSet<>();
        CsafRunDiagnostics diagnostics = new CsafRunDiagnostics(provider.providerKey());
        try {
            var saved = checkpoints == null
                    ? new FeedRunCheckpointService.RunScope<>(discover(provider), progress)
                    : checkpoints.open(run, "csaf-" + provider.providerKey(), Scope.class, () -> discover(provider));
            Scope scope = saved.input();
            progress = saved.progress();
            var metadata = new java.util.LinkedHashMap<>(syncRunService.redhatFiltersMetadata(scope.filters()));
            metadata.put("discoveredDocuments", scope.discovered());
            metadata.put("selectedDocuments", scope.documents().size());
            syncRunService.applyRunMetadata(run, provider.providerKey(), metadata);

            while (progress.nextBatch() < scope.documents().size()) {
                int position = progress.nextBatch();
                CsafDocumentRef document = scope.documents().get(position);
                boolean finalDocument = position + 1 == scope.documents().size();
                diagnostics.markDocumentAttempt();
                CsafDocumentFetchResult response = documentFetcher.fetch(document.url(), provider.providerKey());
                if (!response.success()) {
                    diagnostics.markDocumentFailure(response.failureCategory(), response.attempts());
                    LOG.warn("Failed to fetch {} advisory {} category={} attempts={}", provider.providerKey(),
                            LogUtil.safe(document.url()), response.failureCategory(), response.attempts());
                    progress = settle(run, progress, document, finalDocument,
                            () -> new FeedRunCheckpointService.Counts(0, 0, 0, 1));
                    continue;
                }

                JsonNode advisory;
                try {
                    advisory = objectMapper.readTree(response.body());
                    if (advisory == null || !advisory.isObject()
                            || advisory.path("document").path("tracking").path("id").asText("").isBlank()
                            || advisory.has("vulnerabilities") && !advisory.path("vulnerabilities").isArray()) {
                        throw new IllegalArgumentException("CSAF response is missing its document envelope");
                    }
                } catch (IllegalArgumentException | java.io.IOException malformed) {
                    diagnostics.markDocumentFailure("INVALID_DOCUMENT", response.attempts());
                    LOG.warn("Invalid {} advisory document {}", provider.providerKey(), LogUtil.safe(document.url()));
                    progress = settle(run, progress, document, finalDocument,
                            () -> new FeedRunCheckpointService.Counts(0, 0, 0, 1));
                    continue;
                }

                progress = settle(run, progress, document, finalDocument, () -> {
                    var counts = documentIngestor.ingestDocument(provider, advisory, document.url(), document.vexProfile(),
                            diagnostics, scope.filters());
                    (document.vexProfile() ? vexChanged : changed).addAll(counts.vulnerabilityIds());
                    return new FeedRunCheckpointService.Counts(1, counts.inserted(), counts.updated(), 0);
                });
                diagnostics.markDocumentSuccess(response.attempts());
            }

            LOG.info("CSAF run diagnostics {}", diagnostics.summaryLine());
            if (progress.fetched() == 0 && progress.failed() > 0) {
                return complete(run, progress, "failed", provider.displayName()
                        + " CSAF/VEX sync failed for every discovered document: " + diagnostics.summaryLine());
            }
            if (progress.failed() > 0 || scope.documents().size() < scope.discovered()) {
                return complete(run, progress, "partial", provider.displayName() + " CSAF/VEX coverage is partial"
                        + " (selected " + scope.documents().size() + " of " + scope.discovered()
                        + ", documentsFailed=" + progress.failed() + ")");
            }
            changed.addAll(vexChanged);
            effectsService.refreshAssertionsForVulnerabilityIds(changed);
            effectsService.recomputeCveDeltas(changed);
            effectsService.applyVexDeltas(vexChanged, provider.providerKey());
            return complete(run, progress, "completed", provider.displayName() + " CSAF/VEX sync complete");
        } catch (VulnerabilityAttemptService.StaleAttemptException stale) {
            throw stale;
        } catch (Exception failure) {
            return complete(run, progress, "failed", failure.getMessage());
        }
    }

    private Scope discover(CsafProvider provider) {
        var filters = provider == CsafProvider.REDHAT ? vulnerabilitySourceFilterConfigService.resolvePlatformRedhatFilters()
                : new VulnerabilitySourceFilterConfigService.RedhatFilters(null, null, null);
        CsafDistributionSet distributions = discoveryService.discoverDistributions(provider);
        List<CsafDocumentRef> documents = discoveryService.collectDocumentRefs(distributions, provider);
        if (documents == null || documents.isEmpty()) {
            throw new IllegalStateException(provider.displayName() + " CSAF/VEX discovery returned no documents; coverage cannot be confirmed");
        }
        if (provider == CsafProvider.MICROSOFT && distributions.vexDistributionUrl() != null
                && !distributions.vexDistributionUrl().isBlank()) {
            Set<String> known = new LinkedHashSet<>();
            for (String cve : vulnerabilityRepository.findAllCveExternalIds()) {
                String url = buildMsrcVexUrl(distributions.vexDistributionUrl(), cve);
                if (url != null) known.add(url.toLowerCase(Locale.ROOT));
            }
            if (!known.isEmpty()) {
                documents = new ArrayList<>(documents);
                documents.sort(java.util.Comparator.comparing(doc -> !known.contains(doc.url().toLowerCase(Locale.ROOT))));
            }
        }
        int limit = Math.min(documents.size(), Math.max(1, csafMaxDocumentsPerSync));
        return new Scope(List.copyOf(documents.subList(0, limit)), documents.size(), filters);
    }

    private FeedRunCheckpointService.Progress settle(SyncRun run, FeedRunCheckpointService.Progress prior,
            CsafDocumentRef document, boolean finished, java.util.function.Supplier<FeedRunCheckpointService.Counts> stage) {
        if (checkpoints != null) {
            return checkpoints.commit(run, prior, null, List.of(document.url()), null, null, finished, stage);
        }
        var result = prior.advance(null, null, stage.get(), finished);
        run.setRecordsFetched(result.fetched());
        run.setRecordsInserted(result.inserted());
        run.setRecordsUpdated(result.updated());
        run.setRecordsFailed(result.failed());
        syncRunService.save(run);
        return result;
    }

    private IngestionResult complete(SyncRun run, FeedRunCheckpointService.Progress progress, String status, String message) {
        boolean ok = "completed".equals(status);
        syncRunService.completeRun(run, status, progress.fetched(), progress.inserted(), progress.updated(),
                progress.failed(), ok ? null : message);
        return new IngestionResult(ok ? "ok" : status, progress.fetched(), progress.inserted(), progress.updated(), message);
    }

    /**
     * Constructs the MSRC VEX URL for a given CVE ID.
     * Pattern: {vexRoot}/{year}/msrc_cve-{year}-{number}.json
     * Example: https://msrc.microsoft.com/csaf/vex/2024/msrc_cve-2024-21413.json
     */
    private String buildMsrcVexUrl(String vexRoot, String cveId) {
        if (cveId == null || !cveId.toUpperCase(Locale.ROOT).startsWith("CVE-")) {
            return null;
        }
        String lower = cveId.toLowerCase(Locale.ROOT); // e.g. "cve-2024-21413"
        String[] parts = lower.split("-");
        if (parts.length < 3) {
            return null;
        }
        String year = parts[1]; // "2024"
        String root = vexRoot.endsWith("/") ? vexRoot.substring(0, vexRoot.length() - 1) : vexRoot;
        return root + "/" + year + "/msrc_" + lower + ".json";
    }

}
