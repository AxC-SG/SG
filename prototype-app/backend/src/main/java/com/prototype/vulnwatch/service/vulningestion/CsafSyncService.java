package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
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
        int fetched = 0;
        int inserted = 0;
        int updated = 0;
        int failed = 0;
        Set<UUID> changedVulnerabilityIds = new LinkedHashSet<>();
        Set<UUID> vexChangedVulnerabilityIds = new LinkedHashSet<>();
        CsafRunDiagnostics diagnostics = new CsafRunDiagnostics(provider.providerKey());
        VulnerabilitySourceFilterConfigService.RedhatFilters redhatFilters = provider == CsafProvider.REDHAT
                ? vulnerabilitySourceFilterConfigService.resolvePlatformRedhatFilters()
                : new VulnerabilitySourceFilterConfigService.RedhatFilters(null, null, null);
        if (provider == CsafProvider.REDHAT) {
            syncRunService.applyRunMetadata(run, "redhat", syncRunService.redhatFiltersMetadata(redhatFilters));
        }
        try {
            CsafDistributionSet distributions = discoveryService.discoverDistributions(provider);
            List<CsafDocumentRef> documents = discoveryService.collectDocumentRefs(distributions, provider);

            // For MICROSOFT: re-sort the discovered document list so that VEX documents for
            // CVEs already in our inventory appear first. This is a zero-HTTP-request operation —
            // we only construct the expected MSRC VEX URLs and check membership in the discovered
            // set. CVE-2024 entries buried at position 2000+ in changes.csv (which is sorted by
            // last-modified descending) will be promoted to the front.
            // All priority (inventory-matching) docs are processed regardless of maxDocs;
            // remaining slots are filled from non-priority discovered docs.
            boolean documentListFinalized = false;
            if (provider == CsafProvider.MICROSOFT) {
                String vexRoot = distributions.vexDistributionUrl();
                if (vexRoot != null && !vexRoot.isBlank()) {
                    List<String> allCveIds = vulnerabilityRepository.findAllCveExternalIds();
                    Set<String> priorityUrlSet = new LinkedHashSet<>();
                    for (String cveId : allCveIds) {
                        String url = buildMsrcVexUrl(vexRoot, cveId);
                        if (url != null) {
                            priorityUrlSet.add(url.toLowerCase(Locale.ROOT));
                        }
                    }
                    if (!priorityUrlSet.isEmpty()) {
                        List<CsafDocumentRef> priority = new ArrayList<>();
                        List<CsafDocumentRef> rest = new ArrayList<>();
                        for (CsafDocumentRef doc : documents) {
                            if (priorityUrlSet.contains(doc.url().toLowerCase(Locale.ROOT))) {
                                priority.add(doc);
                            } else {
                                rest.add(doc);
                            }
                        }
                        // Always process ALL priority (inventory-matching) docs; fill remaining
                        // slots up to maxDocs with non-priority docs from changes.csv.
                        int maxDocs = Math.max(1, csafMaxDocumentsPerSync);
                        int restSlots = Math.max(0, maxDocs - priority.size());
                        List<CsafDocumentRef> restCapped = rest.size() > restSlots
                                ? rest.subList(0, restSlots)
                                : rest;
                        documents = new ArrayList<>(priority.size() + restCapped.size());
                        documents.addAll(priority);
                        documents.addAll(restCapped);
                        documentListFinalized = true;
                        LOG.info("MSRC VEX: processing all {} inventory CVE docs + {} non-priority docs (total={})",
                                priority.size(), restCapped.size(), documents.size());
                    }
                }
            }

            // Apply maxDocs limit for non-MICROSOFT providers (or MICROSOFT when no priority sorting was done).
            if (!documentListFinalized) {
                int maxDocs = Math.max(1, csafMaxDocumentsPerSync);
                if (documents.size() > maxDocs) {
                    documents = new ArrayList<>(documents.subList(0, maxDocs));
                }
            }

            for (CsafDocumentRef document : documents) {
                diagnostics.markDocumentAttempt();
                CsafDocumentFetchResult fetchResult = documentFetcher.fetch(document.url());
                if (!fetchResult.success()) {
                    failed++;
                    diagnostics.markDocumentFailure(fetchResult.failureCategory(), fetchResult.attempts());
                    LOG.warn(
                            "Failed to fetch {} advisory {} category={} attempts={} message={}",
                            provider.providerKey(),
                            LogUtil.safe(document.url()),
                            fetchResult.failureCategory(),
                            fetchResult.attempts(),
                            LogUtil.safe(fetchResult.failureMessage()));
                    run.setRecordsFetched(fetched);
                    run.setRecordsInserted(inserted);
                    run.setRecordsUpdated(updated);
                    run.setRecordsFailed(failed);
                    syncRunService.save(run);
                    continue;
                }
                try {
                    JsonNode advisoryNode = objectMapper.readTree(fetchResult.body());
                    CsafIngestionCounters counters = documentIngestor.ingestDocument(
                            provider,
                            advisoryNode,
                            document.url(),
                            document.vexProfile(),
                            diagnostics,
                            redhatFilters
                    );
                    inserted += counters.inserted();
                    updated += counters.updated();
                    if (document.vexProfile()) {
                        vexChangedVulnerabilityIds.addAll(counters.vulnerabilityIds());
                    } else {
                        changedVulnerabilityIds.addAll(counters.vulnerabilityIds());
                    }
                    fetched++;
                    diagnostics.markDocumentSuccess(fetchResult.attempts());
                    run.setRecordsFetched(fetched);
                    run.setRecordsInserted(inserted);
                    run.setRecordsUpdated(updated);
                    run.setRecordsFailed(failed);
                    syncRunService.save(run);
                } catch (Exception advisoryError) {
                    failed++;
                    String category = documentFetcher.failureCategory(advisoryError);
                    diagnostics.markDocumentFailure(category, fetchResult.attempts());
                    LOG.warn(
                            "Failed to ingest {} advisory {} category={} attempts={}",
                            provider.providerKey(),
                            LogUtil.safe(document.url()),
                            category,
                            fetchResult.attempts(),
                            advisoryError);
                    run.setRecordsFetched(fetched);
                    run.setRecordsInserted(inserted);
                    run.setRecordsUpdated(updated);
                    run.setRecordsFailed(failed);
                    syncRunService.save(run);
                }
            }

            Set<UUID> allChangedVulnerabilityIds = new LinkedHashSet<>(changedVulnerabilityIds);
            allChangedVulnerabilityIds.addAll(vexChangedVulnerabilityIds);
            effectsService.refreshAssertionsForVulnerabilityIds(allChangedVulnerabilityIds);
            effectsService.recomputeCveDeltas(allChangedVulnerabilityIds);
            effectsService.applyVexDeltas(vexChangedVulnerabilityIds, provider.providerKey());
            LOG.info("CSAF run diagnostics {}", diagnostics.summaryLine());
            String message = provider.displayName() + " CSAF/VEX sync complete"
                    + (failed > 0 ? " (failed advisories: " + failed + ")" : "");
            syncRunService.completeRun(
                    run,
                    "completed",
                    fetched,
                    inserted,
                    updated,
                    failed,
                    failed > 0 ? diagnostics.summaryLine() : null
            );
            return new IngestionResult("ok", fetched, inserted, updated, message);
        } catch (Exception e) {
            syncRunService.completeRun(run, "failed", fetched, inserted, updated, failed, e.getMessage());
            return new IngestionResult("failed", fetched, inserted, updated, e.getMessage());
        }
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
