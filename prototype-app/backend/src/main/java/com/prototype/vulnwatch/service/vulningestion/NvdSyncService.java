package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.NvdApiClient;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityRule;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRuleRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.service.IdentityGraphService;
import com.prototype.vulnwatch.service.ObservationIngestionService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.VulnerabilityIntelligenceService;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import com.prototype.vulnwatch.util.IdentityUtil;
import java.time.Instant;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskExecutor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

@Service
public class NvdSyncService {

    private final NvdApiClient nvdApiClient;
    private final FeedWatermarkService feedWatermarks;
    private final FeedCoverageLedgerService coverageLedger;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityRuleRepository vulnerabilityRuleRepository;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final IdentityGraphService identityGraphService;
    private final ObservationIngestionService observationIngestionService;
    private final VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService;
    private final TenantService tenantService;
    private final TaskExecutor ingestionExecutor;
    private final VulnerabilitySyncRunService syncRunService;
    private final VulnerabilityIngestionEffectsService effectsService;
    private final VulnerabilityIngestionCommonSupport support;
    private final ObjectMapper objectMapper;

    @Value("${app.nvd.default-lookback-hours:24}")
    private int defaultNvdLookbackHours;

    @Value("${app.intelligence.scheduled-nvd-profiles.enabled:false}")
    private boolean scheduledProfilesEnabled;

    @Value("${app.nvd.cve-delta-recompute-page-interval:5}")
    private int cveDeltaRecomputePageInterval;

    @Value("${app.correlation.backfill-targets-on-startup:false}")
    private boolean backfillTargetsOnStartup;

    @Value("${app.correlation.backfill-page-size:500}")
    private int backfillPageSize;

    public NvdSyncService(
            NvdApiClient nvdApiClient,
            VulnerabilityRepository vulnerabilityRepository,
            VulnerabilityRuleRepository vulnerabilityRuleRepository,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            IdentityGraphService identityGraphService,
            ObservationIngestionService observationIngestionService,
            VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService,
            TenantService tenantService,
            @Qualifier("integrationQueueExecutor") TaskExecutor ingestionExecutor,
            VulnerabilitySyncRunService syncRunService,
            VulnerabilityIngestionEffectsService effectsService,
            VulnerabilityIngestionCommonSupport support,
            ObjectMapper objectMapper,
            FeedWatermarkService feedWatermarks,
            FeedCoverageLedgerService coverageLedger
    ) {
        this.nvdApiClient = nvdApiClient;
        this.feedWatermarks = feedWatermarks;
        this.coverageLedger = coverageLedger;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.vulnerabilityRuleRepository = vulnerabilityRuleRepository;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.identityGraphService = identityGraphService;
        this.observationIngestionService = observationIngestionService;
        this.vulnerabilitySourceFilterConfigService = vulnerabilitySourceFilterConfigService;
        this.tenantService = tenantService;
        this.ingestionExecutor = ingestionExecutor;
        this.syncRunService = syncRunService;
        this.effectsService = effectsService;
        this.support = support;
        this.objectMapper = objectMapper;
    }

    public void runScheduledDailySync() {
        triggerNvdSync(defaultNvdLookbackHours);
    }

    @Transactional
    public void backfillTargetsFromExistingRulesIfEnabled() {
        if (!backfillTargetsOnStartup) {
            return;
        }
        SyncRun run=syncRunService.createRunningRun("NVD_TARGET_REPAIR");
        try {
            int prepared=Math.toIntExact(backfillTargetsFromRulesInternal(true));
            syncRunService.completeRun(run,"completed",prepared,0,prepared,0,null);
        } finally { com.prototype.vulnwatch.service.IntelligenceWriteContext.endRun(run.getId()); }
    }

    public SyncTriggerResponse triggerNvdSync(int lookbackHours) {
        VulnerabilitySyncRunService.TriggerDecision decision =
                syncRunService.prepareQueuedRun("NVD", List.of("NVD", "NVD_FULL"), queuedIncrementalMetadata(lookbackHours));
        return decision.toResponse("NVD sync is already in progress", "NVD incremental sync queued");
    }

    /** One historical last-modified window; retries are idempotent and do not move the incremental watermark. */
    public SyncTriggerResponse triggerNvdHistoricalWindow(Instant from, Instant to) {
        return triggerNvdHistoricalWindow(from, to, null);
    }

    /** A planned baseline window must still target its selected filter scope when the worker begins. */
    public SyncTriggerResponse triggerNvdHistoricalWindow(Instant from, Instant to, String expectedScopeKey) {
        validateHistoricalWindow(from, to);
        Map<String, Object> metadata = new java.util.HashMap<>(Map.of(
                "triggerMode", "historical_window", "from", from.toString(), "to", to.toString()));
        if (expectedScopeKey != null) metadata.put("expectedScopeKey", expectedScopeKey);
        VulnerabilitySyncRunService.TriggerDecision decision = syncRunService.prepareQueuedRun(
                "NVD", List.of("NVD", "NVD_FULL"), metadata);
        return decision.toResponse("NVD sync is already in progress", "NVD historical window queued");
    }

    public void executeNvdSyncAsync(UUID runId, int lookbackHours) {
        SyncRun run = syncRunService.markRunning(runId);
        executeNvdIncrementalSync(run, lookbackHours);
    }

    public void executeQueuedNvdSyncAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        JsonNode metadata = readQueuedMetadata(run);
        String mode = metadata == null ? "incremental" : metadata.path("triggerMode").asText("incremental");
        if ("profile_baseline".equals(mode)) {
            if (scheduledProfilesEnabled) {
                executeNvdFullSync(run, null);
            } else {
                syncRunService.completeRun(run, "failed", 0, 0, 0, 0, "Scheduled NVD profiles are disabled");
            }
        } else if ("historical_window".equals(mode)) {
            final Instant from;
            final Instant to;
            try {
                from = Instant.parse(metadata.path("from").asText());
                to = Instant.parse(metadata.path("to").asText());
                validateHistoricalWindow(from, to);
            } catch (RuntimeException invalid) {
                syncRunService.completeRun(run, "failed", 0, 0, 0, 0, "Invalid NVD historical window");
                return;
            }
            String expectedScopeKey = metadata.path("expectedScopeKey").asText(null);
            executeNvdHistoricalWindow(run, from, to, expectedScopeKey);
        } else if ("incremental".equals(mode)) {
            executeNvdIncrementalSync(run, resolveQueuedLookbackHours(run));
        } else {
            syncRunService.completeRun(run, "failed", 0, 0, 0, 0, "Unknown NVD trigger mode");
        }
    }

    private static void validateHistoricalWindow(Instant from, Instant to) {
        if (from == null || to == null || !from.isBefore(to) || to.isAfter(Instant.now())
                || Duration.between(from, to).compareTo(Duration.ofDays(120)) > 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "NVD historical window must be in the past and at most 120 days");
        }
    }

    private IngestionResult executeNvdHistoricalWindow(SyncRun run, Instant from, Instant to,
                                                       String expectedScopeKey) {
        var filters = vulnerabilitySourceFilterConfigService.resolvePlatformNvdFilters();
        String key = nvdScopeKey(filters);
        if (expectedScopeKey != null && !expectedScopeKey.equals(key)) {
            syncRunService.completeRun(run, "failed", 0, 0, 0, 0,
                    "NVD platform filter scope changed before baseline window execution");
            return new IngestionResult("failed", 0, 0, 0,
                    "NVD platform filter scope changed before baseline window execution");
        }
        Set<String> observedIds = new HashSet<>();
        IngestionResult result = executeNvdSyncInternal(run, from, to, null,
                "NVD historical window complete", false, filters, observedIds);
        if (!"ok".equals(result.status())) {
            syncRunService.completeRun(run, "failed", result.fetched(), result.inserted(),
                    result.updated(), 0, result.message());
            return result;
        }
        try {
            coverageLedger.observeNvdInterval(run.getId(), key, from, to, result.fetched(), observedIds);
        } catch (RuntimeException failure) {
            syncRunService.completeRun(run, "failed", result.fetched(), result.inserted(),
                    result.updated(), 0, "NVD interval coverage evidence could not be recorded");
            return new IngestionResult("failed", result.fetched(), result.inserted(), result.updated(),
                    "NVD interval coverage evidence could not be recorded");
        }
        syncRunService.completeRun(run, "completed", result.fetched(), result.inserted(), result.updated(), 0, null);
        return result;
    }

    public SyncTriggerResponse triggerNvdFullSync(String apiKeyOverride) {
        VulnerabilitySyncRunService.TriggerDecision decision =
                syncRunService.prepareQueuedRun("NVD_FULL", List.of("NVD", "NVD_FULL"), queuedFullMetadata(apiKeyOverride));
        return decision.toResponse("NVD sync is already in progress", "NVD full sync queued");
    }

    public void executeNvdFullSyncAsync(UUID runId, String apiKeyOverride) {
        SyncRun run = syncRunService.markRunning(runId);
        executeNvdFullSync(run, apiKeyOverride);
    }

    public void executeQueuedNvdFullSyncAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeNvdFullSync(run, resolveQueuedApiKeyOverride(run));
    }

    public IngestionResult syncNvd(int lookbackHours) {
        SyncRun run = syncRunService.createRunningRun("NVD");
        return executeNvdIncrementalSync(run, lookbackHours);
    }

    /**
     * Fetch a single CVE directly from NVD by ID and upsert it.
     * Uses the cveId query parameter which bypasses the 120-day rolling window.
     */
    public IngestionResult refreshSingleCveFromNvd(String cveId) {
        SyncRun run=syncRunService.createRunningRun("NVD_SINGLE");
        try {
            NvdApiClient.NvdRecord record=nvdApiClient.fetchSingleCve(cveId);
            if (record==null) {
                syncRunService.completeRun(run,"failed",0,0,0,1,"CVE not found");
                return new IngestionResult("not_found",0,0,0,"CVE not found in NVD: "+cveId);
            }
            upsertNvdRecord(record);
            syncRunService.completeRun(run,"completed",1,0,1,0,null);
            return new IngestionResult("ok",1,0,1,"CVE staged for review: "+cveId);
        } catch(RuntimeException failure) {
            syncRunService.completeRun(run,"failed",0,0,0,1,"NVD refresh failed");throw failure;
        } finally { com.prototype.vulnwatch.service.IntelligenceWriteContext.endRun(run.getId()); }
    }

    private IngestionResult executeNvdIncrementalSync(SyncRun run, int lookbackHours) {
        Instant end = Instant.now();
        var filters = vulnerabilitySourceFilterConfigService.resolvePlatformNvdFilters();
        // A filter change starts its own continuity history; filtered coverage cannot certify another scope.
        String key = nvdScopeKey(filters);
        Instant start = feedWatermarks.completedUntil(key)
                .map(value -> value.minus(1, ChronoUnit.HOURS))
                .orElseGet(() -> end.minus(Math.max(1, lookbackHours), ChronoUnit.HOURS));
        int fetched = 0, inserted = 0, updated = 0;
        while (start.isBefore(end)) {
            Instant intervalEnd = start.plus(120, ChronoUnit.DAYS);
            if (intervalEnd.isAfter(end)) intervalEnd = end;
            Set<String> observedIds = new HashSet<>();
            IngestionResult result = executeNvdSyncInternal(run, start, intervalEnd, null,
                    "NVD interval complete", false, filters, observedIds);
            fetched += result.fetched(); inserted += result.inserted(); updated += result.updated();
            if (!"ok".equals(result.status())) {
                syncRunService.completeRun(run, "failed", fetched, inserted, updated, 0, result.message());
                return new IngestionResult("failed", fetched, inserted, updated, result.message());
            }
            try {
                coverageLedger.observeNvdInterval(run.getId(), key, start, intervalEnd, result.fetched(), observedIds);
            } catch (RuntimeException failure) {
                syncRunService.completeRun(run, "failed", fetched, inserted, updated, 0,
                        "NVD interval coverage evidence could not be recorded");
                return new IngestionResult("failed", fetched, inserted, updated,
                        "NVD interval coverage evidence could not be recorded");
            }
            start = intervalEnd;
        }
        syncRunService.completeRun(run, "completed", fetched, inserted, updated, 0, null);
        feedWatermarks.complete(key,end);
        return new IngestionResult("ok", fetched, inserted, updated, "NVD incremental coverage complete");
    }

    static String nvdScopeKey(VulnerabilitySourceFilterConfigService.NvdFilters filters) {
        return "nvd:" + org.springframework.util.DigestUtils.md5DigestAsHex(
                filters.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private IngestionResult executeNvdFullSync(SyncRun run, String apiKeyOverride) {
        if (!nvdApiClient.hasApiKey(apiKeyOverride)) {
            String message = "NVD full sync requires an API key from the UI or NVD_API_KEY environment configuration";
            syncRunService.completeRun(run, "failed", 0, 0, 0, 0, message);
            return new IngestionResult("failed", 0, 0, 0, message);
        }
        boolean scoped=readQueuedMetadata(run)!=null && readQueuedMetadata(run).has("importProfile");
        IngestionResult result=executeNvdSyncInternal(run, null, null, apiKeyOverride, "NVD full sync complete", true,
                scoped ? new VulnerabilitySourceFilterConfigService.NvdFilters(null,false,false,null,null)
                        : vulnerabilitySourceFilterConfigService.resolvePlatformNvdFilters(), null);
        if(scoped && "ok".equals(result.status())) feedWatermarks.complete("profile:"+readQueuedMetadata(run).path("importProfile").path("id").asText(),Instant.now());
        return result;
    }

    private Map<String, Object> queuedIncrementalMetadata(int lookbackHours) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("triggerMode", "incremental");
        metadata.put("lookbackHours", Math.max(1, lookbackHours));
        return metadata;
    }

    private com.prototype.vulnwatch.service.CredentialEncryptionService encryption;
    @org.springframework.beans.factory.annotation.Autowired
    void configureEncryption(com.prototype.vulnwatch.service.CredentialEncryptionService encryption) { this.encryption=encryption; }

    private Map<String, Object> queuedFullMetadata(String apiKeyOverride) {
        Map<String, Object> metadata = new LinkedHashMap<>();
        metadata.put("triggerMode", "full");
        if (support.hasText(apiKeyOverride)) {
            metadata.put("encryptedApiKeyOverride", encryption.encrypt(apiKeyOverride));
        }
        return metadata;
    }

    private int resolveQueuedLookbackHours(SyncRun run) {
        JsonNode metadata = readQueuedMetadata(run);
        if (metadata == null || !metadata.path("lookbackHours").canConvertToInt()) {
            return defaultNvdLookbackHours;
        }
        return Math.max(1, metadata.path("lookbackHours").asInt(defaultNvdLookbackHours));
    }

    private String resolveQueuedApiKeyOverride(SyncRun run) {
        JsonNode metadata = readQueuedMetadata(run);
        if (metadata == null) {
            return null;
        }
        String apiKeyOverride = metadata.path("encryptedApiKeyOverride").asText(null);
        return support.hasText(apiKeyOverride) ? encryption.decrypt(apiKeyOverride) : null;
    }

    private JsonNode readQueuedMetadata(SyncRun run) {
        if (run == null || !support.hasText(run.getMetadataJson())) {
            return null;
        }
        try {
            return objectMapper.readTree(run.getMetadataJson());
        } catch (Exception exception) {
            return null;
        }
    }

    private IngestionResult executeNvdSyncInternal(
            SyncRun run,
            Instant startInclusive,
            Instant endExclusive,
            String apiKeyOverride,
            String successMessage,
            boolean terminal,
            VulnerabilitySourceFilterConfigService.NvdFilters filters,
            Set<String> observedIds
    ) {
        int fetched = 0;
        int inserted = 0;
        int updated = 0;
        int pagesProcessed = 0;
        int recomputeInterval = Math.max(1, cveDeltaRecomputePageInterval);
        Set<UUID> changedVulnerabilityIds = new LinkedHashSet<>();
        Set<String> seenCveIds = observedIds == null ? new HashSet<>() : observedIds;
        syncRunService.applyRunMetadata(
                run,
                "nvd",
                syncRunService.nvdFiltersMetadata(filters, startInclusive, endExclusive)
        );
        try {
            int startIndex = 0;
            Integer lastObservedTotal = null;
            while (true) {
                NvdApiClient.NvdPage page = nvdApiClient.fetchPage(
                        startIndex,
                        startInclusive,
                        endExclusive,
                        new NvdApiClient.NvdQueryFilters(
                                filters.cpeName(),
                                filters.isVulnerable(),
                                filters.hasKev(),
                                filters.cvssV3Severity(),
                                filters.cvssV4Severity()
                        ),
                        apiKeyOverride
                );
                List<NvdApiClient.NvdRecord> records = page.records();
                // NVD does not provide a snapshot token. Its corpus can change while a full
                // scan is paging, so validate each page against its own response metadata.
                validateNvdPage(page, startIndex, null);
                for (NvdApiClient.NvdRecord record : records) {
                    validateNvdIdentity(record == null ? null : record.cveId(), seenCveIds);
                }
                lastObservedTotal = page.totalResults();
                if (records.isEmpty()) {
                    if (page.totalResults() > startIndex) {
                        throw new IllegalStateException("NVD returned an incomplete empty page");
                    }
                    break;
                }

                fetched += records.size();
                for (NvdApiClient.NvdRecord record : records) {
                    if (!matchesImportProfile(run,record)) continue;
                    boolean created = upsertNvdRecord(record);
                    if (created) {
                        inserted++;
                    } else {
                        updated++;
                    }
                    vulnerabilityRepository.findByExternalId(record.cveId())
                            .map(Vulnerability::getId)
                            .ifPresent(changedVulnerabilityIds::add);
                }

                run.setRecordsFetched(fetched);
                run.setRecordsInserted(inserted);
                run.setRecordsUpdated(updated);
                syncRunService.save(run);
                pagesProcessed++;

                if (pagesProcessed % recomputeInterval == 0 && !changedVulnerabilityIds.isEmpty()) {
                    effectsService.recomputeCveDeltas(changedVulnerabilityIds);
                    changedVulnerabilityIds.clear();
                }

                int nextStart = page.startIndex() + Math.max(1, page.resultsPerPage());
                if (nextStart >= page.totalResults()) {
                    break;
                }
                startIndex = nextStart;
            }
            validateNvdCompletion(fetched, lastObservedTotal);
            if (!changedVulnerabilityIds.isEmpty()) {
                effectsService.recomputeCveDeltas(changedVulnerabilityIds);
            }

            if (terminal) syncRunService.completeRun(run, "completed", fetched, inserted, updated, 0, null);
            return new IngestionResult("ok", fetched, inserted, updated, successMessage);
        } catch (Exception e) {
            if (terminal) syncRunService.completeRun(run, "failed", fetched, inserted, updated, 0, e.getMessage());
            return new IngestionResult("failed", fetched, inserted, updated, e.getMessage());
        }
    }

    static void validateNvdPage(NvdApiClient.NvdPage page, int requestedStart, Integer expectedTotal) {
        if (page.startIndex() != requestedStart) {
            throw new IllegalStateException("NVD pagination did not match the requested interval page");
        }
        if (expectedTotal != null && page.totalResults() != expectedTotal) {
            throw new IllegalStateException("NVD reported a changing total during pagination");
        }
        int available = Math.max(0, page.totalResults() - requestedStart);
        int expectedRecords = Math.min(page.resultsPerPage(), available);
        if (page.resultsPerPage() < 0
                || (page.totalResults() < requestedStart && !page.records().isEmpty())
                || page.records().size() != expectedRecords) {
            throw new IllegalStateException("NVD returned an incomplete interval page");
        }
    }

    static void validateNvdCompletion(int fetched, Integer lastObservedTotal) {
        if (lastObservedTotal == null || fetched < lastObservedTotal) {
            throw new IllegalStateException("NVD pagination ended before the reported total was fetched");
        }
    }

    static void validateNvdIdentity(String cveId, Set<String> seenCveIds) {
        if (cveId == null || !cveId.matches("CVE-[0-9]{4}-[0-9]{4,}")) {
            throw new IllegalStateException("NVD returned an invalid CVE identifier");
        }
        if (!seenCveIds.add(cveId)) {
            throw new IllegalStateException("NVD returned a duplicate CVE identifier in the interval");
        }
    }

    private long backfillTargetsFromRulesInternal(boolean skipIfTargetsExist) {
        if (skipIfTargetsExist && vulnerabilityTargetRepository.count() > 0) {
            return 0;
        }

        int page = 0;
        int pageSize = Math.max(100, backfillPageSize);
        long createdTargets = 0;
        while (true) {
            Page<VulnerabilityRule> rules = vulnerabilityRuleRepository.findAll(PageRequest.of(page, pageSize));
            if (rules.isEmpty()) {
                break;
            }
            List<VulnerabilityTarget> targets = new ArrayList<>();
            for (VulnerabilityRule rule : rules.getContent()) {
                appendTargetsForRule(targets, rule, "backfill", Instant.now().toString());
            }
            targets.forEach(support::saveTarget);
            createdTargets += targets.size();
            if (!rules.hasNext()) {
                break;
            }
            page++;
        }
        return createdTargets;
    }

    private void appendTargetsForRule(
            List<VulnerabilityTarget> targets,
            VulnerabilityRule rule,
            String source,
            String kbVersion
    ) {
        SoftwareIdentity identity = identityGraphService.resolveFromTarget(
                rule.getEcosystem(),
                rule.getPackageName(),
                null,
                null,
                rule.getCpe(),
                null,
                source
        );
        targets.add(support.createTarget(
                rule.getVulnerability(),
                identity,
                VulnerabilityTargetType.COORD,
                IdentityUtil.coordKey(rule.getEcosystem(), rule.getPackageName()),
                rule.getEcosystem(),
                null,
                rule.getPackageName(),
                null,
                null,
                rule.getVersionExact(),
                rule.getVersionStart(),
                rule.getVersionStartInclusive(),
                rule.getVersionEnd(),
                rule.getVersionEndInclusive(),
                null,
                null,
                VersionScheme.UNKNOWN,
                rule.getCpe(),
                support.cpeWildcardScore(rule.getCpe()),
                null,
                source,
                kbVersion
        ));
        if (rule.getCpe() != null && !rule.getCpe().isBlank()) {
            targets.add(support.createTarget(
                    rule.getVulnerability(),
                    identity,
                    VulnerabilityTargetType.CPE,
                    IdentityUtil.normalize(rule.getCpe()),
                    rule.getEcosystem(),
                    null,
                    rule.getPackageName(),
                    null,
                    rule.getCpe(),
                    rule.getVersionExact(),
                    rule.getVersionStart(),
                    rule.getVersionStartInclusive(),
                    rule.getVersionEnd(),
                    rule.getVersionEndInclusive(),
                    null,
                    null,
                    VersionScheme.UNKNOWN,
                    rule.getCpe(),
                    support.cpeWildcardScore(rule.getCpe()),
                    null,
                    source,
                    kbVersion
            ));
        }
    }

    private boolean matchesImportProfile(SyncRun run, NvdApiClient.NvdRecord record) {
        JsonNode metadata=readQueuedMetadata(run);
        if(metadata==null || !metadata.has("importProfile")) return true;
        try {
            var p=objectMapper.treeToValue(metadata.get("importProfile"),com.prototype.vulnwatch.service.IntelligenceImportProfileService.Profile.class);
            var predicate=new com.prototype.vulnwatch.service.IntelligenceImportProfile(p.id(),p.name(),new java.util.ArrayList<>(p.sources()),p.publicationYearFrom(),p.publicationYearTo(),p.minCvss(),p.maxCvss(),p.severities(),p.includeUnknownScores());
            return predicate.matches(new VulnerabilityIntelligenceService.ObservationUpsertRequest(record.cveId(),"nvd",record.cveId(),null,null,null,record.severity(),record.cvssScore(),null,null,null,null,null,null,null,record.published(),record.lastModified(),null));
        } catch(java.io.IOException failure) { throw new IllegalStateException("Invalid immutable import profile snapshot",failure); }
    }

    private boolean upsertNvdRecord(NvdApiClient.NvdRecord record) {
        VulnerabilityIntelligenceService.ObservationUpsertResult upsertResult = observationIngestionService.upsertObservation(
                new VulnerabilityIntelligenceService.ObservationUpsertRequest(
                        record.cveId(),
                        "nvd",
                        record.cveId(),
                        null,
                        support.hasText(record.title()) ? record.title() : record.cveId(),
                        record.description(),
                        record.severity() == null ? "UNKNOWN" : record.severity().toUpperCase(),
                        record.cvssScore(),
                        record.cvssVector(),
                        null,
                        null,
                        record.vulnStatus(),
                        record.cweIds(),
                        record.referencesJson(),
                        record.sourceIdentifier(),
                        record.published(),
                        record.lastModified(),
                        record.rawJson(),
                        record.cvssVersion()
                )
        );
        Vulnerability vuln = upsertResult.vulnerability();
        if("REJECTED".equalsIgnoreCase(record.vulnStatus())) {
            support.withdrawSource(vuln,"nvd",record.cveId());return false;
        }

        vuln.setVulnStatus(record.vulnStatus());
        vuln.setCvssVersion(record.cvssVersion());
        vuln.setCvssVector(record.cvssVector());
        vuln.setAttackVector(record.attackVector());
        vuln.setAttackComplexity(record.attackComplexity());
        vuln.setPrivilegesRequired(record.privilegesRequired());
        vuln.setUserInteraction(record.userInteraction());
        vuln.setScope(record.scope());
        vuln.setExploitabilityScore(record.exploitabilityScore());
        vuln.setImpactScore(record.impactScore());
        vuln.touch();
        support.saveMetadata(vuln,"nvd");

        support.replaceRules(vuln);
        support.replaceTargets(vuln, List.of("nvd", "backfill", "backfill-inventory"));
        for (NvdApiClient.NvdRule ruleData : record.rules()) {
            VulnerabilityRule rule = new VulnerabilityRule();
            rule.setVulnerability(vuln);
            rule.setEcosystem(ruleData.ecosystem());
            rule.setPackageName(ruleData.packageName());
            rule.setVersionExact(ruleData.versionExact());
            rule.setVersionStart(ruleData.versionStart());
            rule.setVersionStartInclusive(ruleData.versionStartInclusive());
            rule.setVersionEnd(ruleData.versionEnd());
            rule.setVersionEndInclusive(ruleData.versionEndInclusive());
            rule.setCpe(ruleData.cpe());
            rule.setCpeVendor(ruleData.cpeVendor());
            rule.setCpeProduct(ruleData.cpeProduct());
            support.saveRule(rule);

            SoftwareIdentity identity = identityGraphService.resolveFromTarget(
                    ruleData.ecosystem(),
                    ruleData.packageName(),
                    null,
                    null,
                    ruleData.cpe(),
                    null,
                    "nvd"
            );

            support.saveTarget(support.createTarget(
                    vuln,
                    identity,
                    VulnerabilityTargetType.COORD,
                    IdentityUtil.coordKey(ruleData.ecosystem(), ruleData.packageName()),
                    ruleData.ecosystem(),
                    null,
                    ruleData.packageName(),
                    null,
                    null,
                    ruleData.versionExact(),
                    ruleData.versionStart(),
                    ruleData.versionStartInclusive(),
                    ruleData.versionEnd(),
                    ruleData.versionEndInclusive(),
                    null,
                    null,
                    VersionScheme.UNKNOWN,
                    null,
                    null,
                    null,
                    "nvd",
                    support.kbVersionFor(record)
            ));

            if (ruleData.cpe() != null && !ruleData.cpe().isBlank()) {
                support.saveTarget(support.createTarget(
                        vuln,
                        identity,
                        VulnerabilityTargetType.CPE,
                        IdentityUtil.normalize(ruleData.cpe()),
                        ruleData.ecosystem(),
                        null,
                        ruleData.packageName(),
                        null,
                        ruleData.cpe(),
                        ruleData.versionExact(),
                        ruleData.versionStart(),
                        ruleData.versionStartInclusive(),
                        ruleData.versionEnd(),
                        ruleData.versionEndInclusive(),
                        null,
                        null,
                        VersionScheme.UNKNOWN,
                        ruleData.cpe(),
                        support.cpeWildcardScore(ruleData.cpe()),
                        null,
                        "nvd",
                        support.kbVersionFor(record)
                ));
            }
        }
        support.persistVulnerabilityConfigExpressions(vuln, record.rawJson());

        return upsertResult.vulnerabilityCreated();
    }

}
