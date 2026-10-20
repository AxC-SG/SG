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
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
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

@Service
public class NvdSyncService {

    private final NvdApiClient nvdApiClient;
    private final FeedWatermarkService feedWatermarks;
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
            FeedWatermarkService feedWatermarks
    ) {
        this.nvdApiClient = nvdApiClient;
        this.feedWatermarks = feedWatermarks;
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
        backfillTargetsFromRulesInternal(true);
    }

    public SyncTriggerResponse triggerNvdSync(int lookbackHours) {
        VulnerabilitySyncRunService.TriggerDecision decision =
                syncRunService.prepareQueuedRun("NVD", List.of("NVD", "NVD_FULL"), queuedIncrementalMetadata(lookbackHours));
        return decision.toResponse("NVD sync is already in progress", "NVD incremental sync queued");
    }

    public void executeNvdSyncAsync(UUID runId, int lookbackHours) {
        SyncRun run = syncRunService.markRunning(runId);
        executeNvdIncrementalSync(run, lookbackHours);
    }

    public void executeQueuedNvdSyncAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeNvdIncrementalSync(run, resolveQueuedLookbackHours(run));
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
        NvdApiClient.NvdRecord record = nvdApiClient.fetchSingleCve(cveId);
        if (record == null) {
            return new IngestionResult("not_found", 0, 0, 0, "CVE not found in NVD: " + cveId);
        }
        boolean created = upsertNvdRecord(record);
        return new IngestionResult("ok", 1, created ? 1 : 0, created ? 0 : 1, "Refreshed " + cveId + " from NVD");
    }

    private IngestionResult executeNvdIncrementalSync(SyncRun run, int lookbackHours) {
        Instant end = Instant.now();
        var filters = vulnerabilitySourceFilterConfigService.resolvePlatformNvdFilters();
        // A filter change starts its own continuity history; filtered coverage cannot certify another scope.
        String key = "nvd:" + org.springframework.util.DigestUtils.md5DigestAsHex(
                filters.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Instant start = feedWatermarks.completedUntil(key)
                .map(value -> value.minus(1, ChronoUnit.HOURS))
                .orElseGet(() -> end.minus(Math.max(1, lookbackHours), ChronoUnit.HOURS));
        int fetched = 0, inserted = 0, updated = 0;
        while (start.isBefore(end)) {
            Instant intervalEnd = start.plus(120, ChronoUnit.DAYS);
            if (intervalEnd.isAfter(end)) intervalEnd = end;
            IngestionResult result = executeNvdSyncInternal(run, start, intervalEnd, null,
                    "NVD interval complete", false);
            fetched += result.fetched(); inserted += result.inserted(); updated += result.updated();
            if (!"ok".equals(result.status())) {
                syncRunService.completeRun(run, "failed", fetched, inserted, updated, 0, result.message());
                return new IngestionResult("failed", fetched, inserted, updated, result.message());
            }
            feedWatermarks.complete(key, intervalEnd);
            start = intervalEnd;
        }
        syncRunService.completeRun(run, "completed", fetched, inserted, updated, 0, null);
        return new IngestionResult("ok", fetched, inserted, updated, "NVD incremental coverage complete");
    }

    private IngestionResult executeNvdFullSync(SyncRun run, String apiKeyOverride) {
        if (!nvdApiClient.hasApiKey(apiKeyOverride)) {
            String message = "NVD full sync requires an API key from the UI or NVD_API_KEY environment configuration";
            syncRunService.completeRun(run, "failed", 0, 0, 0, 0, message);
            return new IngestionResult("failed", 0, 0, 0, message);
        }
        return executeNvdSyncInternal(run, null, null, apiKeyOverride, "NVD full sync complete", true);
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
            boolean terminal
    ) {
        int fetched = 0;
        int inserted = 0;
        int updated = 0;
        int pagesProcessed = 0;
        int recomputeInterval = Math.max(1, cveDeltaRecomputePageInterval);
        Set<UUID> changedVulnerabilityIds = new LinkedHashSet<>();
        VulnerabilitySourceFilterConfigService.NvdFilters filters =
                vulnerabilitySourceFilterConfigService.resolvePlatformNvdFilters();
        syncRunService.applyRunMetadata(
                run,
                "nvd",
                syncRunService.nvdFiltersMetadata(filters, startInclusive, endExclusive)
        );
        try {
            int startIndex = 0;
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
                if (page.startIndex() != startIndex) {
                    throw new IllegalStateException("NVD pagination did not match the requested interval page");
                }
                if (records.isEmpty()) {
                    if (page.totalResults() > startIndex) {
                        throw new IllegalStateException("NVD returned an incomplete empty page");
                    }
                    break;
                }

                fetched += records.size();
                for (NvdApiClient.NvdRecord record : records) {
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
            vulnerabilityTargetRepository.saveAll(targets);
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
                        record.rawJson()
                )
        );
        Vulnerability vuln = upsertResult.vulnerability();

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
        vulnerabilityRepository.save(vuln);

        vulnerabilityRuleRepository.deleteByVulnerability(vuln);
        vulnerabilityTargetRepository.deleteByVulnerabilityAndSourceIn(vuln, List.of("nvd", "backfill", "backfill-inventory"));
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
            vulnerabilityRuleRepository.save(rule);

            SoftwareIdentity identity = identityGraphService.resolveFromTarget(
                    ruleData.ecosystem(),
                    ruleData.packageName(),
                    null,
                    null,
                    ruleData.cpe(),
                    null,
                    "nvd"
            );

            vulnerabilityTargetRepository.save(support.createTarget(
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
                vulnerabilityTargetRepository.save(support.createTarget(
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
