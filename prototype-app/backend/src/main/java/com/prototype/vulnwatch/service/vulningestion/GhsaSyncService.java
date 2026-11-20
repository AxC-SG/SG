package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GithubTokenProvider;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.service.IdentityGraphService;
import com.prototype.vulnwatch.service.ObservationIngestionService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.VulnerabilityIntelligenceService;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import com.prototype.vulnwatch.util.IdentityUtil;
import java.net.URI;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.LinkedHashMap;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskExecutor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class GhsaSyncService {

    private static final String GHSA_DEFAULT_API_URL = "https://api.github.com/advisories";
    private static final String GHSA_API_VERSION = "2022-11-28";
    private static final String GITHUB_USER_AGENT = "vulnwatch-backend/1.0";
    private static final Pattern GHSA_LINK_NEXT_PATTERN = Pattern.compile("<([^>]+)>;\\s*rel=\"next\"");

    private final VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final IdentityGraphService identityGraphService;
    private final ObservationIngestionService observationIngestionService;
    private final VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService;
    private final TenantService tenantService;
    private final TaskExecutor ingestionExecutor;
    private final VulnerabilitySyncRunService syncRunService;
    private final VulnerabilityIngestionEffectsService effectsService;
    private final VulnerabilityIngestionCommonSupport support;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;
    private final GithubTokenProvider githubTokenProvider;
    private final FeedRunCheckpointService checkpoints;
    private final FeedWatermarkService watermarks;

    private record Scope(String firstUrl, String severity, String coverageKey, String through, int maxPages, int pageSize) {}

    @Value("${app.ghsa.api-url:" + GHSA_DEFAULT_API_URL + "}")
    private String ghsaApiUrl;

    @Value("${app.ghsa.default-lookback-days:7}")
    private int ghsaDefaultLookbackDays;

    @Value("${app.ghsa.per-page:100}")
    private int ghsaPerPage;

    // Keep the default aligned with the GitHub collection cap. 40 pages only
    // permits 4,000 advisories at the API's maximum page size and can truncate
    // a normal modified-window sync before its checkpoint is complete.
    @Value("${app.ghsa.max-pages-per-sync:250}")
    private int ghsaMaxPagesPerSync;

    @Value("${app.github.max-retries:4}")
    private int githubMaxRetries;

    @Value("${app.github.retry-base-backoff-ms:1000}")
    private long githubRetryBaseBackoffMs;

    public GhsaSyncService(
            VulnerabilityIntelObservationRepository vulnerabilityIntelObservationRepository,
            VulnerabilityRepository vulnerabilityRepository,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            IdentityGraphService identityGraphService,
            ObservationIngestionService observationIngestionService,
            VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService,
            TenantService tenantService,
            @Qualifier("integrationQueueExecutor") TaskExecutor ingestionExecutor,
            VulnerabilitySyncRunService syncRunService,
            VulnerabilityIngestionEffectsService effectsService,
            VulnerabilityIngestionCommonSupport support,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper,
            GithubTokenProvider githubTokenProvider,
            FeedRunCheckpointService checkpoints,
            FeedWatermarkService watermarks
    ) {
        this.vulnerabilityIntelObservationRepository = vulnerabilityIntelObservationRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.identityGraphService = identityGraphService;
        this.observationIngestionService = observationIngestionService;
        this.vulnerabilitySourceFilterConfigService = vulnerabilitySourceFilterConfigService;
        this.tenantService = tenantService;
        this.ingestionExecutor = ingestionExecutor;
        this.syncRunService = syncRunService;
        this.effectsService = effectsService;
        this.support = support;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
        this.githubTokenProvider = githubTokenProvider;
        this.checkpoints = checkpoints;
        this.watermarks = watermarks;
    }

    public void runScheduledSync() {
        triggerGhsaSync();
    }

    public SyncTriggerResponse triggerGhsaSync() {
        VulnerabilitySyncRunService.TriggerDecision decision =
                syncRunService.prepareQueuedRun("GHSA", List.of("GHSA"));
        return decision.toResponse("GHSA sync is already in progress", "GHSA sync queued");
    }

    public void executeGhsaSyncAsync(UUID runId) {
        SyncRun run = syncRunService.markRunning(runId);
        executeGhsaSync(run);
    }

    public IngestionResult syncGhsa() {
        SyncRun run = syncRunService.createRunningRun("GHSA");
        return executeGhsaSync(run);
    }

    private IngestionResult executeGhsaSync(SyncRun run) {
        var progress = FeedRunCheckpointService.Progress.initial();
        Set<UUID> changedVulnerabilityIds = new LinkedHashSet<>();
        try {
            var saved = checkpoints.open(run, "ghsa", Scope.class, this::scan);
            Scope scope = saved.input();
            progress = saved.progress();
            var metadata = new LinkedHashMap<>(syncRunService.ghsaFiltersMetadata(
                    new VulnerabilitySourceFilterConfigService.GhsaFilters(scope.severity())));
            metadata.put("modifiedWindow", UriComponentsBuilder.fromUriString(scope.firstUrl()).build()
                    .getQueryParams().getFirst("modified"));
            metadata.put("pageSize", scope.pageSize());
            metadata.put("maxPagesPerSync", scope.maxPages());
            syncRunService.applyRunMetadata(run, "ghsa", metadata);

            while (!progress.finished() && progress.nextBatch() < scope.maxPages()) {
                String current = progress.nextBatch() == 0 ? scope.firstUrl() : progress.cursor();
                validateCursor(scope.firstUrl(), current);
                ResponseEntity<String> response = exchangeJson(current);
                String body = response.getBody();
                JsonNode records = body == null ? null : objectMapper.readTree(body);
                String next = parseLinkNext(response.getHeaders().getFirst(HttpHeaders.LINK));
                if (records == null || !records.isArray() || records.size() > scope.pageSize()
                        || (records.isEmpty() && next != null)) {
                    throw new IllegalStateException("GHSA returned a malformed or incomplete page");
                }
                if (next != null) validateCursor(scope.firstUrl(), next);
                List<String> ids = new java.util.ArrayList<>(records.size());
                records.forEach(advisory -> {
                    String id = advisory.path("ghsa_id").asText("").trim().toUpperCase(Locale.ROOT);
                    if (!id.matches("GHSA-[A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4}")) {
                        throw new IllegalStateException("GHSA returned an invalid advisory ID");
                    }
                    ids.add(id);
                });
                progress = checkpoints.commit(run, progress, current, ids, next, null, next == null,
                        () -> stagePage(records, changedVulnerabilityIds));
            }
            if (!progress.finished()) throw new IllegalStateException("GHSA page limit reached before the feed ended");
            effectsService.recomputeCveDeltas(changedVulnerabilityIds);
            var completed = progress;
            checkpoints.finish(() -> {
                syncRunService.completeRun(run, "completed", completed.fetched(), completed.inserted(), completed.updated(), 0, null);
                watermarks.complete(scope.coverageKey(), Instant.parse(scope.through()));
            });
            return new IngestionResult("ok", progress.fetched(), progress.inserted(), progress.updated(), "GHSA sync complete");
        } catch (VulnerabilityAttemptService.StaleAttemptException stale) {
            throw stale;
        } catch (Exception failure) {
            syncRunService.completeRun(run, "failed", progress.fetched(), progress.inserted(), progress.updated(), 0, failure.getMessage());
            return new IngestionResult("failed", progress.fetched(), progress.inserted(), progress.updated(), failure.getMessage());
        }
    }

    private Scope scan() {
        var filters = vulnerabilitySourceFilterConfigService.resolvePlatformGhsaFilters();
        String severity = support.hasText(filters.severity()) ? filters.severity().trim().toLowerCase(Locale.ROOT) : "";
        String scope = ghsaApiUrl + "\n" + severity;
        String coverageKey = "ghsa:" + org.springframework.util.DigestUtils.md5DigestAsHex(
                scope.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        Instant now = Instant.now();
        Instant modifiedStart = watermarks.completedUntil(coverageKey)
                .map(watermark -> watermark.minus(1, ChronoUnit.DAYS))
                .orElseGet(() -> now.minus(Math.max(1, ghsaDefaultLookbackDays), ChronoUnit.DAYS));
        LocalDate from = modifiedStart.atZone(ZoneOffset.UTC).toLocalDate();
        LocalDate through = now.atZone(ZoneOffset.UTC).toLocalDate();
        int pageSize = Math.max(1, Math.min(100, ghsaPerPage));
        var uri = UriComponentsBuilder.fromUriString(ghsaApiUrl)
                .queryParam("per_page", pageSize).queryParam("sort", "updated").queryParam("direction", "asc")
                .queryParam("modified", from + ".." + through);
        if (!severity.isEmpty()) uri.queryParam("severity", severity);
        return new Scope(uri.build().toUriString(), severity, coverageKey, now.toString(), Math.max(1, ghsaMaxPagesPerSync), pageSize);
    }

    private void validateCursor(String firstUrl, String cursor) {
        URI first = URI.create(firstUrl);
        URI next = URI.create(cursor);
        if (first.getHost() == null || next.getHost() == null || !first.getHost().equalsIgnoreCase(next.getHost())
                || !Objects.equals(first.getScheme(), next.getScheme()) || first.getPort() != next.getPort()
                || !Objects.equals(first.getPath(), next.getPath()) || next.getRawUserInfo() != null
                || next.getRawFragment() != null) {
            throw new IllegalStateException("GHSA pagination left the original feed endpoint");
        }
    }

    private FeedRunCheckpointService.Counts stagePage(JsonNode advisories, Set<UUID> changed) {
        int inserted = 0;
        int updated = 0;
        for (JsonNode advisory : advisories) {
            GhsaIngestionCounters counters = upsertGhsaAdvisory(advisory);
            inserted += counters.inserted();
            updated += counters.updated();
            String cveId = support.firstNonBlank(support.textValue(advisory.path("cve_id")),
                    firstCveIdentifier(advisory.path("identifiers")));
            if (support.hasText(cveId)) {
                vulnerabilityRepository.findByExternalId(cveId.trim().toUpperCase(Locale.ROOT))
                        .map(Vulnerability::getId).ifPresent(changed::add);
            }
        }
        return new FeedRunCheckpointService.Counts(advisories.size(), inserted, updated, 0);
    }

    private GhsaIngestionCounters upsertGhsaAdvisory(JsonNode advisoryNode) {
        Set<String> cves=new java.util.TreeSet<>();
        if(advisoryNode.path("cve_id").asText("").matches("CVE-[0-9]{4}-[0-9]{4,}")) cves.add(advisoryNode.path("cve_id").asText());
        for(JsonNode identifier:advisoryNode.path("identifiers")) {
            if("CVE".equalsIgnoreCase(identifier.path("type").asText()) && identifier.path("value").asText().matches("CVE-[0-9]{4}-[0-9]{4,}")) cves.add(identifier.path("value").asText());
        }
        if(cves.isEmpty()) return upsertGhsaSingle(advisoryNode);
        int inserted=0,updated=0;
        for(String cve:cves) {
            var copy=(com.fasterxml.jackson.databind.node.ObjectNode)advisoryNode.deepCopy();copy.put("cve_id",cve);
            var result=upsertGhsaSingle(copy);inserted+=result.inserted();updated+=result.updated();
        }
        return new GhsaIngestionCounters(inserted,updated);
    }
    private GhsaIngestionCounters upsertGhsaSingle(JsonNode advisoryNode) {
        String ghsaId = support.textValue(advisoryNode.path("ghsa_id"));
        String cveId = support.firstNonBlank(
                support.textValue(advisoryNode.path("cve_id")),
                firstCveIdentifier(advisoryNode.path("identifiers")), ghsaId
        );
        if (!support.hasText(cveId)) {
            return new GhsaIngestionCounters(0, 0);
        }
        cveId = cveId.trim().toUpperCase(Locale.ROOT);
        if (!cveId.matches("CVE-[0-9]{4}-[0-9]{4,}|GHSA-[A-Z0-9-]+")) {
            return new GhsaIngestionCounters(0, 0);
        }

        String sourceRecordId = support.hasText(ghsaId) ? ghsaId.trim().toUpperCase(Locale.ROOT) : cveId;
        String severity = support.normalizeUpper(support.textValue(advisoryNode.path("severity")));
        if (!support.hasText(severity)) {
            severity = support.severityFromCvss(support.numericValue(advisoryNode.path("cvss").path("score")));
        }
        Double cvss = support.numericValue(advisoryNode.path("cvss").path("score"));
        String description = support.firstNonBlank(
                support.textValue(advisoryNode.path("summary")),
                support.textValue(advisoryNode.path("description")),
                cveId
        );
        String referencesJson = support.toJson(extractGhsaReferences(advisoryNode));
        Instant publishedAt = support.parseInstantOrNull(support.textValue(advisoryNode.path("published_at")));
        Instant lastModifiedAt = support.parseInstantOrNull(support.textValue(advisoryNode.path("updated_at")));

        VulnerabilityIntelligenceService.ObservationUpsertResult upsertResult = observationIngestionService.upsertObservation(
                new VulnerabilityIntelligenceService.ObservationUpsertRequest(
                        cveId,
                        "ghsa",
                        sourceRecordId,
                        support.textValue(advisoryNode.path("html_url")),
                        support.hasText(ghsaId) ? ghsaId : cveId,
                        description,
                        severity,
                        cvss,
                        support.textValue(advisoryNode.path("cvss").path("vector_string")),
                        null,
                        null,
                        null,
                        null,
                        referencesJson,
                        support.hasText(ghsaId) ? ghsaId : null,
                        publishedAt,
                        lastModifiedAt,
                        advisoryNode.toString()
                )
        );
        Vulnerability vulnerability = upsertResult.vulnerability();
        if(!advisoryNode.path("withdrawn_at").isNull() && !advisoryNode.path("withdrawn_at").isMissingNode()) {
            support.withdrawSource(vulnerability,"ghsa",sourceRecordId);
            return new GhsaIngestionCounters(0,1);
        }
        support.replaceTargetsForRecord(vulnerability, List.of("ghsa"),sourceRecordId);

        JsonNode packageRules = advisoryNode.path("vulnerabilities");
        Set<String> dedupe = new HashSet<>();
        if (packageRules.isArray()) {
            for (JsonNode packageRule : packageRules) {
                String ecosystem = IdentityUtil.normalize(support.textValue(packageRule.path("package").path("ecosystem")));
                String packageName = IdentityUtil.normalize(support.textValue(packageRule.path("package").path("name")));
                if (!support.hasText(packageName)) {
                    continue;
                }
                String range = support.textValue(packageRule.path("vulnerable_version_range"));
                String firstPatched = support.textValue(packageRule.path("first_patched_version").path("identifier"));
                ParsedGhsaRange parsedRange = parseGhsaRange(range, firstPatched);
                SoftwareIdentity identity = identityGraphService.resolveFromTarget(
                        ecosystem,
                        packageName,
                        null,
                        null,
                        null,
                        null,
                        "ghsa"
                );
                String qualifiersJson = support.toJson(java.util.Map.of(
                        "ghsaId", support.hasText(ghsaId) ? ghsaId : "",
                        "vulnerableVersionRange", support.hasText(range) ? range : "",
                        "firstPatchedVersion", support.hasText(firstPatched) ? firstPatched : ""
                ));

                support.saveTargetWithDedupe(
                        dedupe,
                        support.createTarget(
                                vulnerability,
                                identity,
                                VulnerabilityTargetType.ADVISORY_PACKAGE,
                                IdentityUtil.coordKey(ecosystem, packageName),
                                ecosystem,
                                null,
                                packageName,
                                null,
                                support.hasText(range) ? range : sourceRecordId,
                                parsedRange.versionExact(),
                                parsedRange.versionStart(),
                                parsedRange.startInclusive(),
                                parsedRange.versionEnd(),
                                parsedRange.endInclusive(),
                                parsedRange.introduced(),
                                parsedRange.fixed(),
                                VersionScheme.UNKNOWN,
                                null,
                                null,
                                qualifiersJson,
                                "ghsa",
                                lastModifiedAt == null ? Instant.now().toString() : lastModifiedAt.toString()
                        )
                );
            }
        }

        if (upsertResult.vulnerabilityCreated()) {
            return new GhsaIngestionCounters(1, 0);
        }
        return new GhsaIngestionCounters(0, 1);
    }

    private ParsedGhsaRange parseGhsaRange(String range, String firstPatchedVersion) {
        String versionExact = null;
        String versionStart = null;
        Boolean startInclusive = null;
        String versionEnd = null;
        Boolean endInclusive = null;
        String introduced = null;
        String fixed = support.nullIfBlank(firstPatchedVersion);

        if (support.hasText(range)) {
            String normalized = range.trim();
            String[] parts = normalized.split(",");
            for (String part : parts) {
                String token = part == null ? "" : part.trim();
                if (token.isBlank()) {
                    continue;
                }
                if (token.startsWith(">=")) {
                    versionStart = token.substring(2).trim();
                    startInclusive = Boolean.TRUE;
                    introduced = versionStart;
                    continue;
                }
                if (token.startsWith(">")) {
                    versionStart = token.substring(1).trim();
                    startInclusive = Boolean.FALSE;
                    introduced = versionStart;
                    continue;
                }
                if (token.startsWith("<=")) {
                    versionEnd = token.substring(2).trim();
                    endInclusive = Boolean.TRUE;
                    continue;
                }
                if (token.startsWith("<")) {
                    versionEnd = token.substring(1).trim();
                    endInclusive = Boolean.FALSE;
                    continue;
                }
                if (token.startsWith("=")) {
                    versionExact = token.substring(1).trim();
                }
            }
        }
        return new ParsedGhsaRange(
                support.nullIfBlank(versionExact),
                support.nullIfBlank(versionStart),
                startInclusive,
                support.nullIfBlank(versionEnd),
                endInclusive,
                support.nullIfBlank(introduced),
                support.nullIfBlank(fixed)
        );
    }

    private List<String> extractGhsaReferences(JsonNode advisoryNode) {
        LinkedHashSet<String> refs = new LinkedHashSet<>();
        String htmlUrl = support.textValue(advisoryNode.path("html_url"));
        if (support.hasText(htmlUrl)) {
            refs.add(htmlUrl.trim());
        }
        JsonNode references = advisoryNode.path("references");
        if (references.isArray()) {
            for (JsonNode reference : references) {
                String url = support.textValue(reference.path("url"));
                if (support.hasText(url)) {
                    refs.add(url.trim());
                }
            }
        }
        return List.copyOf(refs);
    }

    private String firstCveIdentifier(JsonNode identifiersNode) {
        if (!identifiersNode.isArray()) {
            return null;
        }
        for (JsonNode identifier : identifiersNode) {
            String type = support.normalizeUpper(support.textValue(identifier.path("type")));
            String value = support.textValue(identifier.path("value"));
            if ("CVE".equals(type) && support.hasText(value)) {
                return value.trim();
            }
        }
        return null;
    }

    private ResponseEntity<String> exchangeJson(String url) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.ACCEPT, "application/vnd.github+json");
        headers.set("X-GitHub-Api-Version", GHSA_API_VERSION);
        headers.set(HttpHeaders.USER_AGENT, GITHUB_USER_AGENT);
        githubTokenProvider.applyPlatformFeedBearerAuth(headers);
        try {
            return outboundHttpClient.exchange(
                    URI.create(url).toString(),
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class,
                    "GitHub advisories API",
                    outboundPolicy(),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException runtimeException
                                    ? runtimeException
                                    : new RuntimeException(context.error())
                    )
            );
        } catch (RuntimeException runtimeException) {
            throw runtimeException;
        } catch (Exception checkedException) {
            throw new RuntimeException(checkedException);
        }
    }

    private String parseLinkNext(String linkHeader) {
        if (!support.hasText(linkHeader)) {
            return null;
        }
        Matcher matcher = GHSA_LINK_NEXT_PATTERN.matcher(linkHeader);
        if (!matcher.find()) {
            return null;
        }
        return matcher.group(1);
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("github", 0L, githubMaxRetries, githubRetryBaseBackoffMs);
    }
}
