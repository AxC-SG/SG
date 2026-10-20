package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.dto.OperationalApiReadPathResponse;
import com.prototype.vulnwatch.dto.OperationalCorrelationEffectivenessResponse;
import com.prototype.vulnwatch.dto.OperationalDashboardResponse;
import com.prototype.vulnwatch.dto.OperationalEndpointMetricResponse;
import com.prototype.vulnwatch.dto.OperationalExecutiveHealthResponse;
import com.prototype.vulnwatch.dto.OperationalFreshnessDriftResponse;
import com.prototype.vulnwatch.dto.OperationalIngestionEfficiencyResponse;
import com.prototype.vulnwatch.dto.OperationalIngestionSourceMetricResponse;
import com.prototype.vulnwatch.dto.OperationalMetricDefinitionResponse;
import com.prototype.vulnwatch.dto.OperationalNoiseLifecycleResponse;
import com.prototype.vulnwatch.dto.OperationalNormalizationQualityResponse;
import com.prototype.vulnwatch.dto.OperationalSectionResponse;
import com.prototype.vulnwatch.dto.OperationalSourceFreshnessResponse;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.repo.VulnerabilityIntelSummaryRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class OperationalDashboardService {

    private static final String CVE_PREFIX = "CVE-";
    private static final long HOURS_24 = 24L;
    private static final long HOURS_24_X_7 = HOURS_24 * 7L;

    private final VulnerabilityRepository vulnerabilityRepository;
    private final VulnerabilityIntelSummaryRepository vulnerabilityIntelSummaryRepository;
    private final VulnerabilityIntelQueryService vulnerabilityIntelQueryService;
    private final OperationalMetricsService operationalMetricsService;
    private final SyncRunRepository syncRunRepository;

    public OperationalDashboardService(
            VulnerabilityRepository vulnerabilityRepository,
            VulnerabilityIntelSummaryRepository vulnerabilityIntelSummaryRepository,
            VulnerabilityIntelQueryService vulnerabilityIntelQueryService,
            OperationalMetricsService operationalMetricsService,
            SyncRunRepository syncRunRepository
    ) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.vulnerabilityIntelSummaryRepository = vulnerabilityIntelSummaryRepository;
        this.vulnerabilityIntelQueryService = vulnerabilityIntelQueryService;
        this.operationalMetricsService = operationalMetricsService;
        this.syncRunRepository = syncRunRepository;
    }

    public OperationalDashboardResponse get() {
        Instant now = Instant.now();
        List<SyncRun> syncRuns = syncRunRepository.findAllByOrderByStartedAtDesc().stream()
                .filter(run -> run.getStartedAt() != null && !run.getStartedAt().isBefore(now.minus(Duration.ofHours(HOURS_24_X_7))))
                .toList();
        List<SyncRun> syncRuns24h = syncRuns.stream()
                .filter(run -> run.getStartedAt() != null && run.getStartedAt().isAfter(now.minus(Duration.ofHours(HOURS_24))))
                .toList();

        OperationalMetricsService.MetricSnapshot projectionRefreshSnapshot =
                operationalMetricsService.snapshot(OperationalMetricsService.KEY_NOISE_PROJECTION_REFRESH);
        long syncSuccesses24h = syncRuns24h.stream().filter(run -> isCompleted(run.getStatus())).count();

        return new OperationalDashboardResponse(
                now,
                new OperationalExecutiveHealthResponse(
                        percentage(syncSuccesses24h, syncRuns24h.size()),
                        projectionRefreshSnapshot.p95Ms(),
                        0.0,
                        0.0,
                        0L
                ),
                buildIngestionEfficiency(syncRuns24h),
                emptyNormalizationQuality(),
                emptyCorrelationEffectiveness(),
                emptyNoiseLifecycle(),
                buildApiReadPath(),
                buildFreshnessDrift(now, syncRuns),
                metricCatalog()
        );
    }

    public OperationalSectionResponse<OperationalExecutiveHealthResponse> getOverview() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.executiveHealth());
    }

    public OperationalSectionResponse<OperationalIngestionEfficiencyResponse> getIngestionEfficiency() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.ingestionEfficiency());
    }

    public OperationalSectionResponse<OperationalNormalizationQualityResponse> getNormalizationQuality() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.normalizationQuality());
    }

    public OperationalSectionResponse<OperationalCorrelationEffectivenessResponse> getCorrelationEffectiveness() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.correlationEffectiveness());
    }

    public OperationalSectionResponse<OperationalNoiseLifecycleResponse> getNoiseLifecycle() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.noiseLifecycle());
    }

    public OperationalSectionResponse<OperationalApiReadPathResponse> getApiReadPath() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.apiReadPath());
    }

    public OperationalSectionResponse<OperationalFreshnessDriftResponse> getFreshnessDrift() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.freshnessDrift());
    }

    public OperationalSectionResponse<List<OperationalMetricDefinitionResponse>> getMetricCatalog() {
        OperationalDashboardResponse dashboard = get();
        return new OperationalSectionResponse<>(dashboard.generatedAt(), dashboard.metricCatalog());
    }

    private OperationalIngestionEfficiencyResponse buildIngestionEfficiency(List<SyncRun> syncRuns24h) {
        long queueBacklog = syncRunRepository.findQueueByStatuses(List.of("queued", "running")).size();
        long recordsFetched = syncRuns24h.stream().mapToLong(run -> Math.max(0, run.getRecordsFetched())).sum();
        long recordsInserted = syncRuns24h.stream().mapToLong(run -> Math.max(0, run.getRecordsInserted())).sum();
        long recordsUpdated = syncRuns24h.stream().mapToLong(run -> Math.max(0, run.getRecordsUpdated())).sum();

        Map<String, SourceRunStats> sourceStats = new HashMap<>();
        for (SyncRun run : syncRuns24h) {
            String source = normalizeSource(run.getSyncType());
            SourceRunStats stats = sourceStats.computeIfAbsent(source, ignored -> new SourceRunStats());
            stats.runs += 1;
            stats.successes += isCompleted(run.getStatus()) ? 1 : 0;
            stats.failures += isFailed(run.getStatus()) ? 1 : 0;
            stats.fetched += Math.max(0, run.getRecordsFetched());
            stats.inserted += Math.max(0, run.getRecordsInserted());
            stats.updated += Math.max(0, run.getRecordsUpdated());
        }

        List<OperationalIngestionSourceMetricResponse> sourceBreakdown = sourceStats.entrySet().stream()
                .map(entry -> new OperationalIngestionSourceMetricResponse(
                        entry.getKey(),
                        entry.getValue().runs,
                        entry.getValue().successes,
                        entry.getValue().failures,
                        percentage(entry.getValue().successes, entry.getValue().runs),
                        entry.getValue().fetched,
                        entry.getValue().inserted,
                        entry.getValue().updated
                ))
                .sorted(Comparator.comparing(OperationalIngestionSourceMetricResponse::source))
                .toList();

        long syncSuccesses = syncRuns24h.stream().filter(run -> isCompleted(run.getStatus())).count();
        return new OperationalIngestionEfficiencyResponse(
                0L,
                0.0,
                0.0,
                syncRuns24h.size(),
                percentage(syncSuccesses, syncRuns24h.size()),
                queueBacklog,
                recordsFetched,
                recordsInserted,
                recordsUpdated,
                sourceBreakdown
        );
    }

    private OperationalApiReadPathResponse buildApiReadPath() {
        VulnerabilityIntelligenceService.OperationalState state = vulnerabilityIntelQueryService.getOperationalState();
        long canonicalCveCount = vulnerabilityRepository.countByExternalIdStartingWith(CVE_PREFIX);
        long summaryCveCount = vulnerabilityIntelSummaryRepository.countByExternalIdStartingWith(CVE_PREFIX);
        double summaryCoveragePercent = canonicalCveCount <= 0
                ? 100.0
                : percentage(summaryCveCount, canonicalCveCount);
        long totalFilterCalls = state.filterCacheHits() + state.filterCacheMisses();
        double filterCacheHitRatio = percentage(state.filterCacheHits(), totalFilterCalls);

        List<String> trackedKeys = List.of(
                OperationalMetricsService.KEY_VULN_INTEL_LIST,
                OperationalMetricsService.KEY_VULN_INTEL_FILTERS,
                OperationalMetricsService.KEY_DASHBOARD_OVERVIEW,
                OperationalMetricsService.KEY_DASHBOARD_APPLICABLE_SOFTWARE,
                OperationalMetricsService.KEY_DASHBOARD_IMPACTED_CVES,
                OperationalMetricsService.KEY_DASHBOARD_CVE_INVENTORY_MAP,
                OperationalMetricsService.KEY_VULN_REPO_DASHBOARD,
                OperationalMetricsService.KEY_VULN_REPO_VULNERABILITIES,
                OperationalMetricsService.KEY_VULN_REPO_ORG_CVES,
                OperationalMetricsService.KEY_VULN_REPO_ORG_CVE_STATUS,
                OperationalMetricsService.KEY_VULN_REPO_ORG_CVE_RECOMPUTE,
                OperationalMetricsService.KEY_OPERATIONS_DASHBOARD,
                OperationalMetricsService.KEY_OPERATIONS_OVERVIEW,
                OperationalMetricsService.KEY_OPERATIONS_INGESTION,
                OperationalMetricsService.KEY_OPERATIONS_READ_PATH,
                OperationalMetricsService.KEY_OPERATIONS_FRESHNESS,
                OperationalMetricsService.KEY_OPERATIONS_CATALOG,
                OperationalMetricsService.KEY_FINDINGS_LIST,
                OperationalMetricsService.KEY_FINDINGS_SUMMARY,
                OperationalMetricsService.KEY_FINDINGS_DISTRIBUTIONS,
                OperationalMetricsService.KEY_FINDINGS_BACKLOG_HEALTH,
                OperationalMetricsService.KEY_FINDINGS_FILTERS,
                OperationalMetricsService.KEY_FINDINGS_PROJECTION_STATUS,
                OperationalMetricsService.KEY_INVENTORY_COMPONENTS,
                OperationalMetricsService.KEY_INVENTORY_COMPONENT_FILTERS,
                OperationalMetricsService.KEY_INVENTORY_SOFTWARE_IDENTITIES,
                OperationalMetricsService.KEY_INVENTORY_SOFTWARE_IDENTITY_FUNNEL,
                OperationalMetricsService.KEY_SBOM_FETCH_ENDPOINT,
                OperationalMetricsService.KEY_SBOM_FETCH_GITHUB,
                OperationalMetricsService.KEY_INGESTION_NVD_SYNC,
                OperationalMetricsService.KEY_INGESTION_NVD_FULL_SYNC,
                OperationalMetricsService.KEY_INGESTION_KEV_SYNC,
                OperationalMetricsService.KEY_INGESTION_GHSA_SYNC,
                OperationalMetricsService.KEY_INGESTION_CSAF_MICROSOFT_SYNC,
                OperationalMetricsService.KEY_INGESTION_CSAF_REDHAT_SYNC,
                OperationalMetricsService.KEY_INGESTION_ADVISORIES,
                OperationalMetricsService.KEY_INGESTION_RECOMPUTE_FINDINGS
        );
        List<OperationalEndpointMetricResponse> endpointMetrics = trackedKeys.stream()
                .map(operationalMetricsService::snapshot)
                .map(snapshot -> new OperationalEndpointMetricResponse(
                        snapshot.key(),
                        metricLabel(snapshot.key()),
                        snapshot.requestCount(),
                        snapshot.successCount(),
                        snapshot.errorCount(),
                        snapshot.averageMs(),
                        snapshot.p95Ms(),
                        snapshot.p99Ms(),
                        snapshot.maxMs(),
                        snapshot.lastMs(),
                        snapshot.lastRecordedAt()
                ))
                .toList();

        return new OperationalApiReadPathResponse(
                state.summaryReadModelReady(),
                canonicalCveCount,
                summaryCveCount,
                summaryCoveragePercent,
                state.filterCacheActive(),
                state.filterCacheExpiresAt(),
                state.filterCacheHits(),
                state.filterCacheMisses(),
                filterCacheHitRatio,
                endpointMetrics,
                "JVM_LOCAL_RECENT_REQUESTS",
                OperationalMetricsService.MAX_SAMPLES_PER_KEY
        );
    }

    private OperationalFreshnessDriftResponse buildFreshnessDrift(Instant now, List<SyncRun> syncRuns) {
        long staleThresholdHours = HOURS_24;
        Duration staleThreshold = Duration.ofHours(staleThresholdHours);

        Map<String, Instant> latestBySource = new LinkedHashMap<>();
        for (SyncRun run : syncRuns) {
            if (!isCompleted(run.getStatus()) || run.getStartedAt() == null) {
                continue;
            }
            String source = normalizeSource(run.getSyncType());
            latestBySource.merge(source, run.getStartedAt(), (left, right) -> right.isAfter(left) ? right : left);
        }

        List<OperationalSourceFreshnessResponse> freshness = latestBySource.entrySet().stream()
                .map(entry -> toFreshness(now, staleThreshold, entry.getKey(), entry.getValue()))
                .sorted(Comparator.comparing(OperationalSourceFreshnessResponse::source))
                .toList();
        long staleSourceCount = freshness.stream().filter(OperationalSourceFreshnessResponse::stale).count();

        return new OperationalFreshnessDriftResponse(
                staleThresholdHours,
                staleSourceCount,
                0.0,
                0.0,
                freshness
        );
    }

    private OperationalSourceFreshnessResponse toFreshness(
            Instant now,
            Duration staleThreshold,
            String source,
            Instant lastSuccessfulAt
    ) {
        if (lastSuccessfulAt == null) {
            return new OperationalSourceFreshnessResponse(source, null, -1L, true);
        }
        long ageHours = Math.max(0L, Duration.between(lastSuccessfulAt, now).toHours());
        boolean stale = Duration.between(lastSuccessfulAt, now).compareTo(staleThreshold) > 0;
        return new OperationalSourceFreshnessResponse(source, lastSuccessfulAt, ageHours, stale);
    }

    private OperationalNormalizationQualityResponse emptyNormalizationQuality() {
        return new OperationalNormalizationQualityResponse(0L, 0.0, 0.0, 0.0);
    }

    private OperationalCorrelationEffectivenessResponse emptyCorrelationEffectiveness() {
        return new OperationalCorrelationEffectivenessResponse(0L, 0.0, 0.0, List.of(), List.of(), List.of());
    }

    private OperationalNoiseLifecycleResponse emptyNoiseLifecycle() {
        return new OperationalNoiseLifecycleResponse(0L, 0L, 0L, 0L, 0.0, 0.0, List.of());
    }

    private boolean isCompleted(String status) {
        return hasText(status) && "completed".equalsIgnoreCase(status.trim());
    }

    private boolean isFailed(String status) {
        return hasText(status) && "failed".equalsIgnoreCase(status.trim());
    }

    private String normalizeSource(String value) {
        if (!hasText(value)) {
            return "UNKNOWN";
        }
        return value.trim().toUpperCase(Locale.ROOT).replace(' ', '_');
    }

    private double percentage(long numerator, long denominator) {
        if (denominator <= 0) {
            return 0.0;
        }
        return (double) numerator * 100.0 / (double) denominator;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String metricLabel(String key) {
        return switch (key) {
            case OperationalMetricsService.KEY_VULN_INTEL_LIST -> "Vulnerability Intelligence List";
            case OperationalMetricsService.KEY_VULN_INTEL_FILTERS -> "Vulnerability Intelligence Filters";
            case OperationalMetricsService.KEY_DASHBOARD_OVERVIEW -> "Overview Dashboard";
            case OperationalMetricsService.KEY_DASHBOARD_APPLICABLE_SOFTWARE -> "Applicable Software";
            case OperationalMetricsService.KEY_DASHBOARD_IMPACTED_CVES -> "Impacted CVEs";
            case OperationalMetricsService.KEY_DASHBOARD_CVE_INVENTORY_MAP -> "CVE Inventory Map";
            case OperationalMetricsService.KEY_VULN_REPO_DASHBOARD -> "Vulnerability Repository Dashboard";
            case OperationalMetricsService.KEY_VULN_REPO_VULNERABILITIES -> "Vulnerability Repository Vulnerabilities";
            case OperationalMetricsService.KEY_VULN_REPO_ORG_CVES -> "Vulnerability Investigation";
            case OperationalMetricsService.KEY_VULN_REPO_ORG_CVE_STATUS -> "Vulnerability Investigation Status";
            case OperationalMetricsService.KEY_VULN_REPO_ORG_CVE_RECOMPUTE -> "Vulnerability Investigation Recompute";
            case OperationalMetricsService.KEY_OPERATIONS_DASHBOARD -> "Operations Dashboard";
            case OperationalMetricsService.KEY_OPERATIONS_OVERVIEW -> "Operations Overview";
            case OperationalMetricsService.KEY_OPERATIONS_INGESTION -> "Operations Ingestion Efficiency";
            case OperationalMetricsService.KEY_OPERATIONS_READ_PATH -> "Operations API Read-Path";
            case OperationalMetricsService.KEY_OPERATIONS_FRESHNESS -> "Operations Freshness";
            case OperationalMetricsService.KEY_OPERATIONS_CATALOG -> "Operations Metric Catalog";
            case OperationalMetricsService.KEY_FINDINGS_LIST -> "Findings List";
            case OperationalMetricsService.KEY_FINDINGS_SUMMARY -> "Findings Summary";
            case OperationalMetricsService.KEY_FINDINGS_DISTRIBUTIONS -> "Findings Distributions";
            case OperationalMetricsService.KEY_FINDINGS_BACKLOG_HEALTH -> "Findings Backlog Health";
            case OperationalMetricsService.KEY_FINDINGS_FILTERS -> "Findings Filters";
            case OperationalMetricsService.KEY_FINDINGS_PROJECTION_STATUS -> "Findings Projection Status";
            case OperationalMetricsService.KEY_INVENTORY_COMPONENTS -> "Inventory Components";
            case OperationalMetricsService.KEY_INVENTORY_COMPONENT_FILTERS -> "Inventory Component Filters";
            case OperationalMetricsService.KEY_INVENTORY_SOFTWARE_IDENTITIES -> "Software Identities";
            case OperationalMetricsService.KEY_INVENTORY_SOFTWARE_IDENTITY_FUNNEL -> "Software Identity Funnel";
            case OperationalMetricsService.KEY_SBOM_FETCH_ENDPOINT -> "SBOM Fetch Endpoint";
            case OperationalMetricsService.KEY_SBOM_FETCH_GITHUB -> "SBOM Fetch GitHub";
            case OperationalMetricsService.KEY_INGESTION_NVD_SYNC -> "NVD Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_NVD_FULL_SYNC -> "NVD Full Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_KEV_SYNC -> "KEV Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_GHSA_SYNC -> "GHSA Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_CSAF_MICROSOFT_SYNC -> "CSAF Microsoft Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_CSAF_REDHAT_SYNC -> "CSAF Red Hat Sync Trigger";
            case OperationalMetricsService.KEY_INGESTION_ADVISORIES -> "Advisory Ingest Trigger";
            case OperationalMetricsService.KEY_INGESTION_RECOMPUTE_FINDINGS -> "Recompute Findings Trigger";
            case OperationalMetricsService.KEY_NOISE_PROJECTION_REFRESH -> "Projection Refresh Worker";
            default -> key;
        };
    }

    private List<OperationalMetricDefinitionResponse> metricCatalog() {
        List<OperationalMetricDefinitionResponse> metrics = new ArrayList<>();
        metrics.add(new OperationalMetricDefinitionResponse(
                "Executive Health",
                "sync.success_rate_24h",
                "Sync Success Rate (24h)",
                "Successful connector and source sync runs divided by all sync attempts in the last 24 hours."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Executive Health",
                "projection.refresh_p95_ms",
                "Projection Refresh P95 (ms)",
                "P95 processing time for the global projection refresh worker."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Ingestion Efficiency",
                "sync.runs_24h",
                "Sync Runs (24h)",
                "Total connector and source synchronization runs processed in the last 24 hours."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Ingestion Efficiency",
                "sync.records_24h",
                "Sync Records Processed (24h)",
                "Total records fetched, inserted, and updated from sync runs in the last 24 hours."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "API & Read-Path",
                "api.summary_coverage",
                "Summary Coverage",
                "Percent of canonical CVEs represented in the global summary read model."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "API & Read-Path",
                "api.filter_cache_hit_ratio",
                "Filter Cache Hit Ratio",
                "Percent of eligible read-path requests served from cache."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "API & Read-Path",
                "api.endpoint_latency",
                "Endpoint Latency (Avg/P95/P99)",
                "Per-endpoint API latency and error counts for operationally relevant routes."
        ));
        metrics.add(new OperationalMetricDefinitionResponse(
                "Data Freshness",
                "freshness.stale_source_count",
                "Stale Source Count",
                "Number of ingestion sources without a successful sync run within the stale threshold."
        ));
        return metrics;
    }

    private static final class SourceRunStats {
        private long runs;
        private long successes;
        private long failures;
        private long fetched;
        private long inserted;
        private long updated;
    }
}
