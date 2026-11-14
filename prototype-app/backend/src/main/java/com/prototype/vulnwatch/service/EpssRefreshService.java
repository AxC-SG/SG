package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * BLG-016: EPSS (Exploit Prediction Scoring System) integration.
 *
 * Fetches exploitation probability scores from the FIRST.org EPSS API and
 * updates the epss_score and epss_updated_at columns on Vulnerability rows.
 *
 * The FIRST.org API accepts up to 100 CVE IDs per request and returns the
 * current daily score (0.0–1.0) and percentile for each one.
 *
 * Refresh runs daily (configurable). Only rows whose epss_updated_at is null
 * or older than 25 hours are fetched, avoiding redundant API calls.
 *
 * API reference: https://www.first.org/epss/api
 */
@Service
public class EpssRefreshService {

    private static final Logger LOG = LoggerFactory.getLogger(EpssRefreshService.class);

    @Value("${app.epss.base-url:https://api.first.org/data/v1/epss}")
    private String epssBaseUrl;

    @Value("${app.epss.batch-size:100}")
    private int batchSize;

    @Value("${app.epss.enabled:true}")
    private boolean enabled;

    private final VulnerabilityRepository vulnerabilityRepository;
    private final FindingDeltaQueueService findingDeltaQueueService;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;
    private volatile RefreshStatus lastRefresh = new RefreshStatus("NOT_RUN", 0, 0, 0, null);
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public EpssRefreshService(
            VulnerabilityRepository vulnerabilityRepository,
            FindingDeltaQueueService findingDeltaQueueService,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper
    ) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.findingDeltaQueueService = findingDeltaQueueService;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    private com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService durableRuns;
    private org.springframework.transaction.support.TransactionTemplate mutations;
    @Value("${app.epss.refresh-cron:0 15 3 * * *}") private String refreshCron;

    @org.springframework.beans.factory.annotation.Autowired
    void configureDurableRuns(com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService runs,
                              org.springframework.transaction.PlatformTransactionManager manager) {
        durableRuns = runs;
        mutations = new org.springframework.transaction.support.TransactionTemplate(manager);
    }

    private IntelligenceStagingService staging;
    @org.springframework.beans.factory.annotation.Autowired
    void configureStaging(IntelligenceStagingService staging) { this.staging=staging; }

    public void executeQueuedRun(UUID id) {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("epss.execute")) return;
        var run = durableRuns.markRunning(id);
        try {
            RefreshStatus result = refreshAllInPlatformContext();
            durableRuns.completeRun(run, "COMPLETED".equals(result.status()) ? "completed" : "partial",
                    result.attempted(), 0, result.updated(), result.unavailable(),
                    "COMPLETED".equals(result.status()) ? null : result.status());
        } catch (com.prototype.vulnwatch.service.vulningestion.VulnerabilityAttemptService.StaleAttemptException stale) {
            throw stale;
        } catch (RuntimeException failure) {
            durableRuns.completeRun(run, "failed", 0, 0, 0, 1, failure.getMessage());
        }
    }

    /**
     * Daily refresh at 03:15 UTC — runs after the FIRST.org daily publication window.
     * Cron is configurable via {@code app.epss.refresh-cron}.
     */
    @Scheduled(zone = "UTC", cron = "${app.epss.refresh-cron:0 15 3 * * *}")
    public void refreshAll() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("epss.refresh-all")) {
            return;
        }
        if (!enabled) {
            lastRefresh = new RefreshStatus("DISABLED", 0, 0, 0, Instant.now());
            return;
        }
        Instant occurrence = ScheduleOccurrence.due(refreshCron, Instant.now());
        if (occurrence == null) { LOG.warn("EPSS callback missed its one-minute admission window"); return; }
        TenantContext.runAsPlatform(() -> durableRuns.prepareScheduledRun("EPSS", occurrence));
    }

    private RefreshStatus refreshAllInPlatformContext() {
        if (!enabled) {
            lastRefresh = new RefreshStatus("DISABLED", 0, 0, 0, Instant.now());
            LOG.debug("EPSS refresh is disabled; skipping");
            return lastRefresh;
        }
        LOG.info("Starting daily EPSS refresh");
        int updated = 0, attempted = 0, incomplete = 0;
        Instant staleBefore = Instant.now().minus(25, ChronoUnit.HOURS);
        UUID upperId = staging.epssUpperId();
        UUID afterId = null;
        if (upperId != null) {
            while (true) {
                List<Vulnerability> stale = staging.epssCandidates(staleBefore,afterId,upperId,Math.max(1,Math.min(100,batchSize)));
                if (stale.isEmpty()) break;
                int batchUpdated = refreshBatch(stale);
                updated += batchUpdated;
                attempted += stale.size();
                incomplete += stale.size() - batchUpdated;
                afterId = stale.get(stale.size() - 1).getId();
            }
        }
        RefreshStatus result = new RefreshStatus(incomplete == 0 ? "COMPLETED" : "INCOMPLETE",
                attempted, updated, incomplete, Instant.now());
        lastRefresh = result;
        LOG.info("EPSS refresh {} — attempted {} updated {} unavailable {}",
                result.status(), attempted, updated, incomplete);
        return result;
    }

    public RefreshStatus lastRefresh() { return lastRefresh; }
    public record RefreshStatus(String status, int attempted, int updated, int unavailable, Instant completedAt) {}

    // -------------------------------------------------------------------------
    // Visible for testing
    // -------------------------------------------------------------------------

    int refreshBatch(List<Vulnerability> vulnerabilities) {
        if (vulnerabilities == null || vulnerabilities.isEmpty()) {
            return 0;
        }
        List<String> cveIds = vulnerabilities.stream()
                .map(Vulnerability::getExternalId)
                .filter(id -> id != null && id.toUpperCase(Locale.ROOT).startsWith("CVE-"))
                .collect(Collectors.toList());

        if (cveIds.isEmpty()) {
            return 0;
        }

        String url = UriComponentsBuilder.fromUriString(epssBaseUrl)
                .queryParam("cve", String.join(",", cveIds))
                .build()
                .toUriString();

        String payload;
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.set("User-Agent", "vulnwatch-backend/1.0");
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class,
                    "EPSS batch API",
                    outboundPolicy(),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException runtimeException
                                    ? runtimeException
                                    : new RuntimeException(context.error())
                    )
            );
            payload = response.getBody();
        } catch (Exception e) {
            LOG.warn("EPSS API request failed for batch of {} CVEs: {}", cveIds.size(), e.getMessage());
            return 0;
        }

        if (payload == null || payload.isBlank()) {
            return 0;
        }

        java.util.Map<String, Double> epssMap = parseEpssResponse(payload);
        if (epssMap.isEmpty()) {
            return 0;
        }

        int updated=0;
        for(Vulnerability vulnerability:vulnerabilities) {
            Double score=epssMap.get(vulnerability.getExternalId().toUpperCase(Locale.ROOT));
            if(score!=null) {
                staging.observation(new VulnerabilityIntelligenceService.ObservationUpsertRequest(
                        vulnerability.getExternalId(),"epss",vulnerability.getExternalId(),null,null,null,null,null,null,
                        score,null,null,null,null,null,null,Instant.now(),null));
                updated++;
            }
        }
        return updated;
    }

    private java.util.Map<String, Double> parseEpssResponse(String json) {
        java.util.Map<String, Double> result = new java.util.HashMap<>();
        try {
            JsonNode root = objectMapper.readTree(json);
            JsonNode data = root.path("data");
            if (!data.isArray()) {
                return result;
            }
            for (JsonNode entry : data) {
                String cve = entry.path("cve").asText("").toUpperCase(Locale.ROOT);
                String epssText = entry.path("epss").asText("");
                if (cve.isBlank() || epssText.isBlank()) {
                    continue;
                }
                try {
                    double score = Double.parseDouble(epssText);
                    if (Double.isFinite(score) && score >= 0 && score <= 1) result.put(cve, score);
                } catch (NumberFormatException ignored) {
                    // skip malformed entries
                }
            }
        } catch (Exception e) {
            LOG.warn("Failed to parse EPSS API response: {}", e.getMessage());
        }
        return result;
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("epss", 0L, null, null);
    }
}
