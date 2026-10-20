package com.prototype.vulnwatch.service;

import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Service;

@Service
public class OperationalMetricsService {

    public static final String KEY_VULN_INTEL_LIST = "vulnerability-intelligence-list";
    public static final String KEY_VULN_INTEL_FILTERS = "vulnerability-intelligence-filters";
    public static final String KEY_VULN_REPO_DASHBOARD = "vuln-repo-dashboard";
    public static final String KEY_VULN_REPO_VULNERABILITIES = "vuln-repo-vulnerabilities";
    public static final String KEY_VULN_REPO_ORG_CVES = "vuln-repo-org-cves";
    public static final String KEY_VULN_REPO_ORG_CVE_STATUS = "vuln-repo-org-cves-status";
    public static final String KEY_VULN_REPO_ORG_CVE_RECOMPUTE = "vuln-repo-org-cves-recompute";
    public static final String KEY_DASHBOARD_OVERVIEW = "dashboard-overview";
    public static final String KEY_DASHBOARD_APPLICABLE_SOFTWARE = "dashboard-applicable-software";
    public static final String KEY_DASHBOARD_IMPACTED_CVES = "dashboard-impacted-cves";
    public static final String KEY_DASHBOARD_CVE_INVENTORY_MAP = "dashboard-cve-inventory-map";
    public static final String KEY_OPERATIONS_DASHBOARD = "operations-dashboard";
    public static final String KEY_OPERATIONS_OVERVIEW = "operations-overview";
    public static final String KEY_OPERATIONS_INGESTION = "operations-ingestion-efficiency";
    public static final String KEY_OPERATIONS_NORMALIZATION = "operations-normalization-quality";
    public static final String KEY_OPERATIONS_CORRELATION = "operations-correlation-effectiveness";
    public static final String KEY_OPERATIONS_LIFECYCLE = "operations-noise-lifecycle";
    public static final String KEY_OPERATIONS_READ_PATH = "operations-api-read-path";
    public static final String KEY_OPERATIONS_FRESHNESS = "operations-freshness-drift";
    public static final String KEY_OPERATIONS_CATALOG = "operations-metric-catalog";
    public static final String KEY_FINDINGS_LIST = "findings-list";
    public static final String KEY_FINDINGS_SUMMARY = "findings-summary";
    public static final String KEY_FINDINGS_DISTRIBUTIONS = "findings-distributions";
    public static final String KEY_FINDINGS_BACKLOG_HEALTH = "findings-backlog-health";
    public static final String KEY_FINDINGS_FILTERS = "findings-filters";
    public static final String KEY_FINDINGS_PROJECTION_STATUS = "findings-projection-status";
    public static final String KEY_INVENTORY_COMPONENTS = "inventory-components";
    public static final String KEY_INVENTORY_COMPONENT_FILTERS = "inventory-component-filters";
    public static final String KEY_INVENTORY_SOFTWARE_IDENTITIES = "inventory-software-identities";
    public static final String KEY_INVENTORY_SOFTWARE_IDENTITY_FUNNEL = "inventory-software-identity-funnel";
    public static final String KEY_SBOM_FETCH_ENDPOINT = "sbom-fetch-endpoint";
    public static final String KEY_SBOM_FETCH_GITHUB = "sbom-fetch-github";
    public static final String KEY_INGESTION_NVD_SYNC = "ingestion-nvd-sync";
    public static final String KEY_INGESTION_NVD_FULL_SYNC = "ingestion-nvd-full-sync";
    public static final String KEY_INGESTION_KEV_SYNC = "ingestion-kev-sync";
    public static final String KEY_INGESTION_GHSA_SYNC = "ingestion-ghsa-sync";
    public static final String KEY_INGESTION_CSAF_MICROSOFT_SYNC = "ingestion-csaf-microsoft-sync";
    public static final String KEY_INGESTION_CSAF_REDHAT_SYNC = "ingestion-csaf-redhat-sync";
    public static final String KEY_INGESTION_ADVISORIES = "ingestion-advisories";
    public static final String KEY_INGESTION_RECOMPUTE_FINDINGS = "ingestion-recompute-findings";
    public static final String KEY_NOISE_PROJECTION_REFRESH = "noise-reduction-projection-refresh";
    public static final String KEY_FINDINGS_PROJECTION_REFRESH = "findings-projection-refresh";
    public static final int MAX_SAMPLES_PER_KEY = 500;

    private final Map<String, ArrayDeque<Sample>> samplesByKey = new HashMap<>();

    public void record(String metricKey, long durationMs, int statusCode) {
        if (!hasText(metricKey) || durationMs < 0) {
            return;
        }
        synchronized (samplesByKey) {
            ArrayDeque<Sample> samples = samplesByKey.computeIfAbsent(metricKey, ignored -> new ArrayDeque<>());
            if (samples.size() >= MAX_SAMPLES_PER_KEY) {
                samples.removeFirst();
            }
            samples.addLast(new Sample(durationMs, Instant.now(), statusCode));
        }
    }

    public MetricSnapshot snapshot(String metricKey) {
        synchronized (samplesByKey) {
            ArrayDeque<Sample> samples = samplesByKey.get(metricKey);
            if (samples == null || samples.isEmpty()) {
                return new MetricSnapshot(metricKey, 0L, 0L, 0L, 0.0, 0.0, 0.0, 0L, 0L, null);
            }

            long requestCount = samples.size();
            long successCount = samples.stream().filter(sample -> sample.statusCode() < 400).count();
            long errorCount = requestCount - successCount;
            long maxMs = 0L;
            long totalDuration = 0L;
            long lastMs = 0L;
            Instant lastRecordedAt = null;
            List<Long> durations = new ArrayList<>(samples.size());
            for (Sample sample : samples) {
                long durationMs = sample.durationMs();
                durations.add(durationMs);
                totalDuration += durationMs;
                if (durationMs > maxMs) {
                    maxMs = durationMs;
                }
                lastMs = durationMs;
                lastRecordedAt = sample.recordedAt();
            }
            durations.sort(Long::compareTo);
            double averageMs = (double) totalDuration / (double) requestCount;
            double p95Ms = percentile(durations, 0.95);
            double p99Ms = percentile(durations, 0.99);

            return new MetricSnapshot(
                    metricKey,
                    requestCount,
                    successCount,
                    errorCount,
                    averageMs,
                    p95Ms,
                    p99Ms,
                    maxMs,
                    lastMs,
                    lastRecordedAt
            );
        }
    }

    public List<MetricSnapshot> snapshots() {
        synchronized (samplesByKey) {
            List<MetricSnapshot> snapshots = new ArrayList<>();
            for (String key : samplesByKey.keySet()) {
                snapshots.add(snapshot(key));
            }
            snapshots.sort(Comparator.comparing(MetricSnapshot::key));
            return snapshots;
        }
    }

    private double percentile(List<Long> sortedDurations, double percentile) {
        if (sortedDurations == null || sortedDurations.isEmpty()) {
            return 0.0;
        }
        double boundedPercentile = Math.max(0.0, Math.min(1.0, percentile));
        int index = (int) Math.ceil(boundedPercentile * sortedDurations.size()) - 1;
        int safeIndex = Math.max(0, Math.min(sortedDurations.size() - 1, index));
        return sortedDurations.get(safeIndex);
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private record Sample(
            long durationMs,
            Instant recordedAt,
            int statusCode
    ) {
    }

    public record MetricSnapshot(
            String key,
            long requestCount,
            long successCount,
            long errorCount,
            double averageMs,
            double p95Ms,
            double p99Ms,
            long maxMs,
            long lastMs,
            Instant lastRecordedAt
    ) {
    }
}
