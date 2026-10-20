package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingAssetCountResponse;
import com.prototype.vulnwatch.dto.FindingBacklogHealthResponse;
import com.prototype.vulnwatch.dto.FindingCountBucketResponse;
import com.prototype.vulnwatch.dto.FindingDistributionsResponse;
import com.prototype.vulnwatch.dto.FindingsFilter;
import com.prototype.vulnwatch.dto.FindingSummaryResponse;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.springframework.stereotype.Service;

@Service
public class FindingAnalyticsService {

    private static final List<String> SEVERITY_ORDER = List.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN");
    private static final List<String> STATUS_ORDER = List.of("OPEN", "RESOLVED", "SUPPRESSED", "AUTO_CLOSED");

    private final FindingListProjectionService findingListProjectionService;

    public FindingAnalyticsService(
            FindingListProjectionService findingListProjectionService
    ) {
        this.findingListProjectionService = findingListProjectionService;
    }

    public List<FindingCountBucketResponse> groupCounts(Tenant tenant, FindingsFilter filter, String field) {
        return findingListProjectionService.groupCounts(tenant, filter, field);
    }

    // Projection reads select their tenant before opening their own read transaction.
    public FindingSummaryResponse getSummary(Tenant tenant, FindingsFilter filter) {
        List<FindingListProjectionService.ProjectionRecord> rows = findingListProjectionService.loadRows(tenant, filter);
        long openCount = rows.stream().filter(FindingListProjectionService.ProjectionRecord::isOpen).count();
        long criticalOpenCount = rows.stream()
                .filter(FindingListProjectionService.ProjectionRecord::isOpen)
                .filter(row -> "CRITICAL".equalsIgnoreCase(row.severity()))
                .count();
        long withIncidentCount = rows.stream().filter(row -> FindingFilterSpecifications.hasText(row.incidentId())).count();
        long unassignedOpenCount = rows.stream()
                .filter(FindingListProjectionService.ProjectionRecord::isOpen)
                .filter(row -> !FindingFilterSpecifications.hasText(row.assignedTo()))
                .count();
        FindingBacklogHealthResponse backlog = getBacklogHealth(tenant, filter);
        return new FindingSummaryResponse(
                openCount,
                criticalOpenCount,
                withIncidentCount,
                unassignedOpenCount,
                backlog.overdue(),
                backlog.noSla()
        );
    }

    public FindingDistributionsResponse getDistributions(Tenant tenant, FindingsFilter filter) {
        List<FindingListProjectionService.ProjectionRecord> findings = findingListProjectionService.loadRows(tenant, filter);

        Map<String, Long> severityCounts = findings.stream()
                .collect(Collectors.groupingBy(
                        finding -> finding.severity() == null ? "UNKNOWN" : finding.severity().trim().toUpperCase(),
                        LinkedHashMap::new,
                        Collectors.counting()
                ));
        Map<String, Long> statusCounts = findings.stream()
                .collect(Collectors.groupingBy(finding -> finding.status().trim().toUpperCase(), LinkedHashMap::new, Collectors.counting()));
        Map<String, Long> topAssetCounts = findings.stream()
                .filter(FindingListProjectionService.ProjectionRecord::isOpen)
                .map(FindingListProjectionService.ProjectionRecord::assetName)
                .filter(FindingFilterSpecifications::hasText)
                .collect(Collectors.groupingBy(assetName -> assetName, Collectors.counting()));

        return new FindingDistributionsResponse(
                toBuckets(severityCounts, SEVERITY_ORDER),
                toBuckets(statusCounts, STATUS_ORDER),
                topAssetCounts.entrySet().stream()
                        .sorted(Map.Entry.<String, Long>comparingByValue(Comparator.reverseOrder())
                                .thenComparing(Map.Entry.comparingByKey()))
                        .limit(5)
                        .map(entry -> new FindingAssetCountResponse(entry.getKey(), entry.getValue()))
                        .toList()
        );
    }

    public FindingBacklogHealthResponse getBacklogHealth(Tenant tenant, FindingsFilter filter) {
        List<FindingListProjectionService.ProjectionRecord> rows = findingListProjectionService.loadRows(tenant, filter);
        long overdue = 0;
        long dueSoon = 0;
        long onTrack = 0;
        long noSla = 0;
        java.time.Instant now = java.time.Instant.now();
        java.time.Instant soon = now.plus(java.time.temporal.ChronoUnit.DAYS.getDuration().multipliedBy(7));
        for (FindingListProjectionService.ProjectionRecord row : rows) {
            if (!row.isOpen()) {
                continue;
            }
            if (row.dueAt() == null) {
                noSla++;
            } else if (row.dueAt().isBefore(now)) {
                overdue++;
            } else if (row.dueAt().isBefore(soon)) {
                dueSoon++;
            } else {
                onTrack++;
            }
        }
        return new FindingBacklogHealthResponse(
                overdue,
                dueSoon,
                onTrack,
                noSla
        );
    }

    public long getMatchingCount(Tenant tenant, FindingsFilter filter) {
        return findingListProjectionService.loadRows(tenant, filter).size();
    }

    private List<FindingCountBucketResponse> toBuckets(Map<String, Long> counts, List<String> preferredOrder) {
        return FindingFilterSpecifications.sortByPreferredOrder(counts.keySet(), preferredOrder).stream()
                .map(key -> new FindingCountBucketResponse(key, counts.getOrDefault(key, 0L)))
                .toList();
    }

}
