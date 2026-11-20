package com.prototype.vulnwatch.service;

import java.time.ZoneOffset;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Immutable acquisition scope. Year constraints refer exclusively to publication dates. */
public record IntelligenceImportProfile(UUID id, String name, List<String> sources,
        Integer publicationYearFrom, Integer publicationYearTo, Double minCvss,
        Double maxCvss, Set<String> severities, boolean includeUnknownScores) {
    public IntelligenceImportProfile {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Profile name is required");
        sources = sources == null ? List.of() : List.copyOf(sources);
        severities = severities == null ? Set.of() : Set.copyOf(severities);
        if (sources.isEmpty()) throw new IllegalArgumentException("At least one source is required");
        if (publicationYearFrom != null && (publicationYearFrom < 1970 || publicationYearFrom > 9998)
                || publicationYearTo != null && (publicationYearTo < 1970 || publicationYearTo > 9998)
                || publicationYearFrom != null && publicationYearTo != null && publicationYearFrom > publicationYearTo)
            throw new IllegalArgumentException("Invalid publication year range");
        if (minCvss != null && (!Double.isFinite(minCvss) || minCvss < 0 || minCvss > 10)
                || maxCvss != null && (!Double.isFinite(maxCvss) || maxCvss < 0 || maxCvss > 10)
                || minCvss != null && maxCvss != null && minCvss > maxCvss)
            throw new IllegalArgumentException("Invalid CVSS range");
        if (!Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE").containsAll(severities))
            throw new IllegalArgumentException("Invalid severity");
    }

    public boolean matches(VulnerabilityIntelligenceService.ObservationUpsertRequest observation) {
        if (publicationYearFrom != null || publicationYearTo != null) {
            if (observation.publishedAt() == null) return false;
            int year = observation.publishedAt().atZone(ZoneOffset.UTC).getYear();
            if (publicationYearFrom != null && year < publicationYearFrom
                    || publicationYearTo != null && year > publicationYearTo) return false;
        }
        Double score = observation.cvssScore();
        if (score == null) {
            if ((minCvss != null || maxCvss != null) && !includeUnknownScores) return false;
        } else if (!Double.isFinite(score) || score < 0 || score > 10
                || minCvss != null && score < minCvss || maxCvss != null && score > maxCvss) return false;
        String severity = observation.severity() == null ? "UNKNOWN"
                : observation.severity().toUpperCase(java.util.Locale.ROOT);
        return severities.isEmpty() || severities.contains(severity);
    }
}
