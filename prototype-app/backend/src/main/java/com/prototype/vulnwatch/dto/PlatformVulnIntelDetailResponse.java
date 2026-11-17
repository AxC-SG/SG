package com.prototype.vulnwatch.dto;

import java.util.List;

public record PlatformVulnIntelDetailResponse(
        String externalId,
        String title,
        String description,
        String fullDescription,
        String severity,
        Double cvssScore,
        String cvssVector,
        Double epssScore,
        String cweIds,
        String vulnStatus,
        String publishedAt,
        String modifiedAt,
        boolean inKev,
        String kevDateAdded,
        String kevDueDate,
        String kevRequiredAction,
        List<String> sources,
        String euvdId,
        String jvndbId,
        List<String> cpes,
        List<String> references,
        List<SourceObservation> observations
) {
    public record SourceObservation(
            String sourceSystem,
            String sourceRecordId,
            String sourceUrl,
            String title,
            String description,
            String severity,
            Double cvssScore,
            String cvssVersion,
            String cvssVector,
            String publishedAt,
            String lastModifiedAt,
            String observedAt,
            String lastSeenAt,
            String payloadHash
    ) {}
}
