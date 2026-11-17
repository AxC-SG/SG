package com.prototype.vulnwatch.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Published platform intelligence, deliberately independent of tenant exposure. */
public record CentralCatalogPageResponse(
        List<Record> items, int page, int size, long totalItems, int totalPages) {
    public enum Kind { ALL, CVE, OTHER }
    public enum Status { ALL, ACTIVE, WITHDRAWN }
    public record Record(UUID id, String externalId, Kind kind, Status status,
                         String title, String description, String severity,
                         Double cvssScore, Double epssScore, boolean inKev,
                         Instant publishedAt, Instant lastModifiedAt, List<String> sourceSystems) {}
}
