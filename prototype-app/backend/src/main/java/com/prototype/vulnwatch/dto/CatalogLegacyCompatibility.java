package com.prototype.vulnwatch.dto;

import java.util.List;

/** Read-only migration diagnostic; no policy is created or activated. */
public record CatalogLegacyCompatibility(List<String> enabledSources, List<Gap> gaps) {
    public record Gap(String source, List<String> fields, String reason, String canonicalSource) {}
}
