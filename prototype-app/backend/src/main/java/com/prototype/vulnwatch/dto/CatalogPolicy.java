package com.prototype.vulnwatch.dto;

import java.util.List;
import java.util.Set;

/** Versioned wire contract. This preview contract does not activate tenant membership. */
public record CatalogPolicy(int version, Set<String> sources, boolean includeNonCve,
                            ScoreResolution scoreResolution, Rule rule) {
    public enum ScoreResolution { MAX_ALLOWED_OBSERVATION_V1, MAX_ALLOWED_CVSS_V3_1, MAX_ALLOWED_CVSS_V4_0 }
    public enum Field { PUBLICATION_YEAR, CVSS, EPSS, CISA_KEV }
    public enum Op { ALL, ANY, SOURCE_PRESENT, GT, GTE, LT, LTE, EQ, MISSING }
    public record Rule(Op op, Field field, Double number, Boolean flag, List<Rule> children) {}
}
