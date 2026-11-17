package com.prototype.vulnwatch.service;

import java.util.List;

/** Acquisition shape is not historical coverage proof. Keep signal and inventory-scoped feeds distinct. */
public final class IntelligenceSourceCapabilities {
    public record Capability(String source, String evidenceRole, String acquisitionScope,
                             boolean tenantPolicySelectable) {}

    public static final List<Capability> ALL = List.of(
            new Capability("NVD", "VULNERABILITY", "FILTERED_PAGINATED_API", true),
            new Capability("EUVD", "VULNERABILITY", "BOUNDED_PAGINATED_API", true),
            new Capability("JVN", "VULNERABILITY", "BOUNDED_PAGINATED_API", true),
            new Capability("GHSA", "ADVISORY", "FILTERED_PAGINATED_API", true),
            new Capability("KEV", "EXPLOITATION_SIGNAL", "CURRENT_FEED", true),
            new Capability("OSV", "ADVISORY", "INVENTORY_SCOPED_QUERY", false),
            new Capability("EPSS", "PROBABILITY_SIGNAL", "KNOWN_CVE_BATCH", true),
            new Capability("CSAF_MICROSOFT", "VENDOR_ADVISORY", "DOCUMENT_DISCOVERY", true),
            new Capability("CSAF_REDHAT", "VENDOR_ADVISORY", "DOCUMENT_DISCOVERY", true),
            new Capability("ADVISORY", "MANUAL_ADVISORY", "MANUAL_SUBMISSION", true)
    );

    private IntelligenceSourceCapabilities() {}

    public static Capability require(String source) {
        return ALL.stream().filter(capability -> capability.source().equals(source)).findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Unknown platform intelligence source"));
    }
}
