package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

class IntelligenceSourceCapabilitiesTest {
    @Test
    void everyDisplayedSourceHasAnExplicitAcquisitionShape() {
        assertEquals(Set.of("NVD", "EUVD", "JVN", "GHSA", "KEV", "OSV", "EPSS",
                        "CSAF_MICROSOFT", "CSAF_REDHAT", "ADVISORY"),
                IntelligenceSourceCapabilities.ALL.stream().map(IntelligenceSourceCapabilities.Capability::source)
                        .collect(Collectors.toSet()));
        assertEquals(10, IntelligenceSourceCapabilities.ALL.size());
        assertTrue(IntelligenceSourceCapabilities.ALL.stream().allMatch(capability ->
                capability.evidenceRole() != null && capability.acquisitionScope() != null));
        assertTrue(IntelligenceSourceCapabilities.ALL.stream().allMatch(capability ->
                capability.tenantPolicySelectable() == IntelligenceSourceRegistry.SOURCES.contains(
                        IntelligenceSourceRegistry.setting(capability.source()))));
        assertThrows(IllegalArgumentException.class, () -> IntelligenceSourceCapabilities.require("UNREVIEWED_SOURCE"));
    }

    @Test
    void inventoryScopedOsvIsNotMisrepresentedAsGeneralCatalogPolicySource() {
        var osv = IntelligenceSourceCapabilities.require("OSV");
        assertEquals("INVENTORY_SCOPED_QUERY", osv.acquisitionScope());
        assertFalse(osv.tenantPolicySelectable());
        assertEquals("KNOWN_CVE_BATCH", IntelligenceSourceCapabilities.require("EPSS").acquisitionScope());
        assertTrue(IntelligenceSourceCapabilities.require("NVD").tenantPolicySelectable());
    }

    @Test
    void legacyJvnEvidenceNamesHonorTheSameTenantPreference() {
        for (String evidence : Set.of("jvn", "JVNDB", "japan-vulndb", " Japan_VulnDB ")) {
            assertEquals("jvn", IntelligenceSourceRegistry.setting(evidence));
            assertTrue(IntelligenceSourceRegistry.enabled(evidence, Set.of("jvn")));
            assertFalse(IntelligenceSourceRegistry.enabled(evidence, Set.of("nvd")));
        }
    }
}
