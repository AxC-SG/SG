package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.DefaultResourceLoader;

class CbomRulePackageRegistryTest {
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-11-03T00:00:00Z");

    private CbomRulePackageRegistry registry(String index, String overrides) {
        return new CbomRulePackageRegistry(MAPPER, new DefaultResourceLoader(), "classpath:cbom-rules-test/" + index, overrides);
    }

    @Test
    void packagedBaselineKeepsTheLegacyManifestDigestSoExistingAssessmentsStayAuthoritative() {
        var production = new CbomRulePackageRegistry(MAPPER, "classpath:cbom-rules/index.json", "");
        var baseline = production.find("scoutgrid-baseline", "1.0.0").orElseThrow();
        assertThat(baseline.digest()).isEqualTo("sha256:60f075150e63c596d843d7b81c40ba036ef226283d151fe0317b1721fb475c4e");
        assertThat(baseline.stage()).isEqualTo(CbomRulePackageRegistry.Stage.GENERAL);
        assertThat(baseline.mandatoryRuleIds()).contains("CBOM-WEAK-ALGO").doesNotContain("CBOM-CERT-EXPIRING");
        assertThat(baseline.defaults()).containsEntry("minimumRsaBits", 2048);
    }

    @Test
    void resolvesNewestGeneralDefaultAndRolloutTarget() {
        var registry = registry("index.json", "");
        assertThat(registry.newest("test-pack").orElseThrow().version()).isEqualTo("1.3.0");
        assertThat(registry.generalDefault("test-pack", NOW).orElseThrow().version()).isEqualTo("1.2.0");
        assertThat(registry.oldest("test-pack").orElseThrow().version()).isEqualTo("1.0.0");
        assertThat(registry.find("test-pack", "1.0.0").orElseThrow().retired(NOW)).isTrue();
    }

    @Test
    void appliesReleaseStageOverridesAndRejectsUnknownOnes() {
        var registry = registry("index.json", "test-pack@1.3.0=general");
        assertThat(registry.find("test-pack", "1.3.0").orElseThrow().stage()).isEqualTo(CbomRulePackageRegistry.Stage.GENERAL);
        assertThat(registry.generalDefault("test-pack", NOW).orElseThrow().version()).isEqualTo("1.3.0");
        assertThatThrownBy(() -> registry("index.json", "test-pack@9.9.9=CANARY"))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("unknown package");
    }

    @Test
    void lowestCompatibleUpgradeKeepsMandatoryRulesAndParameterBounds() {
        var registry = registry("index.json", "");
        var retired = registry.find("test-pack", "1.0.0").orElseThrow();
        // 1.1.0 drops mandatory rule B; 1.2.0 caps x at 5.
        assertThat(registry.lowestCompatibleUpgrade(retired, Map.of("x", 4), NOW).orElseThrow().version()).isEqualTo("1.2.0");
        assertThat(registry.lowestCompatibleUpgrade(retired, Map.of("x", 8), NOW).orElseThrow().version()).isEqualTo("1.3.0");
        assertThat(registry.lowestCompatibleUpgrade(retired, Map.of("x", 11), NOW)).isEmpty();
        assertThat(registry.lowestCompatibleUpgrade(retired, Map.of("unknown", 1), NOW)).isEmpty();
    }

    @Test
    void rejectsTamperedDigestsAndInsufficientDeprecationNotice() {
        assertThatThrownBy(() -> registry("index-bad-digest.json", ""))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("digest mismatch");
        assertThatThrownBy(() -> registry("index-short-notice.json", ""))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("90 days");
    }

    @Test
    void comparesSemanticVersionsNumerically() {
        assertThat(CbomRulePackageRegistry.compareVersions("1.10.0", "1.9.9")).isPositive();
        assertThat(CbomRulePackageRegistry.compareVersions("2.0.0", "2.0.0")).isZero();
    }
}
