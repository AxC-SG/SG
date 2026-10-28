package com.prototype.vulnwatch.service.patch;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class PatchHelpersTest {

    @Test
    void shortHostnameStripsDomainAndNetbiosPrefix() {
        assertThat(PatchIngestionService.shortHostname("WS-01.corp.example.com")).isEqualTo("ws-01");
        assertThat(PatchIngestionService.shortHostname("CORP\\WS-02")).isEqualTo("ws-02");
        assertThat(PatchIngestionService.shortHostname("  ")).isNull();
    }

    @Test
    void kbNumbersNormalizeToDigits() {
        assertThat(PatchIngestionService.normalizeKb("KB5034441")).isEqualTo("5034441");
        assertThat(PatchIngestionService.normalizeKb("5034441")).isEqualTo("5034441");
        assertThat(PatchIngestionService.normalizeKb("KB12")).isNull();
        assertThat(PatchIngestionService.normalizeKb("KB5034441; drop table")).isNull();
    }

    @Test
    void highestSeverityWins() {
        assertThat(PatchIngestionService.maxSeverity("MEDIUM", "critical")).isEqualTo("CRITICAL");
        assertThat(PatchIngestionService.maxSeverity("HIGH", "LOW")).isEqualTo("HIGH");
        assertThat(PatchIngestionService.maxSeverity(null, "bogus")).isNull();
    }

    @Test
    void onlyHttpsLinksAreKept() {
        assertThat(PatchIngestionService.httpsUrlOrNull("https://support.microsoft.com/kb/5034441")).isNotNull();
        assertThat(PatchIngestionService.httpsUrlOrNull("javascript:alert(1)")).isNull();
        assertThat(PatchIngestionService.httpsUrlOrNull("http://example.com")).isNull();
    }

    @Test
    void sanitizeRedactsEchoedSecrets() {
        String cleaned = PatchConnectorService.sanitize(
                "401 Bearer eyJabc.def {\"client_secret\":\"s3cr3t\"} password=hunter2");
        assertThat(cleaned).doesNotContain("eyJabc", "s3cr3t", "hunter2");
    }
}
