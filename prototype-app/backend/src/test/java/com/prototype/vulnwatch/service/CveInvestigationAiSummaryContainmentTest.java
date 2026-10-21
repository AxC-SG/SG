package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.*;
import com.prototype.vulnwatch.dto.CveInvestigationSummaryResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;

class CveInvestigationAiSummaryContainmentTest {
    private final CveInvestigationSummaryService deterministic = mock(CveInvestigationSummaryService.class);
    private final OutboundHttpClient outbound = mock(OutboundHttpClient.class);
    private final OutboundPolicyFactory policies = mock(OutboundPolicyFactory.class);
    private final CveInvestigationSummaryResponse summary = new CveInvestigationSummaryResponse(
            Instant.parse("2026-10-21T00:00:00Z"), "Review the recorded deterministic evidence",
            new CveInvestigationSummaryResponse.RiskAnalysis("LOW", 0, "Controlled fixture"),
            new CveInvestigationSummaryResponse.ImpactAnalysis(0, 0, "Unknown", "Unknown", "Unknown"),
            List.of(), List.of("No provider evidence inferred"),
            new CveInvestigationSummaryResponse.MetricsSummary(0, 0, 0, 0, 0, 0), null);

    @ParameterizedTest
    @ValueSource(strings = {"app.openai.api-key", "OPENAI_API_KEY", "openai_API_KEY", "openai.api.key"})
    void everyCredentialAliasRemainsInactiveInDisabledAndDeployedModes(String alias) {
        for (String environment : List.of("test", "production", "preproduction")) {
            var env = new MockEnvironment().withProperty("app.environment", environment)
                    .withProperty("app.openai.enabled", "test".equals(environment) ? "false" : "true")
                    .withProperty(alias, "controlled-inactive-sentinel");
            var gate = new GenerativeAssistancePolicy(env);
            var direct = service(gate);
            when(deterministic.generateSummary("CVE-2026-0001", Map.of())).thenReturn(summary);
            assertSame(summary, direct.generateAiSummary("CVE-2026-0001", Map.of()));
            var rest = mock(RestTemplate.class);
            var shared = new OpenAiClient(rest, new ObjectMapper(), gate);
            assertFalse(shared.isAvailable());
            assertNull(shared.chatCompletion("Controlled", "Controlled"));
            verifyNoInteractions(rest, outbound, policies);
        }
    }

    @Test void providerOutagePreservesDeterministicSubstanceAndItsEvidenceTime() {
        var direct = enabled();
        when(outbound.execute(anyString(), any(), any(), eq(String.class), anyString(), any(), any(), any()))
                .thenThrow(new IllegalStateException("Controlled provider outage"));
        assertSame(summary, direct.generateAiSummary("CVE-2026-0001", Map.of()));
    }

    @Test void malformedProviderResponseDoesNotBecomeEvidenceOrReplaceDeterministicOutput() {
        var direct = enabled();
        when(outbound.execute(anyString(), any(), any(), eq(String.class), anyString(), any(), any(), any()))
                .thenReturn("controlled invalid JSON");
        assertSame(summary, direct.generateAiSummary("CVE-2026-0001", Map.of()));
    }

    private CveInvestigationAiSummaryService enabled() {
        when(deterministic.generateSummary("CVE-2026-0001", Map.of())).thenReturn(summary);
        return service(new GenerativeAssistancePolicy(new MockEnvironment().withProperty("app.environment", "test")
                .withProperty("app.openai.enabled", "true").withProperty("OPENAI_API_KEY", "controlled-test-only")));
    }
    private CveInvestigationAiSummaryService service(GenerativeAssistancePolicy gate) {
        var service = new CveInvestigationAiSummaryService(deterministic, outbound, policies, new ObjectMapper(), gate);
        ReflectionTestUtils.setField(service, "openAiBaseUrl", "https://example.test");
        ReflectionTestUtils.setField(service, "openAiModel", "controlled-fixture");
        return service;
    }
}
