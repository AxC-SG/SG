package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OpenAiClient;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignDetailResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignFindingRowResponse;
import com.prototype.vulnwatch.dto.CampaignDtos.CampaignVulnerabilityResponse;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CampaignAiService {

    private static final String SYSTEM_PROMPT =
            "You are a security operations analyst. Use only the supplied campaign facts. "
                    + "Do not invent campaign state, ownership, or vulnerability identifiers.";

    private final CampaignService campaignService;
    private final OpenAiClient openAiClient;
    private final ObjectMapper objectMapper;
    private final int maxRequestsPerMinute;
    private final Map<UUID, RequestWindow> requestWindows = new ConcurrentHashMap<>();

    public CampaignAiService(
            CampaignService campaignService,
            OpenAiClient openAiClient,
            ObjectMapper objectMapper,
            @Value("${app.campaign-ai.max-requests-per-minute:10}") int maxRequestsPerMinute
    ) {
        this.campaignService = campaignService;
        this.openAiClient = openAiClient;
        this.objectMapper = objectMapper;
        this.maxRequestsPerMinute = Math.max(1, maxRequestsPerMinute);
    }

    public CampaignAiResponse insights(Tenant tenant, UUID campaignId) {
        checkAvailableAndRateLimit(tenant);
        CampaignDetailResponse detail = campaignService.getDetail(tenant, campaignId);
        String text = openAiClient.chat(
                SYSTEM_PROMPT,
                insightsPrompt(detail),
                new OpenAiClient.AiCallOptions(null, 0.55, 520, false)
        );
        if (text == null || text.isBlank()) {
            throw unavailable();
        }
        return new CampaignAiResponse(text.trim(), null, Instant.now());
    }

    public CampaignAiResponse advisories(Tenant tenant, UUID campaignId) {
        checkAvailableAndRateLimit(tenant);
        CampaignDetailResponse detail = campaignService.getDetail(tenant, campaignId);
        String raw = openAiClient.chat(
                SYSTEM_PROMPT,
                advisoriesPrompt(detail),
                new OpenAiClient.AiCallOptions(null, 0.3, 800, true)
        );
        if (raw == null || raw.isBlank()) {
            throw unavailable();
        }
        try {
            Map<String, List<CampaignAdvisory>> wrapper = objectMapper.readValue(
                    raw, new TypeReference<Map<String, List<CampaignAdvisory>>>() {});
            List<CampaignAdvisory> items = wrapper.getOrDefault("advisories", List.of());
            if (items.isEmpty()) {
                throw unavailable();
            }
            return new CampaignAiResponse(null, items.stream().limit(5).toList(), Instant.now());
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw unavailable();
        }
    }

    private void checkAvailableAndRateLimit(Tenant tenant) {
        if (!openAiClient.isAvailable()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Campaign AI is not configured");
        }
        UUID tenantId = tenant.getId();
        long minute = Instant.now().getEpochSecond() / 60;
        RequestWindow updated = requestWindows.compute(tenantId, (ignored, current) -> {
            if (current == null || current.minute() != minute) {
                return new RequestWindow(minute, 1);
            }
            return new RequestWindow(minute, current.count() + 1);
        });
        if (updated.count() > maxRequestsPerMinute) {
            throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS, "Campaign AI request limit exceeded");
        }
    }

    private String insightsPrompt(CampaignDetailResponse detail) {
        var summary = detail.summary();
        long overdue = detail.findings().stream().filter(this::isOverdue).count();
        String teams = detail.findings().stream()
                .collect(java.util.stream.Collectors.groupingBy(
                        CampaignAiService::ownerLabel,
                        java.util.stream.Collectors.counting()))
                .entrySet().stream()
                .map(entry -> entry.getKey() + ": " + entry.getValue() + " findings")
                .sorted()
                .collect(java.util.stream.Collectors.joining("; "));
        return """
                Generate exactly four concise bullet points, each beginning with "- ".
                Cover remediation velocity, stalled ownership, vulnerability impact, and the immediate leadership action.

                Campaign: %s
                Status: %s
                CVEs: %s
                Due: %s
                Progress: %d%% (%d of %d remediated)
                Overdue findings: %d
                Assets: %d
                Exceptions: %d
                Team ownership: %s
                """.formatted(
                summary.name(),
                summary.status(),
                String.join(", ", summary.cveIds()),
                summary.dueAt(),
                summary.completionPercent(),
                summary.remediatedCount(),
                summary.totalFindings(),
                overdue,
                summary.assetCount(),
                summary.exceptionCount(),
                teams.isBlank() ? "No team data" : teams);
    }

    private String advisoriesPrompt(CampaignDetailResponse detail) {
        String vulnerabilities = detail.vulnerabilities().stream()
                .map(this::vulnerabilitySummary)
                .collect(java.util.stream.Collectors.joining(", "));
        return """
                Identify up to five critical advisories relevant to the supplied CVEs.
                Return one JSON object with an "advisories" array. Each item must contain:
                title, cveId, severity, type, publishedDate, and summary.
                Use null for an unknown publishedDate. Do not return markdown.

                Campaign: %s
                Vulnerabilities: %s
                """.formatted(detail.summary().name(), vulnerabilities);
    }

    private String vulnerabilitySummary(CampaignVulnerabilityResponse item) {
        return item.externalId() + "=" + valueOr(item.severity(), "UNKNOWN");
    }

    private boolean isOverdue(CampaignFindingRowResponse finding) {
        return finding.dueAt() != null
                && finding.dueAt().isBefore(Instant.now())
                && ("OPEN".equals(finding.outcome()) || "REOPENED".equals(finding.outcome()));
    }

    private String valueOr(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private ResponseStatusException unavailable() {
        return new ResponseStatusException(HttpStatus.BAD_GATEWAY, "Campaign AI could not generate a response");
    }

    private record RequestWindow(long minute, int count) {
    }

    /** Phase 0B §4.5: team name by stable team ID when canonical, else Unowned/Conflict/Pending migration. */
    static String ownerLabel(CampaignFindingRowResponse finding) {
        var current = finding.currentOwnership();
        if (current == null || !"CANONICAL".equals(current.authorityState())) return "Pending migration";
        if ("OWNED".equals(current.ownershipStatus()) && current.ownerTeamName() != null) return current.ownerTeamName();
        return "CONFLICT".equals(current.ownershipStatus()) ? "Conflict" : "Unowned";
    }

    public record CampaignAiResponse(
            String text,
            List<CampaignAdvisory> advisories,
            Instant generatedAt
    ) {
    }

    public record CampaignAdvisory(
            String title,
            String cveId,
            String severity,
            String type,
            String publishedDate,
            String summary
    ) {
    }
}
