package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OpenAiClient;
import com.prototype.vulnwatch.dto.UpgradeRecommendationRequest;
import com.prototype.vulnwatch.dto.UpgradeRecommendationResponse;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UpgradeRecommendationService {

    private static final String SYSTEM_PROMPT =
        "You are a software security advisor. Give cautious upgrade guidance from the supplied evidence. " +
        "Only recommend an exact version when authoritative release evidence is included in the input. " +
        "Otherwise recommendedVersion must be an empty string and notes must say that the version is not verified. " +
        "Do not supply version numbers or vendor attribution from model memory. " +
        "Respond ONLY with a valid JSON object with exactly these three fields: " +
        "{\"recommendedVersion\": \"<exact version number>\", " +
        "\"upgradeNotes\": \"<concise 1-2 sentence upgrade summary including what the upgrade fixes>\", " +
        "\"urgency\": \"<CRITICAL|HIGH|MEDIUM|LOW>\"}. " +
        "No markdown fences, no extra text.";

    private final OpenAiClient openAiClient;
    private final ObjectMapper objectMapper;

    public UpgradeRecommendationService(OpenAiClient openAiClient, ObjectMapper objectMapper) {
        this.openAiClient = openAiClient;
        this.objectMapper = objectMapper;
    }

    public UpgradeRecommendationResponse getRecommendation(UpgradeRecommendationRequest req) {
        String userPrompt = buildPrompt(req);
        String aiResponse = openAiClient.chatCompletion(SYSTEM_PROMPT, userPrompt);

        if (aiResponse != null && !aiResponse.isBlank()) {
            UpgradeRecommendationResponse parsed = tryParseJson(aiResponse);
            if (parsed != null) return parsed;
        }

        // Fallback when OpenAI is unavailable or response unparseable
        String urgency = (req.eolDate() != null && !req.eolDate().isBlank())
            ? "HIGH"
            : (req.cveIds() != null && !req.cveIds().isEmpty() ? "HIGH" : "MEDIUM");

        return new UpgradeRecommendationResponse(
            "",
            "No upgrade version has been verified. Review the vendor's supported releases and advisories, " +
            "select a release that addresses the recorded vulnerabilities or end-of-life status, and test compatibility before rollout.",
            urgency
        );
    }

    private String buildPrompt(UpgradeRecommendationRequest req) {
        StringBuilder sb = new StringBuilder();
        sb.append("Software: ").append(req.softwareName()).append("\n");
        if (req.vendor() != null && !req.vendor().isBlank()) {
            sb.append("Vendor: ").append(req.vendor()).append("\n");
        }
        if (req.currentVersion() != null && !req.currentVersion().isBlank()) {
            sb.append("Current version: ").append(req.currentVersion()).append("\n");
        }
        if (req.eolDate() != null && !req.eolDate().isBlank()) {
            sb.append("EOL date: ").append(req.eolDate()).append(" (reached end of life)\n");
        }
        List<String> cveIds = req.cveIds();
        if (cveIds != null && !cveIds.isEmpty()) {
            sb.append("Known CVEs: ").append(String.join(", ", cveIds)).append("\n");
        }
        sb.append("\nNo verified release-version evidence is supplied. Return an empty recommendedVersion and cautious upgrade notes as JSON.");
        return sb.toString();
    }

    private UpgradeRecommendationResponse tryParseJson(String raw) {
        try {
            String json = raw.replaceAll("```json\\s*", "").replaceAll("```\\s*", "").trim();
            JsonNode node = objectMapper.readTree(json);
            String recommendedVersion = node.path("recommendedVersion").asText(null);
            String upgradeNotes = node.path("upgradeNotes").asText(null);
            String urgency = node.path("urgency").asText("MEDIUM");
            if (recommendedVersion == null || upgradeNotes == null) return null;
            return new UpgradeRecommendationResponse(recommendedVersion, upgradeNotes, urgency);
        } catch (Exception e) {
            return null;
        }
    }
}
