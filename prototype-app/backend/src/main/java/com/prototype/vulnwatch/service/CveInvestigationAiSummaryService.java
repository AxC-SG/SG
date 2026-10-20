package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureContext;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.dto.CveInvestigationSummaryRequest;
import com.prototype.vulnwatch.dto.CveInvestigationSummaryResponse;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import com.prototype.vulnwatch.util.LogUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;

@Service
public class CveInvestigationAiSummaryService {

    private static final Logger LOG = LoggerFactory.getLogger(CveInvestigationAiSummaryService.class);

    private static final String SYSTEM_PROMPT = """
            # CVE Investigation Executive Summary Generator

            You are an elite cybersecurity analyst generating an executive-grade investigation
            summary for a CVE that has completed the full investigation runbook. Your output is
            read by CISOs, security leadership, and audit teams — so it must be accurate,
            actionable, and defensible.

            ## ROLE & MISSION

            Produce a comprehensive Executive Summary Report that synthesizes findings from ALL
            investigation phases into a single authoritative document. The summary must answer
            four questions decisively:
            1. What is the actual, org-specific risk from this CVE?
            2. What did the investigation discover?
            3. What must the organization do, in what order, and by when?
            4. What evidence supports every claim?

            ## ANALYSIS INSTRUCTIONS

            Before writing, perform this internal reasoning (do not output the reasoning):

            1. Compute the true exposure. Start with total_assets_matched, subtract
               confirmed_false_positives, flag EoL assets for special handling.
            2. Compute a risk score on a 0-100 scale:
               - Base: CVSS score x 10
               - +5 if in CISA KEV
               - +5 if EPSS >= 0.5 or PoC publicly available
               - +5 if any external-facing asset impacted
               - +3 if any EoL software involved
               - +3 if no patch available
               - Clamp to 0-100, label: 0-39 LOW, 40-69 MEDIUM, 70-84 HIGH, 85+ CRITICAL
            3. Determine remediation urgency. KEV + overdue = IMMEDIATE. KEV within window =
               URGENT. High CVSS without KEV = STANDARD. Low + internal = ROUTINE.
            4. Order remediation steps: Patch > Upgrade > Migrate > Compensating Control > Accept Risk.
               Always prioritize external-facing assets.
            5. Identify evidence gaps — anything inferred rather than read from input.

            ## OUTPUT FORMAT

            Produce the summary in Markdown following this exact structure:

            ---

            # CVE Investigation Summary — {cve_id}

            **Generated:** {current_timestamp}
            **Analyst:** {analyst_name}
            **Status:** {investigation_status}
            **CVSS:** {cvss_score} · **Severity:** {severity} · **Risk Score:** {computed_risk_score}/100

            ## Executive Summary

            A 2-3 sentence plain-English statement a CISO can read in 15 seconds. Include:
            (a) how bad it is for THIS organization, (b) how many assets are impacted after
            false-positive filtering, (c) whether there is a clean path to fix it. Lead with the
            exposure number. No filler phrases.

            ## Impact Analysis

            **Organizational Risk: {risk_level} ({risk_score}/100)**

            One paragraph explaining WHY this risk level applies, drawing on the specific
            combination of CVSS, KEV status, external-facing exposure, EoL presence, patch
            availability, and EPSS. Every risk factor must be traceable to the input data.

            ## Scope of Exposure

            - **True positives:** {true_positive_count} assets confirmed vulnerable
            - **False positives cleared:** {fp_count}
            - **External-facing:** {ext_count} — highest priority cohort
            - **End-of-life software instances:** {eol_count}
            - **OS distribution:** brief summary from assets_by_os

            ### Affected Software Inventory

            Table with exactly these 4 columns: Software | Version | Asset Count | Solution
            One row per unique software + version combination. Keep values concise.

            ## Remediation Plan

            Numbered, prioritized, sequenced plan. Each step:
            - **Action** (concrete verb phrase)
            - **Rationale** (why this step, why this order)
            - **Owner** (role)
            - **Timeframe** (Immediate 24-48h / Short-term 1-2 weeks / Medium-term 30-90 days)
            - **Assets in scope** (how many, which cohort)

            ## Metrics Summary

            | Total Matched | True Positives | False Positives | External Facing | Unpatched Vulnerable | EoL Count |
            |--|--|--|--|--|--|
            | {n} | {n} | {n} | {n} | {n} | {n} |

            ## Evidence & Source Quality

            List 3-6 key sources cited (vendor advisories, KEV catalog, NVD, analyst URLs).
            Mark each: OFFICIAL / HIGH / MEDIUM / LOW credibility.
            Note any evidence gaps explicitly.

            ## Confidence & Limitations

            - **Confidence:** {0.0-1.0} with one-line rationale
            - **What reduces confidence:** list factors honestly

            ---

            ## CRITICAL RULES

            - DO NOT invent numbers. Every count, percentage, date must come from the input.
            - DO NOT soften the risk language when the data warrants urgency.
            - DO NOT use phrases like "comprehensive," "robust," "holistic," "cutting-edge".
            - DO cite the specific investigation phase that produced each finding.
            - DO flag contradictions in the input rather than silently reconciling them.
            - DO output ONLY the Markdown report. No preamble, no meta-commentary.
            - DO keep the entire report under 600 words unless data genuinely requires more.
            - IF a field is missing or null, write "Not captured in investigation".
            """;

    private final CveInvestigationSummaryService deterministicSummaryService;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;
    private final GenerativeAssistancePolicy generativeAssistancePolicy;

    @Value("${app.openai.base-url:https://api.openai.com/v1}")
    private String openAiBaseUrl;

    @Value("${app.openai.model:gpt-4o-mini}")
    private String openAiModel;

    @Value("${app.openai.min-request-interval-ms:0}")
    private long minRequestIntervalMs;

    @Value("${app.openai.max-retries:2}")
    private int maxRetries;

    @Value("${app.openai.retry-base-backoff-ms:1500}")
    private long retryBaseBackoffMs;

    @Value("${app.openai.max-output-tokens:2400}")
    private int maxOutputTokens;

    public CveInvestigationAiSummaryService(
            CveInvestigationSummaryService deterministicSummaryService,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper,
            GenerativeAssistancePolicy generativeAssistancePolicy
    ) {
        this.deterministicSummaryService = deterministicSummaryService;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
        this.generativeAssistancePolicy = generativeAssistancePolicy;
    }

    public CveInvestigationSummaryResponse generateAiSummary(
            String cveId,
            Map<String, Object> payload
    ) {
        CveInvestigationSummaryResponse deterministicSummary = deterministicSummaryService.generateSummary(cveId, payload);
        String apiKey = generativeAssistancePolicy.configuredApiKey();
        if (apiKey == null || apiKey.isBlank()) {
            return normalizeGeneratedAt(deterministicSummary);
        }

        String requestBody = buildRequestBody(cveId, payload, deterministicSummary);
        String rawResponse;
        try {
            rawResponse = executeOpenAiRequest(apiKey, requestBody);
        } catch (RuntimeException ex) {
            LOG.warn("Generative summary unavailable for {}; returning deterministic assessment.", LogUtil.safe(cveId));
            return normalizeGeneratedAt(deterministicSummary);
        }
        String markdown = extractMarkdownText(rawResponse);

        if (markdown == null || markdown.isBlank()) {
            LOG.warn("OpenAI returned empty markdown for {}. Falling back to deterministic summary.", LogUtil.safe(cveId));
            return normalizeGeneratedAt(deterministicSummary);
        }

        return new CveInvestigationSummaryResponse(
                Instant.now(),
                deterministicSummary.executiveSummary(),
                deterministicSummary.riskAnalysis(),
                deterministicSummary.impactAnalysis(),
                deterministicSummary.remediationPlan(),
                deterministicSummary.keyFindings(),
                deterministicSummary.metrics(),
                markdown
        );
    }

    private String buildRequestBody(
            String cveId,
            Map<String, Object> payload,
            CveInvestigationSummaryResponse deterministicSummary
    ) {
        try {
            String userPrompt = buildUserPrompt(cveId, payload, deterministicSummary);
            Map<String, Object> request = new LinkedHashMap<>();
            request.put("model", openAiModel);
            request.put("max_output_tokens", maxOutputTokens);
            request.put("input", List.of(
                    Map.of(
                            "role", "system",
                            "content", List.of(Map.of("type", "input_text", "text", SYSTEM_PROMPT))
                    ),
                    Map.of(
                            "role", "user",
                            "content", List.of(Map.of("type", "input_text", "text", userPrompt))
                    )
            ));
            // Plain text output — not JSON schema
            request.put("text", Map.of("format", Map.of("type", "text")));
            return objectMapper.writeValueAsString(request);
        } catch (JsonProcessingException error) {
            throw new IllegalStateException("Unable to build OpenAI summary request.", error);
        }
    }

    private String buildUserPrompt(
            String cveId,
            Map<String, Object> rawPayload,
            CveInvestigationSummaryResponse deterministicSummary
    ) throws JsonProcessingException {
        // Transform the raw payload into the structured format the prompt expects
        Map<String, Object> structuredPayload = buildStructuredPayload(cveId, rawPayload, deterministicSummary);
        return "Generate the Executive Summary Report for this CVE investigation.\n\nInvestigation data:\n"
                + objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(structuredPayload);
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> buildStructuredPayload(
            String cveId,
            Map<String, Object> raw,
            CveInvestigationSummaryResponse det
    ) {
        // --- cve_metadata ---
        Map<String, Object> summaryRaw = raw.get("summary") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
        Map<String, Object> kevStatus = new LinkedHashMap<>();
        kevStatus.put("in_kev_catalog", Boolean.TRUE.equals(summaryRaw.get("inKev")));
        kevStatus.put("kev_added_date", summaryRaw.getOrDefault("kevDateAdded", null));
        kevStatus.put("kev_due_date", summaryRaw.getOrDefault("kevDueDate", null));

        Map<String, Object> cveMetadata = new LinkedHashMap<>();
        cveMetadata.put("cve_id", cveId);
        cveMetadata.put("description", summaryRaw.getOrDefault("description", "Not captured"));
        cveMetadata.put("cvss_score", summaryRaw.getOrDefault("cvssScore", null));
        cveMetadata.put("severity", summaryRaw.getOrDefault("severity", "UNKNOWN"));
        cveMetadata.put("epss_score", summaryRaw.getOrDefault("epssScore", null));
        cveMetadata.put("kev_status", kevStatus);
        cveMetadata.put("exploitation_status", Boolean.TRUE.equals(summaryRaw.get("exploitAvailable")) ? "POC_AVAILABLE" : "UNKNOWN");

        // --- investigation_metadata ---
        Map<String, Object> invRaw = raw.get("investigation") instanceof Map<?, ?> m ? (Map<String, Object>) m : Map.of();
        Map<String, Object> investigationMeta = new LinkedHashMap<>();
        investigationMeta.put("analyst", invRaw.getOrDefault("leadAnalyst", "Not captured"));
        investigationMeta.put("status", "COMPLETE");

        // --- asset_inventory_results ---
        List<Map<String, Object>> affectedAssets = raw.get("affectedAssets") instanceof List<?> l
                ? l.stream().filter(e -> e instanceof Map<?, ?>).map(e -> (Map<String, Object>) e).collect(Collectors.toList())
                : List.of();

        long externalFacingCount = affectedAssets.stream().filter(a -> Boolean.TRUE.equals(a.get("externalFacing"))).count();

        // Build matched software summary
        Map<String, Map<String, Object>> swMap = new LinkedHashMap<>();
        for (Map<String, Object> asset : affectedAssets) {
            if (asset.get("matchedSoftware") instanceof List<?> msList) {
                for (Object msObj : msList) {
                    if (msObj instanceof Map<?, ?> ms) {
                        String sw = String.valueOf(ms.get("software"));
                        String ver = ms.get("version") != null ? String.valueOf(ms.get("version")) : "";
                        String key = sw + "@" + ver;
                        swMap.computeIfAbsent(key, k -> {
                            Map<String, Object> entry = new LinkedHashMap<>();
                            entry.put("software", sw);
                            entry.put("version", ver);
                            entry.put("asset_count", 0);
                            entry.put("external_facing_count", 0);
                            return entry;
                        });
                        Map<String, Object> entry = swMap.get(key);
                        entry.put("asset_count", ((Number) entry.get("asset_count")).intValue() + 1);
                        if (Boolean.TRUE.equals(asset.get("externalFacing"))) {
                            entry.put("external_facing_count", ((Number) entry.get("external_facing_count")).intValue() + 1);
                        }
                    }
                }
            }
        }

        List<Map<String, Object>> externalFacingAssets = affectedAssets.stream()
                .filter(a -> Boolean.TRUE.equals(a.get("externalFacing")))
                .map(a -> {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("hostname", a.getOrDefault("hostname", "unknown"));
                    entry.put("ip", a.getOrDefault("ipAddress", "—"));
                    entry.put("os", a.getOrDefault("os", "—"));
                    entry.put("owner", a.getOrDefault("owner", "—"));
                    entry.put("environment", a.getOrDefault("environment", "—"));
                    return entry;
                })
                .collect(Collectors.toList());

        // Compute OS breakdown from affectedAssets
        Map<String, Long> osCounts = new LinkedHashMap<>();
        for (Map<String, Object> asset : affectedAssets) {
            String os = asset.get("os") instanceof String s && !s.isBlank() ? s : "Unknown";
            osCounts.merge(os, 1L, Long::sum);
        }
        List<Map<String, Object>> assetsByOs = osCounts.entrySet().stream()
                .map(e -> {
                    Map<String, Object> entry = new LinkedHashMap<>();
                    entry.put("os", e.getKey());
                    entry.put("count", e.getValue());
                    return entry;
                })
                .collect(Collectors.toList());

        Map<String, Object> assetInventory = new LinkedHashMap<>();
        assetInventory.put("total_assets_matched", affectedAssets.size());
        assetInventory.put("external_facing_count", externalFacingCount);
        assetInventory.put("internal_count", affectedAssets.size() - externalFacingCount);
        assetInventory.put("assets_by_os", assetsByOs);
        assetInventory.put("matched_software", List.copyOf(swMap.values()));
        assetInventory.put("external_facing_assets", externalFacingAssets);

        // --- false_positive_results ---
        List<Map<String, Object>> fpRows = raw.get("falsePositiveRows") instanceof List<?> l
                ? l.stream().filter(e -> e instanceof Map<?, ?>).map(e -> (Map<String, Object>) e).collect(Collectors.toList())
                : List.of();
        long confirmedFp = fpRows.stream().filter(r -> Boolean.TRUE.equals(r.get("falsePositive"))).count();

        List<Map<String, Object>> fpFindings = fpRows.stream().map(row -> {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("software", row.getOrDefault("software", "unknown"));
            entry.put("version", row.getOrDefault("version", "—"));
            entry.put("is_false_positive", Boolean.TRUE.equals(row.get("falsePositive")));
            entry.put("evidence", row.getOrDefault("vendorGuidance", null));
            entry.put("vendor_advisory", row.getOrDefault("vendorAdvisory", null));
            return entry;
        }).collect(Collectors.toList());

        Map<String, Object> fpResults = new LinkedHashMap<>();
        fpResults.put("software_entries_checked", fpRows.size());
        fpResults.put("confirmed_false_positives", confirmedFp);
        fpResults.put("true_positives", affectedAssets.size() - confirmedFp);
        fpResults.put("per_software_findings", fpFindings);

        // --- eol_analysis_results ---
        List<Map<String, Object>> eolRows = raw.get("eolRows") instanceof List<?> l
                ? l.stream().filter(e -> e instanceof Map<?, ?>).map(e -> (Map<String, Object>) e).collect(Collectors.toList())
                : List.of();
        long eolCount = eolRows.stream()
                .filter(r -> r.get("lifecycle") instanceof String lc
                        && !lc.equalsIgnoreCase("supported")
                        && !lc.equalsIgnoreCase("unknown"))
                .count();

        List<Map<String, Object>> eolLifecycle = eolRows.stream().map(row -> {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("software", row.getOrDefault("software", "unknown"));
            entry.put("vendor", row.getOrDefault("vendor", "—"));
            entry.put("version", row.getOrDefault("version", "—"));
            entry.put("lifecycle_status", row.getOrDefault("lifecycle", "UNKNOWN"));
            entry.put("end_of_support_date", row.getOrDefault("endOfSupport", null));
            entry.put("end_of_life_date", row.getOrDefault("endOfLife", null));
            entry.put("recommended_upgrade_target", row.getOrDefault("recommendedUpgrade", null));
            return entry;
        }).collect(Collectors.toList());

        Map<String, Object> eolResults = new LinkedHashMap<>();
        eolResults.put("eol_software_count", eolCount);
        eolResults.put("supported_software_count", eolRows.size() - eolCount);
        eolResults.put("per_software_lifecycle", eolLifecycle);

        // --- solutions_results ---
        List<Map<String, Object>> solutionRowsRaw = raw.get("solutionRows") instanceof List<?> l
                ? l.stream().filter(e -> e instanceof Map<?, ?>).map(e -> (Map<String, Object>) e).collect(Collectors.toList())
                : List.of();

        List<Map<String, Object>> solutionsList = solutionRowsRaw.stream().map(row -> {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("software", row.getOrDefault("software", "unknown"));
            entry.put("version", row.getOrDefault("version", "—"));
            entry.put("vendor", row.getOrDefault("vendor", "—"));
            entry.put("impacted_assets", row.getOrDefault("impactedAssets", 0));
            entry.put("solution_type", row.getOrDefault("solutionType", "PATCH"));
            entry.put("solution_detail", row.getOrDefault("solutionDetail", "Not captured"));
            entry.put("target_version", row.getOrDefault("targetVersion", null));
            return entry;
        }).collect(Collectors.toList());

        Map<String, Object> solutionsResults = new LinkedHashMap<>();
        solutionsResults.put("per_software_solutions", solutionsList);

        // --- created_findings ---
        List<Map<String, Object>> createdFindings = raw.get("createdFindings") instanceof List<?> l
                ? l.stream().filter(e -> e instanceof Map<?, ?>).map(e -> (Map<String, Object>) e).collect(Collectors.toList())
                : List.of();

        List<Map<String, Object>> createdFindingsList = createdFindings.stream().map(row -> {
            Map<String, Object> entry = new LinkedHashMap<>();
            entry.put("finding_id", row.getOrDefault("displayId", "unknown"));
            entry.put("asset_name", row.getOrDefault("assetName", "—"));
            entry.put("asset_identifier", row.getOrDefault("assetIdentifier", "—"));
            entry.put("software", row.getOrDefault("packageName", "unknown"));
            entry.put("version", row.getOrDefault("packageVersion", "—"));
            entry.put("severity", row.getOrDefault("severity", "UNKNOWN"));
            entry.put("status", row.getOrDefault("status", "UNKNOWN"));
            entry.put("decision_state", row.getOrDefault("decisionState", "UNKNOWN"));
            entry.put("assigned_to", row.getOrDefault("assignedTo", null));
            entry.put("due_date", row.getOrDefault("dueAt", null));
            entry.put("incident_id", row.getOrDefault("incidentId", null));
            return entry;
        }).collect(Collectors.toList());

        Map<String, Object> createdFindingsResults = new LinkedHashMap<>();
        createdFindingsResults.put("created_count", createdFindingsList.size());
        createdFindingsResults.put("per_finding", createdFindingsList);

        // --- patch_compliance ---
        Map<String, Object> patchCompliance = new LinkedHashMap<>();
        patchCompliance.put("patch_available", Boolean.TRUE.equals(summaryRaw.get("patchAvailable")));
        patchCompliance.put("unpatched_vulnerable_assets", det.metrics().unpatchedVulnerable());

        // Assemble final payload
        Map<String, Object> structured = new LinkedHashMap<>();
        structured.put("cve_metadata", cveMetadata);
        structured.put("investigation_metadata", investigationMeta);
        structured.put("asset_inventory_results", assetInventory);
        structured.put("false_positive_results", fpResults);
        structured.put("eol_analysis_results", eolResults);
        structured.put("solutions_results", solutionsResults);
        structured.put("created_findings", createdFindingsResults);
        structured.put("patch_compliance", patchCompliance);
        return structured;
    }

    private String executeOpenAiRequest(String apiKey, String requestBody) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.setBearerAuth(apiKey);

        return outboundHttpClient.execute(
                openAiBaseUrl + "/responses",
                HttpMethod.POST,
                new HttpEntity<>(requestBody, headers),
                String.class,
                "OpenAI investigation summary",
                outboundPolicy(),
                this::classifyFailure,
                response -> {
                    String body = response.getBody();
                    if (body == null || body.isBlank()) {
                        throw new IllegalStateException("OpenAI response body is empty.");
                    }
                    return body;
                }
        );
    }

    private String extractMarkdownText(String rawResponse) {
        try {
            JsonNode root = objectMapper.readTree(rawResponse);
            // Try output_text first (plain text format)
            JsonNode outputText = root.path("output_text");
            if (outputText.isTextual() && !outputText.asText().isBlank()) {
                return outputText.asText().trim();
            }
            // Walk output array for text content
            JsonNode outputArray = root.path("output");
            if (outputArray.isArray()) {
                for (JsonNode item : outputArray) {
                    JsonNode content = item.path("content");
                    if (content.isArray()) {
                        for (JsonNode block : content) {
                            if ("output_text".equals(block.path("type").asText())
                                    || "text".equals(block.path("type").asText())) {
                                String text = block.path("text").asText(null);
                                if (text != null && !text.isBlank()) {
                                    return text.trim();
                                }
                            }
                        }
                    }
                    // item itself might have a text field
                    if (item.path("text").isTextual()) {
                        return item.path("text").asText().trim();
                    }
                }
            }
            return null;
        } catch (Exception e) {
            LOG.warn("Failed to extract markdown text from OpenAI response: {}", e.getMessage());
            return null;
        }
    }

    private CveInvestigationSummaryResponse normalizeGeneratedAt(CveInvestigationSummaryResponse summary) {
        if (summary.generatedAt() != null) {
            return summary;
        }
        return new CveInvestigationSummaryResponse(
                Instant.now(),
                summary.executiveSummary(),
                summary.riskAnalysis(),
                summary.impactAnalysis(),
                summary.remediationPlan(),
                summary.keyFindings(),
                summary.metrics(),
                null
        );
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("openai", minRequestIntervalMs, maxRetries, retryBaseBackoffMs);
    }

    private OutboundFailureDecision<RuntimeException> classifyFailure(OutboundFailureContext context) {
        RuntimeException exception = new IllegalStateException(
                "OpenAI summary request failed: " + context.error().getMessage(), context.error());
        if (context.isRetryableByDefault()) {
            return OutboundFailureDecision.retry(context.retryAfterDelayMs(), exception);
        }
        return OutboundFailureDecision.fail(exception);
    }
}
