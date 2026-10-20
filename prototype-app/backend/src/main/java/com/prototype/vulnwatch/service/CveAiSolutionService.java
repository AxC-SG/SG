package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.AdvisoryFetchService;
import com.prototype.vulnwatch.client.http.OpenAiClient;
import com.prototype.vulnwatch.client.http.OpenAiClient.AiCallOptions;
import com.prototype.vulnwatch.controller.CveDetailController;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import com.prototype.vulnwatch.util.LogUtil;

@Service
public class CveAiSolutionService {

    private static final Logger LOG = LoggerFactory.getLogger(CveAiSolutionService.class);

    private static final String SOFTWARE_SYSTEM_PROMPT = """
            You are a cybersecurity remediation advisor writing for an enterprise IT operations team.
            Follow the user's instructions exactly. Return direct operational guidance only.
            Keep the final answer to 200 words or fewer.
            """;

    private static final String SYSTEM_PROMPT = """
            You are a senior security engineer writing a highly specific, actionable remediation
            advisory for a vulnerability management dashboard. Every sentence must name the actual
            product, patch ID, KB number, version, asset count, or EOL date drawn directly from
            the supplied CVE context. NEVER write generic sentences like "apply mitigations per
            vendor instructions" or "monitor for vendor updates" — those are useless to the team.
            Instead write instructions like:
              "Deploy KB5034441 to all 47 Windows 10 22H2 endpoints via WSUS before end of day."
              "Block inbound SMTP relay on port 25 at the perimeter firewall until patch is applied."
              "Run 'winver' on a patched host and confirm build 19045.3930 or later."

            Respond with valid JSON matching EXACTLY this schema (no extra keys, no markdown fences):
            {
              "title": "<CVE-ID> Remediation Summary — Your Organization",
              "affected_scope": "<N assets · N software identities · N components>",
              "bottom_line": {
                "severity": "<CRITICAL|HIGH|MEDIUM|LOW>",
                "cvss": "<score>",
                "kev_status": "<Listed in CISA KEV | Not in KEV>",
                "patch_status": "<Patch Available | No Patch Available>",
                "summary": "<1-2 sentences naming the product, attack type, and blast radius in your org>"
              },
              "what_is_happening": {
                "description": "<2-3 sentences: name the vulnerable component, the exact mechanism (e.g. heap overflow in Outlook's URL parser), and why your N assets are at risk>",
                "attack_steps": [
                  "<step naming the specific protocol or component — e.g. 'Attacker sends crafted MIME email to Outlook client'>",
                  "<step describing what the vulnerable code does — e.g. 'Outlook processes the MonikerLink URL via preview pane without user click'>",
                  "<step describing impact — e.g. 'NTLM credential hash leaks to attacker-controlled SMB server'>"
                ],
                "interaction_note": "<zero-click / single-click / requires user to open attachment — be specific>"
              },
              "primary_fix": {
                "action": "<Install / Apply / Upgrade>",
                "patch_id": "<KB number, advisory ID, or package version — from vendor_intelligence in context>",
                "target_version": "<exact build or version from context, e.g. 16.0.17231.20236>",
                "applies_to": "<exact product editions and install types from context>",
                "reboot_required": <true|false>,
                "verification": "<exact CLI command or UI step to confirm — e.g. 'Get-HotFix -Id KB5034441' or 'Help > About shows version 16.0.x'>"
              },
              "timeline": [
                {
                  "window": "Next 24 hours", "color": "red", "label": "Immediate actions",
                  "actions": [
                    "<specific action naming the product and what to disable/block — e.g. 'Disable Outlook preview pane for all N Exchange Online mailboxes via OWA policy'>",
                    "<specific network control — e.g. 'Block outbound SMB (port 445) to untrusted IPs at the perimeter firewall'>"
                  ]
                },
                {
                  "window": "Days 1–7", "color": "amber", "label": "Deploy the patch",
                  "actions": [
                    "<specific patch deployment step naming the KB/package and target system count — e.g. 'Push KB5034441 via WSUS to all N Windows endpoints; prioritise internet-facing systems first'>",
                    "<specific validation step — e.g. 'Confirm build 19045.3930 via endpoint management console; flag non-compliant hosts'>"
                  ]
                },
                {
                  "window": "Days 8–30", "color": "green", "label": "Validate & harden",
                  "actions": [
                    "<specific hardening or compliance action — e.g. 'Enable Attack Surface Reduction rule GUID 92E97FA1... to block Office from spawning child processes'>",
                    "<EOL or upgrade action if relevant — e.g. 'Begin migration of N EOL Windows 10 20H2 hosts to Windows 11 23H2 per upgrade path'>",
                    "<evidence closure step — e.g. 'Update org_cve_records applicability state to FIXED and close investigation ticket'>"
                  ]
                }
              ],
              "compensating_controls": [
                {"control": "<specific control naming the product feature or tool>", "effort": "<Low|Medium|High>", "effectiveness": "<Low|Medium|High>"}
              ],
              "rollback_plan": [
                "<specific rollback step — e.g. 'Use WSUS to uninstall KB5034441 on affected hosts if regression observed'>",
                "<verification step — e.g. 'Re-run baseline scans and confirm no new critical failures before re-patching'>"
              ],
              "lifecycle_warning": {
                "product": "<exact product name from context or null>",
                "eol_date": "<ISO date from context or null>",
                "is_eol": <true|false>,
                "lifecycle_status": "<Active Support|Extended Support|End of Life|null>",
                "upgrade_recommendation": "<specific upgrade path — e.g. 'Upgrade from Windows 10 21H2 to Windows 11 23H2; free in-place upgrade available via Windows Update' or null>"
              },
              "reasoning_trace": [
                "Source triage: <what sources were used and their trust tier>",
                "Asset correlation: <how many assets matched and by what CPE/version>",
                "Patch extraction: <which KB/build was identified and from which source>",
                "Urgency scoring: <why this SLA — KEV, EPSS, PoC, asset count>"
              ],
              "evidence_gaps": "<specific gaps — e.g. 'No EPSS score available; fixed version not confirmed in vendor_intelligence for macOS builds'>",
              "confidence_score": <integer 0-100>,
              "confidence_rationale": "<short phrase explaining the score — e.g. 'KEV-listed with PoC and patch confirmed in MSRC advisory'>"
            }
            Hard rules:
            - SCOPE: The affected_entities list contains ONLY the products with confirmed impact. All recommendations must be scoped exclusively to those products. Do NOT mention products not in the list.
            - If vendor advisory content is provided, extract patch KB numbers, fixed versions, workarounds, and compensating controls from it and use them as the PRIMARY source. Cite the advisory source in your reasoning_trace.
            - If advisory content is absent or incomplete, state the evidence gap. Do not invent patch IDs, versions, source citations, or vendor attribution from model memory. Attribute a claim to MSRC, NVD, or a vendor only when that claim is supported by the supplied evidence.
            - Never output the literal string "null" or "N/A" for patch_id or target_version — if genuinely unknown, omit the field entirely.
            - Every action in timeline.actions must name the specific product, patch ID, or asset count from context.
            - Never use the words "vendor instructions", "monitor for updates", or "additional security measures".
            - compensating_controls: at least 2 entries, each naming a specific product feature or network control relevant to the impacted products.
            - rollback_plan: at least 2 steps, each referencing the specific patch or change being rolled back.
            """;

    private final AdvisoryFetchService advisoryFetchService;
    private final OpenAiClient openAiClient;
    private final ObjectMapper objectMapper;
    private final CveAiSolutionPersistenceService aiSolutionPersistenceService;

    public CveAiSolutionService(
            AdvisoryFetchService advisoryFetchService,
            OpenAiClient openAiClient,
            ObjectMapper objectMapper,
            CveAiSolutionPersistenceService aiSolutionPersistenceService
    ) {
        this.advisoryFetchService = advisoryFetchService;
        this.openAiClient = openAiClient;
        this.objectMapper = objectMapper;
        this.aiSolutionPersistenceService = aiSolutionPersistenceService;
    }

    public CveDetailController.AiSolutionResponse generate(String cveId, Map<String, Object> recommendationContext) {
        String softwarePrompt = stringValue(recommendationContext.get("softwareRecommendationPrompt"));
        if (softwarePrompt != null && !softwarePrompt.isBlank()) {
            return generateSoftwareRecommendation(recommendationContext, softwarePrompt);
        }

        if (!openAiClient.isAvailable()) {
            CveDetailController.AiSolutionResponse response = new CveDetailController.AiSolutionResponse();
            response.success = false;
            response.recommendation = "Generative assistance is disabled or unavailable. Use the deterministic assessment, linked advisories and recorded evidence to plan remediation.";
            return response;
        }

        String userPrompt = buildUserPrompt(cveId, recommendationContext);
        AiCallOptions options = new AiCallOptions(null, 0.2, 3500, true);
        String raw = openAiClient.chat(SYSTEM_PROMPT, userPrompt, options);
        if (raw == null || raw.isBlank()) {
            CveDetailController.AiSolutionResponse response = new CveDetailController.AiSolutionResponse();
            response.success = false;
            response.error = "AI recommendation generation failed. Please check the OpenAI configuration and try again.";
            return response;
        }

        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> parsed = objectMapper.readValue(raw, Map.class);
            try {
                aiSolutionPersistenceService.saveAiSolution(cveId, raw);
            } catch (Exception saveError) {
                LOG.warn("Failed to persist AI solution for {}: {}", LogUtil.safe(cveId), saveError.getMessage());
            }
            CveDetailController.AiSolutionResponse response = new CveDetailController.AiSolutionResponse();
            response.success = true;
            response.data = parsed;
            response.generatedAt = Instant.now();
            return response;
        } catch (Exception parseError) {
            CveDetailController.AiSolutionResponse response = new CveDetailController.AiSolutionResponse();
            response.success = false;
            response.error = "AI returned an unstructured response. Please retry.";
            response.recommendation = raw.trim();
            return response;
        }
    }

    private CveDetailController.AiSolutionResponse generateSoftwareRecommendation(
            Map<String, Object> recommendationContext,
            String softwarePrompt
    ) {
        CveDetailController.AiSolutionResponse response = new CveDetailController.AiSolutionResponse();
        if (!openAiClient.isAvailable()) {
            response.success = false;
            response.recommendation = trimWords(buildSoftwareFallbackRecommendation(recommendationContext), 200);
            return response;
        }

        String raw = openAiClient.chat(
                SOFTWARE_SYSTEM_PROMPT,
                softwarePrompt,
                new AiCallOptions(null, 0.2, 800, false));
        if (raw == null || raw.isBlank()) {
            response.success = false;
            response.recommendation = trimWords(buildSoftwareFallbackRecommendation(recommendationContext), 200);
            return response;
        }
        response.success = true;
        response.recommendation = trimWords(raw.trim(), 200);
        response.generatedAt = Instant.now();
        return response;
    }

    private String buildUserPrompt(String cveId, Map<String, Object> recommendationContext) {
        String advisoryContent = fetchAdvisoryContent(cveId, recommendationContext);
        return "CVE context (affected_entities contains ONLY products with confirmed impact — asset_count > 0; ignore all other products):\n"
                + toJson(recommendationContext)
                + (advisoryContent.isBlank() ? "" :
                "\n\nVENDOR ADVISORY CONTENT (fetched from official advisory pages — use patches, KB numbers, workarounds, and compensating controls found here as the PRIMARY source for your recommendation):\n"
                        + advisoryContent);
    }

    private String fetchAdvisoryContent(String cveId, Map<String, Object> recommendationContext) {
        StringBuilder advisoryBuilder = new StringBuilder();
        Object urlsObj = recommendationContext.get("advisory_urls");
        if (urlsObj instanceof List<?> rawList) {
            List<String> advisoryUrls = rawList.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
            if (!advisoryUrls.isEmpty()) {
                String fetched = advisoryFetchService.fetchAdvisoryContent(advisoryUrls);
                if (!fetched.isBlank()) {
                    advisoryBuilder.append(fetched);
                }
            }
        }
        String msrcData = advisoryFetchService.fetchMsrcPatchInfo(cveId);
        if (!msrcData.isBlank()) {
            advisoryBuilder.append(msrcData);
        }
        return advisoryBuilder.toString().trim();
    }

    private String buildSoftwareFallbackRecommendation(Map<String, Object> recommendationContext) {
        Object softwareObj = recommendationContext.get("software");
        Object vulnObj = recommendationContext.get("vulnerability");
        String softwareName = softwareObj instanceof Map<?, ?> softwareMap ? stringValue(softwareMap.get("name")) : null;
        String softwareVersion = softwareObj instanceof Map<?, ?> softwareMap ? stringValue(softwareMap.get("version")) : null;
        String cveId = vulnObj instanceof Map<?, ?> vulnMap ? stringValue(vulnMap.get("id")) : null;
        String cveSummary = vulnObj instanceof Map<?, ?> vulnMap ? stringValue(vulnMap.get("summary")) : null;
        String affectedAssets = stringValue(recommendationContext.get("affected_assets"));
        String severity = stringValue(recommendationContext.get("severity"));
        return String.join(" ",
                "Review",
                nonBlankJoin(" ", softwareName, softwareVersion),
                "for",
                nonBlankJoin(" ", cveId, cveSummary),
                severity == null ? "" : "Severity " + severity + ".",
                affectedAssets == null ? "" : affectedAssets + " assets are affected.",
                "Apply the vendor fix first, use network or access restrictions if patching is delayed, verify the corrected version, and test rollback on a non-production host before broad rollout.");
    }

    private String toJson(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            return String.valueOf(obj);
        }
    }

    private String nonBlankJoin(String separator, String... values) {
        return java.util.Arrays.stream(values)
                .filter(value -> value != null && !value.isBlank())
                .reduce((left, right) -> left + separator + right)
                .orElse("");
    }

    private String stringValue(Object value) {
        return value == null ? null : String.valueOf(value).trim();
    }

    private String trimWords(String value, int limit) {
        if (value == null || value.isBlank() || limit <= 0) {
            return value == null ? "" : value.trim();
        }
        String[] words = value.trim().split("\\s+");
        if (words.length <= limit) {
            return value.trim();
        }
        StringBuilder builder = new StringBuilder();
        for (int i = 0; i < limit; i++) {
            if (i > 0) {
                builder.append(' ');
            }
            builder.append(words[i]);
        }
        return builder.toString().trim();
    }
}
