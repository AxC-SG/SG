package com.prototype.vulnwatch.ticketing;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.JiraTicketingConfigService;
import com.prototype.vulnwatch.service.JiraTicketingConfigService.JiraRuntimeConfig;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_GATEWAY;
import static org.springframework.http.HttpStatus.SERVICE_UNAVAILABLE;

/**
 * Raises and reads Jira issues through the Jira Cloud REST v3 API.
 *
 * <p>Works against Jira Data Center too, which accepts the same {@code /rest/api/3} paths for
 * the two operations used here.
 */
@Component
public class JiraTicketingProvider implements TicketingProvider {

    private static final Logger log = LoggerFactory.getLogger(JiraTicketingProvider.class);

    private static final DateTimeFormatter ISO_DATE =
            DateTimeFormatter.ISO_LOCAL_DATE.withZone(ZoneOffset.UTC);

    /**
     * Severity to Jira's default priority names. Instances that renamed their priority scheme
     * will reject these, which is why the connector can send no priority at all.
     */
    private static final Map<String, String> PRIORITY_NAMES = Map.of(
            "CRITICAL", "Highest",
            "HIGH", "High",
            "MEDIUM", "Medium",
            "LOW", "Low",
            "INFO", "Lowest"
    );

    private final JiraTicketingConfigService jiraTicketingConfigService;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;

    public JiraTicketingProvider(
            JiraTicketingConfigService jiraTicketingConfigService,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper
    ) {
        this.jiraTicketingConfigService = jiraTicketingConfigService;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
    }

    @Override
    public TicketingSystem system() {
        return TicketingSystem.JIRA;
    }

    @Override
    public boolean isConfigured(Tenant tenant) {
        return jiraTicketingConfigService.isReadyForTicketing(tenant);
    }

    @Override
    public TicketRef createForFinding(Tenant tenant, Finding finding, TicketRequest request) {
        JiraRuntimeConfig config = requireConfig(tenant);
        TicketRequest safe = request == null ? TicketRequest.empty() : request;

        String body = serialize(buildCreatePayload(config, finding, safe));
        HttpHeaders headers = JiraTicketingConfigService.authHeaders(config);
        headers.setContentType(MediaType.APPLICATION_JSON);

        ResponseEntity<String> response = outboundHttpClient.exchange(
                config.baseUrl() + "/rest/api/3/issue",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                String.class,
                "Jira issue creation",
                outboundPolicyFactory.forProvider(JiraTicketingConfigService.PROVIDER_KEY, 0L, null, null),
                context -> new OutboundFailureDecision<RuntimeException>(
                        context.isRetryableByDefault(),
                        context.retryAfterDelayMs(),
                        context.error() instanceof RuntimeException rte
                                ? rte
                                : new RuntimeException("Jira issue creation failed: "
                                        + context.error().getMessage(), context.error())));

        JsonNode result = parse(response, "Jira issue creation");
        String issueKey = text(result.path("key"));
        String issueId = text(result.path("id"));
        if (issueKey == null) {
            throw new ResponseStatusException(BAD_GATEWAY,
                    "Jira returned an unexpected response — issue key missing");
        }
        return new TicketRef(
                TicketingSystem.JIRA,
                issueKey,
                issueId,
                config.baseUrl() + "/browse/" + issueKey,
                // Jira assigns the project's initial workflow status; it is not in the create
                // response, so the first status sync fills in the real value.
                "Open",
                "Issue " + issueKey + " created successfully in Jira"
        );
    }

    @Override
    public Optional<TicketStatus> fetchStatus(Tenant tenant, String externalKey) {
        if (externalKey == null || externalKey.isBlank()) {
            return Optional.empty();
        }
        Optional<JiraRuntimeConfig> configOpt = jiraTicketingConfigService.resolveRuntimeConfig(tenant);
        if (configOpt.isEmpty()) {
            return Optional.empty();
        }
        JiraRuntimeConfig config = configOpt.get();
        String endpoint = config.baseUrl() + "/rest/api/3/issue/"
                + URLEncoder.encode(externalKey.trim(), StandardCharsets.UTF_8) + "?fields=status";
        try {
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    endpoint,
                    HttpMethod.GET,
                    new HttpEntity<Void>(JiraTicketingConfigService.authHeaders(config)),
                    String.class,
                    "Jira issue status fetch",
                    outboundPolicyFactory.forProvider(JiraTicketingConfigService.PROVIDER_KEY, 0L, null, null),
                    context -> new OutboundFailureDecision<RuntimeException>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException rte
                                    ? rte
                                    : new RuntimeException("Jira status fetch failed: "
                                            + context.error().getMessage(), context.error())));
            JsonNode status = parse(response, "Jira issue status fetch").path("fields").path("status");
            String label = text(status.path("name"));
            if (label == null) {
                return Optional.empty();
            }
            // statusCategory is Jira's stable notion of completion. Status *names* are freely
            // renameable per workflow, so matching on them would misread any customised board.
            boolean resolved = "done".equalsIgnoreCase(
                    String.valueOf(text(status.path("statusCategory").path("key"))));
            return Optional.of(new TicketStatus(label, resolved));
        } catch (RuntimeException ex) {
            // Leave the last known status in place rather than blanking it on a transient outage.
            log.warn("Failed to fetch Jira status for issue {}: {}", externalKey, ex.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public TicketRef createForCve(Tenant tenant, CveTicketRequest request) {
        JiraRuntimeConfig config = requireConfig(tenant);
        String body = serialize(buildCveCreatePayload(config, request));
        HttpHeaders headers = JiraTicketingConfigService.authHeaders(config);
        headers.setContentType(MediaType.APPLICATION_JSON);

        ResponseEntity<String> response = outboundHttpClient.exchange(
                config.baseUrl() + "/rest/api/3/issue",
                HttpMethod.POST,
                new HttpEntity<>(body, headers),
                String.class,
                "Jira CVE issue creation",
                outboundPolicyFactory.forProvider(JiraTicketingConfigService.PROVIDER_KEY, 0L, null, null),
                context -> new OutboundFailureDecision<RuntimeException>(
                        context.isRetryableByDefault(), context.retryAfterDelayMs(),
                        context.error() instanceof RuntimeException rte ? rte
                                : new RuntimeException("Jira CVE issue creation failed: "
                                + context.error().getMessage(), context.error())));

        JsonNode result = parse(response, "Jira CVE issue creation");
        String issueKey = text(result.path("key"));
        if (issueKey == null) {
            throw new ResponseStatusException(BAD_GATEWAY,
                    "Jira returned an unexpected response — issue key missing");
        }
        return new TicketRef(
                TicketingSystem.JIRA, issueKey, text(result.path("id")),
                config.baseUrl() + "/browse/" + issueKey, "Open",
                "Issue " + issueKey + " created successfully in Jira");
    }

    /**
     * Records the change as a comment and, for state changes, moves the issue through the
     * project's workflow.
     *
     * <p>Jira has no direct "set status" call — an issue can only move along transitions its
     * workflow defines. When no transition leads to the target category, the comment still
     * lands and the push counts as applied: retrying forever would never find a transition and
     * would repost the comment on every run.
     */
    @Override
    public boolean pushFindingStatus(Tenant tenant, String externalKey, TicketPush push) {
        if (externalKey == null || externalKey.isBlank() || push == null) {
            return false;
        }
        Optional<JiraRuntimeConfig> configOpt = jiraTicketingConfigService.resolveRuntimeConfig(tenant);
        if (configOpt.isEmpty() || !configOpt.get().enabled()) {
            return false;
        }
        JiraRuntimeConfig config = configOpt.get();
        String note = push.note() == null || push.note().isBlank() ? "Updated by Scout" : push.note();

        if (!addComment(config, externalKey, note)) {
            return false;
        }
        if (push.action() == TicketPush.Action.COMMENT) {
            return true;
        }
        Optional<String> transitionId = findTransition(config, externalKey,
                push.action() == TicketPush.Action.RESOLVE
                        ? Set.of("done")
                        : Set.of("new", "indeterminate"));
        if (transitionId.isEmpty()) {
            log.info("Jira issue {} has no workflow transition to {} — comment recorded instead",
                    externalKey, push.action());
            return true;
        }
        return applyTransition(config, externalKey, transitionId.get());
    }

    private boolean addComment(JiraRuntimeConfig config, String issueKey, String note) {
        HttpHeaders headers = JiraTicketingConfigService.authHeaders(config);
        headers.setContentType(MediaType.APPLICATION_JSON);
        String body = serialize(Map.of("body", adfDocument(note)));
        try {
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    config.baseUrl() + "/rest/api/3/issue/"
                            + URLEncoder.encode(issueKey.trim(), StandardCharsets.UTF_8) + "/comment",
                    HttpMethod.POST,
                    new HttpEntity<>(body, headers),
                    String.class,
                    "Jira issue comment",
                    outboundPolicyFactory.forProvider(JiraTicketingConfigService.PROVIDER_KEY, 0L, null, null),
                    context -> new OutboundFailureDecision<RuntimeException>(
                            context.isRetryableByDefault(), context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException rte ? rte
                                    : new RuntimeException("Jira comment failed: "
                                    + context.error().getMessage(), context.error())));
            return response.getStatusCode().is2xxSuccessful();
        } catch (RuntimeException ex) {
            log.warn("Failed to comment on Jira issue {}: {}", issueKey, ex.getMessage());
            return false;
        }
    }

    /** First available transition whose destination falls in one of the target categories. */
    private Optional<String> findTransition(JiraRuntimeConfig config, String issueKey, Set<String> targetCategories) {
        try {
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    config.baseUrl() + "/rest/api/3/issue/"
                            + URLEncoder.encode(issueKey.trim(), StandardCharsets.UTF_8) + "/transitions",
                    HttpMethod.GET,
                    new HttpEntity<Void>(JiraTicketingConfigService.authHeaders(config)),
                    String.class,
                    "Jira issue transitions",
                    outboundPolicyFactory.forProvider(JiraTicketingConfigService.PROVIDER_KEY, 0L, null, null),
                    context -> new OutboundFailureDecision<RuntimeException>(
                            context.isRetryableByDefault(), context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException rte ? rte
                                    : new RuntimeException("Jira transition lookup failed: "
                                    + context.error().getMessage(), context.error())));
            JsonNode transitions = parse(response, "Jira issue transitions").path("transitions");
            if (!transitions.isArray()) {
                return Optional.empty();
            }
            for (JsonNode transition : transitions) {
                String category = text(transition.path("to").path("statusCategory").path("key"));
                if (category != null && targetCategories.contains(category.toLowerCase(Locale.ROOT))) {
                    return Optional.ofNullable(text(transition.path("id")));
                }
            }
        } catch (RuntimeException ex) {
            log.warn("Failed to read transitions for Jira issue {}: {}", issueKey, ex.getMessage());
        }
        return Optional.empty();
    }

    private boolean applyTransition(JiraRuntimeConfig config, String issueKey, String transitionId) {
        HttpHeaders headers = JiraTicketingConfigService.authHeaders(config);
        headers.setContentType(MediaType.APPLICATION_JSON);
        String body = serialize(Map.of("transition", Map.of("id", transitionId)));
        try {
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    config.baseUrl() + "/rest/api/3/issue/"
                            + URLEncoder.encode(issueKey.trim(), StandardCharsets.UTF_8) + "/transitions",
                    HttpMethod.POST,
                    new HttpEntity<>(body, headers),
                    String.class,
                    "Jira issue transition",
                    outboundPolicyFactory.forProvider(JiraTicketingConfigService.PROVIDER_KEY, 0L, null, null),
                    context -> new OutboundFailureDecision<RuntimeException>(
                            context.isRetryableByDefault(), context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException rte ? rte
                                    : new RuntimeException("Jira transition failed: "
                                    + context.error().getMessage(), context.error())));
            return response.getStatusCode().is2xxSuccessful();
        } catch (RuntimeException ex) {
            log.warn("Failed to transition Jira issue {}: {}", issueKey, ex.getMessage());
            return false;
        }
    }

    private Map<String, Object> buildCveCreatePayload(JiraRuntimeConfig config, CveTicketRequest request) {
        String severity = firstNonBlank(request.severity(), "MEDIUM");
        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("project", Map.of("key", config.projectKey()));
        fields.put("summary", request.cveId() + ": remediate "
                + request.safeAssets().size() + " affected asset(s)"
                + (request.assignmentGroup() == null || request.assignmentGroup().isBlank()
                        ? "" : " — " + request.assignmentGroup().trim()));
        fields.put("description", adfDocument(buildCveDescription(request, severity)));
        if (config.issueTypeId() != null) {
            fields.put("issuetype", Map.of("id", config.issueTypeId()));
        } else {
            fields.put("issuetype", Map.of("name", config.issueTypeName()));
        }
        if (config.includePriority()) {
            String priorityName = PRIORITY_NAMES.get(
                    firstNonBlank(request.priority(), severity, "MEDIUM").toUpperCase(Locale.ROOT));
            if (priorityName != null) {
                fields.put("priority", Map.of("name", priorityName));
            }
        }
        if (request.dueDate() != null && !request.dueDate().isBlank()) {
            fields.put("duedate", request.dueDate().trim());
        }
        if (request.assignee() != null && !request.assignee().isBlank()) {
            fields.put("assignee", Map.of("id", request.assignee().trim()));
        }
        List<String> labels = new ArrayList<>();
        labels.add("scout");
        labels.add(sanitizeLabel(request.cveId()));
        if (config.defaultLabels() != null) {
            for (String candidate : config.defaultLabels().split(",")) {
                String label = sanitizeLabel(candidate);
                if (!label.isEmpty() && !labels.contains(label)) {
                    labels.add(label);
                }
            }
        }
        fields.put("labels", labels);
        return Map.of("fields", fields);
    }

    private String buildCveDescription(CveTicketRequest request, String severity) {
        StringBuilder text = new StringBuilder();
        text.append("Scout correlated ").append(request.cveId()).append(" to this group's inventory.").append('\n');
        text.append("Severity: ").append(severity).append('\n');
        if (request.assignmentGroup() != null && !request.assignmentGroup().isBlank()) {
            text.append("Assignment group: ").append(request.assignmentGroup().trim()).append('\n');
        }
        if (request.dueDate() != null && !request.dueDate().isBlank()) {
            text.append("Remediation due: ").append(request.dueDate().trim()).append('\n');
        }
        if (!request.safeAssets().isEmpty()) {
            text.append('\n').append("Affected assets:").append('\n');
            for (TicketAsset asset : request.safeAssets()) {
                text.append("- ").append(firstNonBlank(asset.assetName(), asset.assetIdentifier(), "unknown asset"));
                String pkg = firstNonBlank(asset.packageName(), null);
                if (pkg != null) {
                    text.append(" — ").append(pkg);
                    if (asset.packageVersion() != null && !asset.packageVersion().isBlank()) {
                        text.append(' ').append(asset.packageVersion().trim());
                    }
                }
                text.append('\n');
            }
        }
        if (request.notes() != null && !request.notes().isBlank()) {
            text.append('\n').append(request.notes().trim()).append('\n');
        }
        if (request.solutionInfo() != null && !request.solutionInfo().isBlank()) {
            text.append('\n').append("Remediation guidance:").append('\n').append(request.solutionInfo().trim()).append('\n');
        }
        return text.toString();
    }

    private JiraRuntimeConfig requireConfig(Tenant tenant) {
        JiraRuntimeConfig config = jiraTicketingConfigService.resolveRuntimeConfig(tenant)
                .orElseThrow(() -> new ResponseStatusException(SERVICE_UNAVAILABLE,
                        "Jira is not configured for this tenant. Configure the Jira connector first."));
        if (!config.enabled()) {
            throw new ResponseStatusException(SERVICE_UNAVAILABLE, "The Jira connector is disabled for this tenant.");
        }
        return config;
    }

    private Map<String, Object> buildCreatePayload(JiraRuntimeConfig config, Finding finding, TicketRequest request) {
        String severity = firstNonBlank(request.severity(), finding.getSeverityOverride(), "MEDIUM");
        String title = firstNonBlank(request.title(), finding.getTitle(), finding.getDisplayId());
        String dueDate = firstNonBlank(request.dueDate(), isoDate(finding.getDueAt()));

        Map<String, Object> fields = new LinkedHashMap<>();
        fields.put("project", Map.of("key", config.projectKey()));
        fields.put("summary", finding.getDisplayId() + ": " + title);
        fields.put("description", adfDocument(buildDescription(finding, severity, request, dueDate)));

        // An explicit id wins: issue type names are not unique across an instance's schemes.
        if (config.issueTypeId() != null) {
            fields.put("issuetype", Map.of("id", config.issueTypeId()));
        } else {
            fields.put("issuetype", Map.of("name", config.issueTypeName()));
        }

        if (config.includePriority()) {
            String priorityName = PRIORITY_NAMES.get(
                    firstNonBlank(request.priority(), severity, "MEDIUM").toUpperCase(Locale.ROOT));
            if (priorityName != null) {
                fields.put("priority", Map.of("name", priorityName));
            }
        }
        if (dueDate != null) {
            fields.put("duedate", dueDate);
        }
        if (request.assignee() != null && !request.assignee().isBlank()) {
            // Jira Cloud identifies users by opaque account id, not username.
            fields.put("assignee", Map.of("id", request.assignee().trim()));
        }
        List<String> labels = labels(config, finding);
        if (!labels.isEmpty()) {
            fields.put("labels", labels);
        }

        return Map.of("fields", fields);
    }

    /**
     * Labels are how a Jira project filters Scout-raised work, so every issue carries a
     * provenance label plus whatever the tenant configured.
     */
    private List<String> labels(JiraRuntimeConfig config, Finding finding) {
        List<String> labels = new ArrayList<>();
        labels.add("scout");
        if (finding.getDisplayId() != null && !finding.getDisplayId().isBlank()) {
            labels.add(sanitizeLabel(finding.getDisplayId()));
        }
        if (config.defaultLabels() != null) {
            for (String candidate : config.defaultLabels().split(",")) {
                String label = sanitizeLabel(candidate);
                if (!label.isEmpty() && !labels.contains(label)) {
                    labels.add(label);
                }
            }
        }
        return labels;
    }

    /** Jira rejects labels containing whitespace. */
    private static String sanitizeLabel(String value) {
        return value == null ? "" : value.trim().replaceAll("\\s+", "-");
    }

    private String buildDescription(Finding finding, String severity, TicketRequest request, String dueDate) {
        StringBuilder text = new StringBuilder();
        text.append("Scout finding ").append(finding.getDisplayId()).append('\n');
        text.append("Severity: ").append(severity).append('\n');
        if (finding.getPolicyId() != null) {
            text.append("Policy: ").append(finding.getPolicyId()).append('\n');
        }
        if (finding.getReasonCode() != null) {
            text.append("Reason: ").append(finding.getReasonCode()).append('\n');
        }
        if (finding.getOwnerGroup() != null) {
            text.append("Owner group: ").append(finding.getOwnerGroup()).append('\n');
        }
        if (dueDate != null) {
            text.append("Remediation due: ").append(dueDate).append('\n');
        }
        if (request.notes() != null && !request.notes().isBlank()) {
            text.append('\n').append(request.notes().trim()).append('\n');
        }
        if (request.solutionInfo() != null && !request.solutionInfo().isBlank()) {
            text.append("\nRemediation guidance:\n").append(request.solutionInfo().trim()).append('\n');
        }
        return text.toString();
    }

    /**
     * Wraps plain text as an Atlassian Document Format doc. The v3 API rejects a plain string
     * for rich-text fields, so this is required rather than cosmetic.
     */
    private static Map<String, Object> adfDocument(String body) {
        List<Map<String, Object>> paragraphs = new ArrayList<>();
        for (String line : body.split("\n", -1)) {
            if (line.isEmpty()) {
                continue;
            }
            paragraphs.add(Map.of(
                    "type", "paragraph",
                    "content", List.of(Map.of("type", "text", "text", line))));
        }
        if (paragraphs.isEmpty()) {
            paragraphs.add(Map.of("type", "paragraph", "content", List.of()));
        }
        return Map.of("type", "doc", "version", 1, "content", paragraphs);
    }

    private String serialize(Map<String, Object> payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (JsonProcessingException ex) {
            throw new ResponseStatusException(BAD_GATEWAY,
                    "Failed to serialize Jira issue payload: " + ex.getMessage());
        }
    }

    private JsonNode parse(ResponseEntity<String> response, String operationName) {
        String body = response.getBody();
        if (body == null || body.isBlank()) {
            throw new ResponseStatusException(BAD_GATEWAY, operationName + " returned an empty response");
        }
        try {
            return objectMapper.readTree(body);
        } catch (JsonProcessingException ex) {
            throw new ResponseStatusException(BAD_GATEWAY,
                    operationName + " returned a response that could not be parsed: " + ex.getMessage());
        }
    }

    private static String text(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        String value = node.asText(null);
        return value == null || value.isBlank() ? null : value;
    }

    private static String firstNonBlank(String... candidates) {
        for (String candidate : candidates) {
            if (candidate != null && !candidate.isBlank()) {
                return candidate.trim();
            }
        }
        return null;
    }

    private static String isoDate(Instant instant) {
        return instant == null ? null : ISO_DATE.format(instant);
    }
}
