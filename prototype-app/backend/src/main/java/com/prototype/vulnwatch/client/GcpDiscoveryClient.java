package com.prototype.vulnwatch.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

/**
 * REST client for the GCP APIs Cloud Discovery reads.
 *
 * <p>Calls go through {@link OutboundHttpClient} rather than the Google SDKs so they share the
 * outbound host allowlist (provider {@value #PROVIDER_KEY}), pacing and retry policy of every
 * other integration. Every list call reports whether it saw the complete result set; callers
 * must not treat a missing resource as deleted unless its listing was complete.
 */
@Component
public class GcpDiscoveryClient {

    public static final String PROVIDER_KEY = "gcp";

    /** Hard ceiling on pages per listing, so a runaway result set cannot hold a worker forever. */
    static final int MAX_PAGES = 200;

    private static final Logger LOG = LoggerFactory.getLogger(GcpDiscoveryClient.class);
    private static final Pattern ZONE = Pattern.compile("^[a-z]+-[a-z]+[0-9]+-[a-z]$");

    private static final String COMPUTE = "https://compute.googleapis.com/compute/v1";
    private static final String OS_CONFIG = "https://osconfig.googleapis.com/v1";
    private static final String CLOUD_ASSET = "https://cloudasset.googleapis.com/v1";
    private static final String RESOURCE_MANAGER = "https://cloudresourcemanager.googleapis.com/v1";

    private final OutboundHttpClient http;
    private final OutboundPolicyFactory policies;
    private final ObjectMapper objectMapper;

    public GcpDiscoveryClient(OutboundHttpClient http, OutboundPolicyFactory policies, ObjectMapper objectMapper) {
        this.http = http;
        this.policies = policies;
        this.objectMapper = objectMapper;
    }

    // ── Records ──────────────────────────────────────────────────────────────────────────────

    /** A Compute Engine VM. */
    public record GcpInstanceRecord(
            String projectId,
            String instanceId,
            String name,
            String zone,
            String machineType,
            String status,
            String network,
            String subnetwork,
            Map<String, String> labels,
            Instant createdAt,
            boolean hasServiceAccount
    ) {
        /** Stable identifier keyed on the numeric id, which, unlike the name, is never reused. */
        public String identifier() {
            return "//compute.googleapis.com/projects/" + projectId + "/zones/" + zone + "/instances/" + instanceId;
        }

        public String region() {
            return regionOf(zone);
        }
    }

    /** A non-VM resource from Cloud Asset Inventory. */
    public record GcpResourceRecord(
            String name,
            String assetType,
            String resourceType,
            String projectId,
            String displayName,
            String location,
            String state,
            Map<String, String> labels,
            Instant createdAt
    ) {}

    /** A listing plus what went wrong; {@code complete} is false when anything was missed. */
    public record ListResult<T>(List<T> records, Map<String, String> errors, boolean complete) {}

    /** Installed packages per VM, keyed by numeric instance id. */
    public record InventoryResult(
            Map<String, List<Map<String, String>>> packagesByInstanceId,
            Map<String, Instant> capturedAtByInstanceId,
            Map<String, String> errors
    ) {}

    /** A GCP API error with the status Google reported, safe to show to an operator. */
    public static class GcpApiException extends RuntimeException {
        private final int status;

        public GcpApiException(int status, String message) {
            super(message);
            this.status = status;
        }

        public int status() {
            return status;
        }
    }

    // ── Permissions ──────────────────────────────────────────────────────────────────────

    /** The subset of {@code permissions} the token holds on the project. */
    public Set<String> testPermissions(String token, String projectId, Collection<String> permissions) {
        JsonNode response = call(HttpMethod.POST,
                RESOURCE_MANAGER + "/projects/" + projectId + ":testIamPermissions", token,
                Map.of("permissions", List.copyOf(permissions)), "GCP permission check");
        Set<String> granted = new LinkedHashSet<>();
        response.path("permissions").forEach(node -> granted.add(node.asText()));
        return granted;
    }

    // ── Compute Engine ───────────────────────────────────────────────────────────────────────

    public ListResult<GcpInstanceRecord> listInstances(String token, String projectId) {
        List<GcpInstanceRecord> records = new ArrayList<>();
        Map<String, String> errors = new LinkedHashMap<>();
        String pageToken = null;
        int pages = 0;
        try {
            do {
                String url = COMPUTE + "/projects/" + projectId
                        + "/aggregated/instances?maxResults=500&returnPartialSuccess=true"
                        + (pageToken == null ? "" : "&pageToken=" + encode(pageToken));
                JsonNode page = call(HttpMethod.GET, url, token, null, "GCP Compute instance listing");
                for (Iterator<Map.Entry<String, JsonNode>> scopes = page.path("items").fields(); scopes.hasNext(); ) {
                    Map.Entry<String, JsonNode> scope = scopes.next();
                    for (JsonNode instance : scope.getValue().path("instances")) {
                        GcpInstanceRecord record = toInstance(projectId, instance);
                        if (record != null) {
                            records.add(record);
                        }
                    }
                }
                page.path("unreachables").forEach(node -> errors.put(node.asText(), "unreachable"));
                pageToken = textOrNull(page.path("nextPageToken"));
                pages++;
            } while (pageToken != null && pages < MAX_PAGES);
            if (pageToken != null) {
                errors.put("compute", "result truncated after " + MAX_PAGES + " pages");
            }
        } catch (RuntimeException failure) {
            errors.put("compute", safeMessage(failure));
        }
        return new ListResult<>(records, errors, errors.isEmpty());
    }

    private GcpInstanceRecord toInstance(String projectId, JsonNode node) {
        String id = textOrNull(node.path("id"));
        String zone = lastSegment(textOrNull(node.path("zone")));
        if (id == null || zone == null || !ZONE.matcher(zone).matches()) {
            return null;
        }
        JsonNode nic = node.path("networkInterfaces").path(0);
        return new GcpInstanceRecord(
                projectId,
                id,
                textOrNull(node.path("name")),
                zone,
                lastSegment(textOrNull(node.path("machineType"))),
                textOrNull(node.path("status")),
                lastSegment(textOrNull(nic.path("network"))),
                lastSegment(textOrNull(nic.path("subnetwork"))),
                labels(node.path("labels")),
                parseTime(textOrNull(node.path("creationTimestamp"))),
                node.path("serviceAccounts").size() > 0
        );
    }

    // ── OS Config (VM Manager) inventory ─────────────────────────────────────────────────────

    /**
     * Installed packages for VMs in the given zones. Missing VM Manager data is not an error for
     * the asset listing: those VMs are recorded without packages, the same as EC2 without SSM.
     */
    public InventoryResult listInventories(String token, String projectId, Collection<String> zones) {
        Map<String, List<Map<String, String>>> packages = new HashMap<>();
        Map<String, Instant> captured = new HashMap<>();
        Map<String, String> errors = new LinkedHashMap<>();
        for (String zone : new LinkedHashSet<>(zones)) {
            if (zone == null || !ZONE.matcher(zone).matches()) {
                continue;
            }
            String pageToken = null;
            int pages = 0;
            try {
                do {
                    String url = OS_CONFIG + "/projects/" + projectId + "/locations/" + zone
                            + "/instances/-/inventories?view=FULL&pageSize=100"
                            + (pageToken == null ? "" : "&pageToken=" + encode(pageToken));
                    JsonNode page = call(HttpMethod.GET, url, token, null, "GCP OS inventory listing");
                    for (JsonNode inventory : page.path("inventories")) {
                        String instanceId = instanceIdFromInventoryName(textOrNull(inventory.path("name")));
                        if (instanceId == null) {
                            continue;
                        }
                        packages.put(instanceId, packageRows(inventory.path("items")));
                        Instant updated = parseTime(textOrNull(inventory.path("updateTime")));
                        if (updated != null) {
                            captured.put(instanceId, updated);
                        }
                    }
                    pageToken = textOrNull(page.path("nextPageToken"));
                    pages++;
                } while (pageToken != null && pages < MAX_PAGES);
            } catch (RuntimeException failure) {
                errors.put(zone, safeMessage(failure));
            }
        }
        return new InventoryResult(packages, captured, errors);
    }

    private List<Map<String, String>> packageRows(JsonNode items) {
        List<Map<String, String>> rows = new ArrayList<>();
        for (JsonNode item : items) {
            if (!"INSTALLED_PACKAGE".equals(item.path("type").asText())) {
                continue;
            }
            JsonNode installed = item.path("installedPackage");
            JsonNode windows = installed.path("windowsApplication");
            if (!windows.isMissingNode()) {
                addRow(rows, textOrNull(windows.path("displayName")), textOrNull(windows.path("publisher")),
                        textOrNull(windows.path("displayVersion")));
                continue;
            }
            for (String kind : List.of("aptPackage", "yumPackage", "zypperPackage", "googetPackage", "cosPackage")) {
                JsonNode pkg = installed.path(kind);
                if (!pkg.isMissingNode()) {
                    addRow(rows, textOrNull(pkg.path("packageName")), null, textOrNull(pkg.path("version")));
                    break;
                }
            }
        }
        return rows;
    }

    private static void addRow(List<Map<String, String>> rows, String name, String publisher, String version) {
        if (name == null) {
            return;
        }
        Map<String, String> row = new HashMap<>();
        row.put("display_name", name);
        row.put("publisher", publisher == null ? "" : publisher);
        row.put("version", version == null ? "" : version);
        rows.add(row);
    }

    static String instanceIdFromInventoryName(String name) {
        // projects/{project}/locations/{zone}/instances/{instanceId}/inventory
        if (name == null) {
            return null;
        }
        String[] parts = name.split("/");
        for (int i = 0; i + 1 < parts.length; i++) {
            if ("instances".equals(parts[i]) && parts[i + 1].matches("\\d+")) {
                return parts[i + 1];
            }
        }
        return null;
    }

    // ── Cloud Asset Inventory ────────────────────────────────────────────────────────────────

    /**
     * Searches the project for the given asset types.
     *
     * @param assetTypesByKey Scout resource type key to the Cloud Asset types it covers
     */
    public ListResult<GcpResourceRecord> searchResources(
            String token, String projectId, Map<String, List<String>> assetTypesByKey) {
        Map<String, String> keyByAssetType = new HashMap<>();
        assetTypesByKey.forEach((key, types) -> types.forEach(type -> keyByAssetType.put(type, key)));
        if (keyByAssetType.isEmpty()) {
            return new ListResult<>(List.of(), Map.of(), true);
        }
        StringBuilder typeQuery = new StringBuilder();
        keyByAssetType.keySet().stream().sorted().forEach(type -> typeQuery.append("&assetTypes=").append(encode(type)));

        List<GcpResourceRecord> records = new ArrayList<>();
        Map<String, String> errors = new LinkedHashMap<>();
        String pageToken = null;
        int pages = 0;
        try {
            do {
                String url = CLOUD_ASSET + "/projects/" + projectId + ":searchAllResources?pageSize=500" + typeQuery
                        + (pageToken == null ? "" : "&pageToken=" + encode(pageToken));
                JsonNode page = call(HttpMethod.GET, url, token, null, "GCP Cloud Asset search");
                for (JsonNode result : page.path("results")) {
                    String name = textOrNull(result.path("name"));
                    String assetType = textOrNull(result.path("assetType"));
                    String key = assetType == null ? null : keyByAssetType.get(assetType);
                    if (name == null || key == null) {
                        continue;
                    }
                    records.add(new GcpResourceRecord(
                            name,
                            assetType,
                            key,
                            projectId,
                            textOrNull(result.path("displayName")),
                            textOrNull(result.path("location")),
                            textOrNull(result.path("state")),
                            labels(result.path("labels")),
                            parseTime(textOrNull(result.path("createTime")))));
                }
                pageToken = textOrNull(page.path("nextPageToken"));
                pages++;
            } while (pageToken != null && pages < MAX_PAGES);
            if (pageToken != null) {
                errors.put("cloudasset", "result truncated after " + MAX_PAGES + " pages");
            }
        } catch (RuntimeException failure) {
            errors.put("cloudasset", safeMessage(failure));
        }
        return new ListResult<>(records, errors, errors.isEmpty());
    }

    // ── HTTP ─────────────────────────────────────────────────────────────────────────────────

    private JsonNode call(HttpMethod method, String url, String token, Object body, String operation) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        HttpEntity<?> entity;
        if (body == null) {
            entity = new HttpEntity<Void>(headers);
        } else {
            headers.setContentType(MediaType.APPLICATION_JSON);
            entity = new HttpEntity<>(toJson(body), headers);
        }
        OutboundPolicy policy = policies.forProvider(PROVIDER_KEY, null, null, null);
        ResponseEntity<String> response = http.exchange(url, method, entity, String.class, operation, policy,
                context -> new OutboundFailureDecision<RuntimeException>(
                        context.isRetryableByDefault(),
                        context.retryAfterDelayMs(),
                        toApiException(operation, context.statusCodeValue(), context.error())));
        String responseBody = response.getBody();
        if (responseBody == null || responseBody.isBlank()) {
            return objectMapper.createObjectNode();
        }
        try {
            return objectMapper.readTree(responseBody);
        } catch (Exception malformed) {
            throw new GcpApiException(502, operation + " returned a malformed response");
        }
    }

    private RuntimeException toApiException(String operation, Integer status, Exception error) {
        if (status != null) {
            String detail = googleErrorMessage(error == null ? null : error.getMessage());
            return new GcpApiException(status, operation + " failed (HTTP " + status + ")"
                    + (detail == null ? "" : ": " + detail));
        }
        return new GcpApiException(503, operation + " failed: " + (error == null ? "unknown error" : error.getMessage()));
    }

    private static final Pattern GOOGLE_ERROR_MESSAGE = Pattern.compile("\"message\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    /** The {@code error.message} Google puts in its JSON error body, which the HTTP error text carries. */
    static String googleErrorMessage(String errorText) {
        if (errorText == null || errorText.isBlank()) {
            return null;
        }
        java.util.regex.Matcher matcher = GOOGLE_ERROR_MESSAGE.matcher(errorText);
        return matcher.find() ? truncate(matcher.group(1), 400) : null;
    }

    private String toJson(Object body) {
        try {
            return objectMapper.writeValueAsString(body);
        } catch (Exception impossible) {
            throw new IllegalStateException("Could not serialize GCP request", impossible);
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    static String regionOf(String zone) {
        if (zone == null) {
            return null;
        }
        int dash = zone.lastIndexOf('-');
        return dash > 0 ? zone.substring(0, dash) : zone;
    }

    private static Map<String, String> labels(JsonNode node) {
        Map<String, String> labels = new LinkedHashMap<>();
        node.fields().forEachRemaining(entry -> labels.put(entry.getKey(), entry.getValue().asText()));
        return labels;
    }

    private static String lastSegment(String value) {
        if (value == null) {
            return null;
        }
        int slash = value.lastIndexOf('/');
        return slash >= 0 ? value.substring(slash + 1) : value;
    }

    private static String textOrNull(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        String text = node.asText();
        return text == null || text.isBlank() ? null : text;
    }

    private static Instant parseTime(String value) {
        if (value == null) {
            return null;
        }
        try {
            return OffsetDateTime.parse(value).toInstant();
        } catch (Exception notOffset) {
            try {
                return Instant.parse(value);
            } catch (Exception unparseable) {
                return null;
            }
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    static String safeMessage(RuntimeException failure) {
        String message = failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage();
        LOG.debug("GCP call failed: {}", message);
        return truncate(message, 500);
    }

    private static String truncate(String value, int max) {
        return value.length() <= max ? value : value.substring(0, max) + "…";
    }
}
