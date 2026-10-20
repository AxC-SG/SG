package com.prototype.vulnwatch.client;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import com.prototype.vulnwatch.client.http.AzureManagementTransport;

@Service
public class AzureDiscoveryClient {

    private static final Logger LOG = LoggerFactory.getLogger(AzureDiscoveryClient.class);
    private static final String MANAGEMENT_SCOPE = "https://management.azure.com/.default";
    private static final String API_VERSION = "2021-04-01";

    private final AzureManagementTransport httpClient;
    private final ObjectMapper objectMapper;
    private final int maxPages;
    private final int maxResponseBytes;
    private final long maxDurationMs;

    public AzureDiscoveryClient(ObjectMapper objectMapper) {
        this(objectMapper, new AzureManagementTransport(), 100, 8_000_000, 120_000);
    }

    @Autowired
    public AzureDiscoveryClient(ObjectMapper objectMapper, AzureManagementTransport httpClient,
            @Value("${app.azure.discovery.max-pages:100}") int maxPages,
            @Value("${app.azure.discovery.max-response-bytes:8000000}") int maxResponseBytes,
            @Value("${app.azure.discovery.max-duration-ms:120000}") long maxDurationMs) {
        this.objectMapper = objectMapper;
        this.httpClient = httpClient;
        if (maxPages < 1 || maxResponseBytes < 1 || maxDurationMs < 1) throw new IllegalArgumentException("Azure HTTP budgets must be positive");
        this.maxPages = maxPages;
        this.maxResponseBytes = maxResponseBytes;
        this.maxDurationMs = maxDurationMs;
    }

    /** Test connectivity to a single Azure subscription using the shared credential. */
    public AzureConnectivityResult testConnectivity(TokenCredential credential, String subscriptionId) {
        try {
            JsonNode response = getJson(credential,
                    "https://management.azure.com/subscriptions/" + encode(subscriptionId) + "?api-version=2020-01-01");
            String displayName = textOrNull(response.path("displayName"));
            String tenantId = textOrNull(response.path("tenantId"));
            return new AzureConnectivityResult(
                    true, subscriptionId, hasText(displayName) ? displayName : subscriptionId, tenantId, null);
        } catch (Exception e) {
            LOG.debug("Azure subscription connectivity test failed: {}", e.getClass().getSimpleName());
            return new AzureConnectivityResult(false, subscriptionId, null, null, e.getMessage());
        }
    }

    /** Fetch all resources for a single subscription, filtered by region if regions is non-empty. */
    public AzureResourceFetchResult fetchResources(TokenCredential credential, String subscriptionId, List<String> regions) {
        List<AzureResourceRecord> records = new ArrayList<>();
        Set<String> seen = new LinkedHashSet<>();
        String nextUrl = "https://management.azure.com/subscriptions/" + encode(subscriptionId) + "/resources?api-version=" + API_VERSION;
        String error = null;
        Set<String> visited = new LinkedHashSet<>();
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(maxDurationMs);

        while (nextUrl != null) {
            try {
                if (visited.size() >= maxPages || !visited.add(nextUrl) || System.nanoTime() > deadline) {
                    throw new IllegalStateException("Azure continuation exceeded its page or time budget");
                }
                JsonNode response = getJson(credential, nextUrl);
                if (System.nanoTime() > deadline) throw new IllegalStateException("Azure discovery exceeded its time budget");
                JsonNode values = response.path("value");
                if (values.isArray()) {
                    for (JsonNode value : values) {
                        AzureResourceRecord record = toRecord(subscriptionId, value);
                        if (record.resourceId() == null || !seen.add(record.resourceId())) {
                            continue;
                        }
                        if (matchesRegion(record.location(), regions)) {
                            records.add(record);
                        }
                    }
                }
                nextUrl = textOrNull(response.path("nextLink"));
            } catch (Exception e) {
                LOG.warn("Azure resource fetch failed for subscription {}: {}", subscriptionId, e.getMessage());
                error = e.getMessage();
                nextUrl = null;
            }
        }

        return new AzureResourceFetchResult(records, error);
    }

    private boolean matchesRegion(String location, List<String> regions) {
        if (regions == null || regions.isEmpty() || !hasText(location)) {
            return true;
        }
        return regions.stream().anyMatch(region -> region != null && region.equalsIgnoreCase(location.trim()));
    }

    private AzureResourceRecord toRecord(String subscriptionId, JsonNode value) {
        String resourceId = textOrNull(value.path("id"));
        String name = textOrNull(value.path("name"));
        String resourceType = textOrNull(value.path("type"));
        String location = textOrNull(value.path("location"));
        String kind = textOrNull(value.path("kind"));
        String provisioningState = textOrNull(value.path("properties").path("provisioningState"));
        String resourceGroup = extractResourceGroup(resourceId);
        Map<String, String> tags = new LinkedHashMap<>();
        JsonNode tagsNode = value.path("tags");
        if (tagsNode.isObject()) {
            tagsNode.fields().forEachRemaining(entry -> tags.put(entry.getKey(), entry.getValue().asText()));
        }
        return new AzureResourceRecord(
                subscriptionId,
                resourceId,
                hasText(name) ? name : fallbackName(resourceId),
                resourceType,
                resourceGroup,
                location,
                kind,
                provisioningState,
                tags
        );
    }

    private JsonNode getJson(TokenCredential credential, String url) throws IOException, InterruptedException {
        URI uri = URI.create(url);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || !"management.azure.com".equalsIgnoreCase(uri.getHost())
                || uri.getUserInfo() != null || (uri.getPort() != -1 && uri.getPort() != 443) || uri.getFragment() != null) {
            throw new IllegalArgumentException("Azure continuation must use the approved management endpoint");
        }
        String token = bearerToken(credential);
        return objectMapper.readTree(httpClient.get(uri, token, maxResponseBytes, maxDurationMs));
    }

    private String bearerToken(TokenCredential credential) {
        AccessToken token = credential.getToken(new TokenRequestContext().addScopes(MANAGEMENT_SCOPE))
                .block(Duration.ofSeconds(30));
        if (token == null || token.getToken() == null || token.getToken().isBlank()) {
            throw new IllegalStateException("Unable to acquire Azure management API token");
        }
        return token.getToken();
    }

    private String extractResourceGroup(String resourceId) {
        if (!hasText(resourceId)) {
            return null;
        }
        String marker = "/resourceGroups/";
        int start = resourceId.indexOf(marker);
        if (start < 0) {
            return null;
        }
        String remainder = resourceId.substring(start + marker.length());
        int end = remainder.indexOf('/');
        return end < 0 ? remainder : remainder.substring(0, end);
    }

    private String fallbackName(String resourceId) {
        if (!hasText(resourceId)) {
            return "unknown";
        }
        int slash = resourceId.lastIndexOf('/');
        return slash >= 0 && slash + 1 < resourceId.length() ? resourceId.substring(slash + 1) : resourceId;
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String abbreviate(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.length() > 240 ? trimmed.substring(0, 240) + "..." : trimmed;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String textOrNull(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() ? null : node.asText(null);
    }

    public record AzureResourceRecord(
            String subscriptionId,
            String resourceId,
            String name,
            String resourceType,
            String resourceGroup,
            String location,
            String kind,
            String provisioningState,
            Map<String, String> tags
    ) {}

    public record AzureConnectivityResult(
            boolean success,
            String subscriptionId,
            String subscriptionName,
            String tenantId,
            String errorMessage
    ) {}

    public record AzureResourceFetchResult(
            List<AzureResourceRecord> records,
            String error
    ) {}
}
