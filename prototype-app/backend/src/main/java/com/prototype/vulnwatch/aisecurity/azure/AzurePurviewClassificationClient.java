package com.prototype.vulnwatch.aisecurity.azure;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiGridProviderCallCounter;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Reads whatever classification results already exist in the customer's Microsoft Purview
 * account for a given Storage Account — a metadata search against Purview's Data Map, never a
 * scan Scout triggers itself and never a read of blob content. Purview account name is optional
 * connector config; when it isn't set, PII lookups are simply reported as not scanned.
 *
 * <p>Targets the Purview Data Map "Discovery - Query" API (POST /datamap/api/search/query,
 * api-version 2023-09-01). This should be verified against a live Purview account before the
 * {@code app.ai-security.azure.purview-pii.enabled} flag (default off) is turned on.
 */
@Component
public class AzurePurviewClassificationClient {

    private static final String PURVIEW_SCOPE = "https://purview.azure.com/.default";
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(15);
    private static final int MAX_RESPONSE_BYTES = 1_000_000;
    private static final int MAX_PAGES = 25;
    private static final int PAGE_SIZE = 1_000;

    private final com.prototype.vulnwatch.client.http.CheckedHttpTransport http;
    private final ObjectMapper objectMapper;
    private final AiGridProviderCallCounter providerCalls;

    @org.springframework.beans.factory.annotation.Autowired
    public AzurePurviewClassificationClient(ObjectMapper objectMapper, AiGridProviderCallCounter providerCalls) {
        this.objectMapper = objectMapper;
        this.providerCalls = providerCalls;
        this.http = new com.prototype.vulnwatch.client.http.CheckedHttpTransport();
    }

    AzurePurviewClassificationClient(ObjectMapper objectMapper) {
        this(objectMapper, new AiGridProviderCallCounter());
    }

    public PiiLookupResult lookup(TokenCredential credential, String purviewAccountName, String storageAccountName) {
        if (purviewAccountName == null || purviewAccountName.isBlank()) {
            return notScanned();
        }
        String account = purviewAccountName.trim().toLowerCase(Locale.ROOT);
        String storage = storageAccountName == null ? "" : storageAccountName.trim().toLowerCase(Locale.ROOT);
        if (!account.matches("[a-z0-9][a-z0-9-]{1,61}[a-z0-9]") || !storage.matches("[a-z0-9]{3,24}")) {
            return lookupFailed();
        }
        try {
            URI uri = URI.create("https://" + account
                    + ".purview.azure.com/datamap/api/search/query?api-version=2023-09-01");
            validatePurviewUri(uri);
            String continuationToken = null;
            Set<String> visitedTokens = new LinkedHashSet<>();
            for (int page = 0; page < MAX_PAGES; page++) {
                Map<String, Object> query = new LinkedHashMap<>();
                query.put("keywords", storage);
                query.put("limit", PAGE_SIZE);
                if (continuationToken != null) query.put("continuationToken", continuationToken);
                String body = objectMapper.writeValueAsString(query);
                HttpRequest request = HttpRequest.newBuilder(uri)
                        .timeout(REQUEST_TIMEOUT)
                        .header("Authorization", "Bearer " + bearerToken(credential))
                        .header("Content-Type", "application/json")
                        .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                        .build();
                providerCalls.increment();
                var response = http.sendStream(request, MAX_RESPONSE_BYTES);
                try (InputStream responseBody = response.body()) {
                    if (response.statusCode() == 404) return notScanned();
                    if (response.statusCode() < 200 || response.statusCode() >= 300) return lookupFailed();
                    JsonNode root = objectMapper.readTree(readBounded(responseBody));
                    PiiLookupResult parsed = parseResults(root, storage);
                    if ("SCANNED_PII_FOUND".equals(parsed.status())) return parsed;
                    continuationToken = text(root.path("continuationToken"));
                    if (continuationToken == null) return unknown();
                    if (!visitedTokens.add(continuationToken)) return lookupFailed();
                }
            }
            return lookupFailed();
        } catch (Exception ex) {
            return lookupFailed();
        }
    }

    PiiLookupResult parseResults(JsonNode root, String storageAccountName) {
        Set<String> infoTypes = new LinkedHashSet<>();
        int classifiedEntityCount = 0;
        JsonNode values = root.path("value");
        if (values.isArray()) {
            for (JsonNode entity : values) {
                if (!belongsToStorageAccount(text(entity.path("qualifiedName")), storageAccountName)) continue;
                JsonNode classifications = entity.path("classification");
                if (classifications.isArray() && !classifications.isEmpty()) {
                    classifiedEntityCount++;
                    for (JsonNode classification : classifications) {
                        String typeName = classification.isTextual() ? classification.asText(null) : null;
                        if (typeName != null && !typeName.isBlank()) {
                            infoTypes.add(typeName);
                        }
                    }
                }
            }
        }
        if (classifiedEntityCount == 0) {
            return unknown();
        }
        return new PiiLookupResult("SCANNED_PII_FOUND", "AZURE_PURVIEW", List.copyOf(infoTypes),
                classifiedEntityCount, null);
    }

    private boolean belongsToStorageAccount(String qualifiedName, String storageAccountName) {
        if (qualifiedName == null || storageAccountName == null) return false;
        String account = storageAccountName.toLowerCase(Locale.ROOT);
        String normalized = qualifiedName.toLowerCase(Locale.ROOT);
        try {
            URI qualified = URI.create(qualifiedName);
            String host = qualified.getHost() == null ? "" : qualified.getHost().toLowerCase(Locale.ROOT);
            if (host.equals(account + ".blob.core.windows.net")
                    || host.equals(account + ".dfs.core.windows.net")
                    || host.equals(account + ".file.core.windows.net")) return true;
        } catch (IllegalArgumentException ignored) { }
        return normalized.matches(".*/storageaccounts/" + java.util.regex.Pattern.quote(account) + "(?:/.*)?$");
    }

    private byte[] readBounded(InputStream body) throws java.io.IOException {
        byte[] bytes = body.readNBytes(MAX_RESPONSE_BYTES + 1);
        if (bytes.length > MAX_RESPONSE_BYTES) throw new java.io.IOException("Purview response exceeded the allowed size");
        return bytes;
    }

    private String text(JsonNode node) {
        if (node == null || !node.isTextual() || node.asText().isBlank()) return null;
        return node.asText();
    }

    void validatePurviewUri(URI uri) {
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null
                || !host.endsWith(".purview.azure.com")) {
            throw new IllegalArgumentException("Azure Purview endpoint is not allowed");
        }
    }

    private String bearerToken(TokenCredential credential) {
        AccessToken token = credential.getToken(new TokenRequestContext().addScopes(PURVIEW_SCOPE))
                .block(Duration.ofSeconds(30));
        if (token == null || token.getToken() == null || token.getToken().isBlank()) {
            throw new IllegalStateException("Unable to acquire Azure Purview token");
        }
        return token.getToken();
    }

    private PiiLookupResult unknown() {
        return new PiiLookupResult("UNKNOWN", "AZURE_PURVIEW", List.of(), 0, null);
    }

    private PiiLookupResult notScanned() {
        return new PiiLookupResult("NOT_SCANNED", "AZURE_PURVIEW", List.of(), 0, null);
    }

    private PiiLookupResult lookupFailed() {
        return new PiiLookupResult("LOOKUP_FAILED", "AZURE_PURVIEW", List.of(), 0, null);
    }

    public record PiiLookupResult(
            String status,
            String source,
            List<String> infoTypes,
            int findingCount,
            Instant lastScannedAt
    ) {
    }
}
