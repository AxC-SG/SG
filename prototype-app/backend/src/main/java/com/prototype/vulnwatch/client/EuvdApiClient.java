package com.prototype.vulnwatch.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureContext;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class EuvdApiClient {

    public record EuvdRecord(
            String sourceRecordId,
            String externalId,
            String title,
            String description,
            String severity,
            Double cvssScore,
            String cvssVector,
            Instant publishedAt,
            Instant lastModifiedAt,
            String sourceUrl,
            String referencesJson,
            String rawJson
    ) {
    }

    public record EuvdPage(
            List<EuvdRecord> records,
            int totalResults,
            int pageNumber,
            int pageSize
    ) {
    }

    private static final Pattern CVE_PATTERN = Pattern.compile("\\bCVE-\\d{4}-\\d{4,}\\b", Pattern.CASE_INSENSITIVE);

    private final ObjectMapper objectMapper;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;

    @Value("${app.euvd.api-url:https://euvdservices.enisa.europa.eu/api/search}")
    private String apiUrl;

    @Value("${app.euvd.per-page:100}")
    private int perPage;

    @Value("${app.euvd.min-request-interval-ms:${app.http.outbound.min-request-interval-ms:0}}")
    private long minRequestIntervalMs;

    @Value("${app.euvd.max-retries:${app.http.outbound.max-retries:3}}")
    private int maxRetries;

    @Value("${app.euvd.retry-base-backoff-ms:${app.http.outbound.retry-base-backoff-ms:500}}")
    private long retryBaseBackoffMs;

    public EuvdApiClient(
            ObjectMapper objectMapper,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory
    ) {
        this.objectMapper = objectMapper;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
    }

    public int perPage() {
        return Math.max(1, Math.min(500, perPage));
    }

    public EuvdPage fetchPage(int pageNumber) {
        int safePage = Math.max(0, pageNumber);
        String uri = UriComponentsBuilder.fromUriString(apiUrl)
                .queryParam("fromScore", 0)
                .queryParam("toScore", 10)
                .queryParam("page", safePage)
                .queryParam("size", perPage())
                .build()
                .toUriString();
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN, MediaType.ALL));
        headers.set("User-Agent", "Mozilla/5.0 (compatible; VulnWatch/1.0; +https://euvd.enisa.europa.eu)");
        headers.set("Accept-Language", "en-US,en;q=0.9");
        headers.set("Origin", "https://euvd.enisa.europa.eu");
        headers.set("Referer", "https://euvd.enisa.europa.eu/apidoc");
        String body = outboundHttpClient.execute(
                uri,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class,
                "EUVD API request",
                outboundPolicy(),
                this::classifyFailure,
                response -> response.getBody() == null ? "" : response.getBody()
        );
        return parsePage(body, safePage);
    }

    private EuvdPage parsePage(String body, int requestedPage) {
        try {
            JsonNode root = objectMapper.readTree(body == null || body.isBlank() ? "{}" : body);
            JsonNode recordsNode = locateRecordsNode(root);
            List<EuvdRecord> records = new ArrayList<>();
            if (recordsNode != null && recordsNode.isArray()) {
                for (JsonNode recordNode : recordsNode) {
                    records.add(parseRecord(recordNode));
                }
            }
            int total = intValue(root, "total", "totalResults", "totalElements", "count");
            if (total <= 0) {
                total = records.size();
            }
            int pageNumber = intValue(root, "page", "pageNumber", "number");
            if (pageNumber < 0) {
                pageNumber = requestedPage;
            }
            int pageSize = intValue(root, "size", "pageSize", "perPage", "limit");
            if (pageSize <= 0) {
                pageSize = perPage();
            }
            return new EuvdPage(records, total, pageNumber, pageSize);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse EUVD response", e);
        }
    }

    private JsonNode locateRecordsNode(JsonNode root) {
        if (root == null || root.isNull()) {
            return null;
        }
        if (root.isArray()) {
            return root;
        }
        for (String candidate : List.of("items", "vulnerabilities", "results", "data", "content", "records")) {
            JsonNode node = root.path(candidate);
            if (node.isArray()) {
                return node;
            }
        }
        return null;
    }

    private EuvdRecord parseRecord(JsonNode recordNode) {
        String sourceRecordId = firstText(recordNode,
                "id",
                "euvdId",
                "euvd_id",
                "recordId",
                "record_id",
                "vulnId",
                "vuln_id",
                "identifier",
                "uuid"
        );
        if (sourceRecordId == null) {
            sourceRecordId = firstTextFromNested(recordNode, "metadata", "id");
        }
        if (sourceRecordId == null) {
            sourceRecordId = "EUVD-" + Integer.toHexString(recordNode.hashCode());
        }

        String rawJson = recordNode.toString();
        Set<String> cveIds = extractCveIds(rawJson);
        String externalId = cveIds.isEmpty() ? sourceRecordId : cveIds.iterator().next();
        String title = firstText(recordNode, "title", "name", "summary", "vulnerabilityName");
        if (title == null) {
            title = externalId;
        }
        String description = firstText(recordNode, "description", "details", "summary", "problemDescription");
        String severity = normalizeUpper(firstText(recordNode, "severity", "baseSeverity", "risk", "rating"));
        Double cvssScore = firstDouble(recordNode,
                "cvssScore",
                "baseScore",
                "score",
                "cvss",
                "cvss_v3_score",
                "cvssv3score"
        );
        String cvssVector = firstText(recordNode, "cvssVector", "vectorString", "vector", "cvss_v3_vector");
        if (severity == null) {
            severity = severityFromCvss(cvssScore);
        }
        Instant publishedAt = firstInstant(recordNode,
                "published",
                "publishedAt",
                "datePublished",
                "createdAt",
                "releaseDate"
        );
        Instant lastModifiedAt = firstInstant(recordNode,
                "lastModified",
                "lastModifiedAt",
                "modified",
                "modifiedAt",
                "updatedAt",
                "dateUpdated"
        );
        String sourceUrl = firstText(recordNode, "url", "sourceUrl", "detailUrl", "selfUrl", "link");
        if (sourceUrl == null) {
            sourceUrl = apiUrl + "/" + sourceRecordId;
        }
        String referencesJson = extractReferencesJson(recordNode);
        return new EuvdRecord(
                sourceRecordId,
                externalId,
                title,
                description,
                severity,
                cvssScore,
                cvssVector,
                publishedAt,
                lastModifiedAt,
                sourceUrl,
                referencesJson,
                rawJson
        );
    }

    private String extractReferencesJson(JsonNode recordNode) {
        JsonNode references = firstArray(recordNode,
                "references",
                "refs",
                "referencesList",
                "externalReferences",
                "links"
        );
        if (references == null || references.isEmpty()) {
            return null;
        }
        List<java.util.Map<String, Object>> items = new ArrayList<>();
        for (JsonNode reference : references) {
            String url = firstText(reference, "url", "href", "link", "reference");
            if (url == null) {
                continue;
            }
            java.util.Map<String, Object> item = new java.util.LinkedHashMap<>();
            item.put("url", url);
            String name = firstText(reference, "name", "title", "source", "type");
            if (name != null) {
                item.put("name", name);
            }
            items.add(item);
        }
        if (items.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(items);
        } catch (Exception e) {
            return null;
        }
    }

    private JsonNode firstArray(JsonNode node, String... names) {
        if (node == null || node.isNull()) {
            return null;
        }
        for (String name : names) {
            JsonNode candidate = node.path(name);
            if (candidate.isArray()) {
                return candidate;
            }
        }
        return null;
    }

    private String firstText(JsonNode node, String... names) {
        if (node == null || node.isNull()) {
            return null;
        }
        for (String name : names) {
            JsonNode candidate = node.path(name);
            if (!candidate.isMissingNode() && !candidate.isNull()) {
                String value = candidate.asText(null);
                if (value != null && !value.isBlank()) {
                    return value.trim();
                }
            }
        }
        return null;
    }

    private String firstTextFromNested(JsonNode node, String parent, String child) {
        if (node == null || node.isNull()) {
            return null;
        }
        JsonNode parentNode = node.path(parent);
        if (parentNode == null || parentNode.isMissingNode() || parentNode.isNull()) {
            return null;
        }
        return firstText(parentNode, child);
    }

    private Double firstDouble(JsonNode node, String... names) {
        if (node == null || node.isNull()) {
            return null;
        }
        for (String name : names) {
            JsonNode candidate = node.path(name);
            if (candidate.isNumber()) {
                return candidate.asDouble();
            }
            if (candidate.isTextual()) {
                try {
                    return Double.parseDouble(candidate.asText());
                } catch (Exception ignored) {
                }
            }
        }
        return null;
    }

    private Instant firstInstant(JsonNode node, String... names) {
        String value = firstText(node, names);
        if (value == null) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (Exception ignored) {
        }
        try {
            return LocalDateTime.parse(value).toInstant(ZoneOffset.UTC);
        } catch (Exception ignored) {
        }
        return null;
    }

    private String severityFromCvss(Double cvss) {
        if (cvss == null) {
            return "UNKNOWN";
        }
        if (cvss >= 9.0d) {
            return "CRITICAL";
        }
        if (cvss >= 7.0d) {
            return "HIGH";
        }
        if (cvss >= 4.0d) {
            return "MEDIUM";
        }
        if (cvss > 0.0d) {
            return "LOW";
        }
        return "UNKNOWN";
    }

    private int intValue(JsonNode node, String... names) {
        if (node == null || node.isNull()) {
            return -1;
        }
        for (String name : names) {
            JsonNode candidate = node.path(name);
            if (candidate.isNumber()) {
                return candidate.asInt();
            }
            if (candidate.isTextual()) {
                try {
                    return Integer.parseInt(candidate.asText().trim());
                } catch (Exception ignored) {
                }
            }
        }
        return -1;
    }

    private Set<String> extractCveIds(String rawJson) {
        LinkedHashSet<String> cveIds = new LinkedHashSet<>();
        if (rawJson == null || rawJson.isBlank()) {
            return cveIds;
        }
        Matcher matcher = CVE_PATTERN.matcher(rawJson);
        while (matcher.find()) {
            String value = matcher.group();
            if (value != null && !value.isBlank()) {
                cveIds.add(value.toUpperCase(Locale.ROOT));
            }
        }
        return cveIds;
    }

    private String normalizeUpper(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim().toUpperCase(Locale.ROOT);
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("euvd", minRequestIntervalMs, maxRetries, retryBaseBackoffMs);
    }

    private OutboundFailureDecision<RuntimeException> classifyFailure(OutboundFailureContext context) {
        Integer statusCode = context.statusCodeValue();
        if (statusCode != null) {
            return new OutboundFailureDecision<>(
                    context.isRetryableByDefault(),
                    context.retryAfterDelayMs(),
                    new RuntimeException("EUVD request failed with status " + statusCode, context.error())
            );
        }
        return new OutboundFailureDecision<>(
                true,
                null,
                new RuntimeException("Failed to fetch EUVD response after retries", context.error())
        );
    }
}
