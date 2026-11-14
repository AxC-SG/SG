package com.prototype.vulnwatch.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureContext;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.util.CpeUtil;
import jakarta.annotation.PostConstruct;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
public class NvdApiClient {

    public record NvdRecord(
            String cveId,
            String title,
            String description,
            Double cvssScore,
            String severity,
            String vulnStatus,
            String cvssVersion,
            String cvssVector,
            String attackVector,
            String attackComplexity,
            String privilegesRequired,
            String userInteraction,
            String scope,
            Double exploitabilityScore,
            Double impactScore,
            String cweIds,
            String referencesJson,
            String sourceIdentifier,
            Instant published,
            Instant lastModified,
            List<NvdRule> rules,
            String rawJson
    ) {
    }

    public record NvdRule(
            String ecosystem,
            String packageName,
            String versionExact,
            String versionStart,
            Boolean versionStartInclusive,
            String versionEnd,
            Boolean versionEndInclusive,
            String cpe,
            String cpeVendor,
            String cpeProduct
    ) {
    }

    public record NvdPage(
            List<NvdRecord> records,
            int totalResults,
            int startIndex,
            int resultsPerPage
    ) {
    }

    public record NvdQueryFilters(
            String cpeName,
            boolean isVulnerable,
            boolean hasKev,
            String cvssV3Severity,
            String cvssV4Severity
    ) {
    }

    private record CvssSelection(
            JsonNode metric,
            JsonNode cvssData,
            String fallbackSeverity
    ) {
    }

    private static final DateTimeFormatter REQUEST_TIME_FORMATTER = DateTimeFormatter
            .ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")
            .withZone(ZoneOffset.UTC);

    private static final String NVD_DEFAULT_TITLE = "NVD Vulnerability";

    private final ObjectMapper objectMapper;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;

    @Value("${app.nvd.base-url}")
    private String baseUrl;

    @Value("${app.nvd.api-key:}")
    private String apiKey;

    @Value("${app.nvd.api-key-file:}")
    private String apiKeyFile;

    @Value("${app.nvd.results-per-page:2000}")
    private int resultsPerPage;

    @Value("${app.nvd.min-request-interval-ms:700}")
    private long minRequestIntervalMs;

    @Value("${app.nvd.max-retries:5}")
    private int maxRetries;

    @Value("${app.nvd.retry-base-backoff-ms:1000}")
    private long retryBaseBackoffMs;

    private String resolvedApiKey = "";

    public NvdApiClient(
            ObjectMapper objectMapper,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory
    ) {
        this.objectMapper = objectMapper;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
    }

    @PostConstruct
    public void init() {
        this.resolvedApiKey = resolveApiKey();
    }

    public boolean hasApiKey() {
        return hasApiKey(null);
    }

    public boolean hasApiKey(String apiKeyOverride) {
        return !resolveRequestApiKey(apiKeyOverride).isBlank();
    }

    public int resultsPerPage() {
        return Math.max(100, Math.min(2000, resultsPerPage));
    }

    public NvdPage fetchPage(int startIndex, Instant startInclusive, Instant endExclusive) {
        return fetchPage(startIndex, startInclusive, endExclusive, null, null);
    }

    public NvdPage fetchPage(int startIndex, Instant startInclusive, Instant endExclusive, String apiKeyOverride) {
        return fetchPage(startIndex, startInclusive, endExclusive, null, apiKeyOverride);
    }

    public NvdPage fetchPage(
            int startIndex,
            Instant startInclusive,
            Instant endExclusive,
            NvdQueryFilters filters,
            String apiKeyOverride
    ) {
        String uri = buildUri(startIndex, startInclusive, endExclusive, filters);
        String body = fetchRaw(uri, apiKeyOverride);
        return parsePage(body, startIndex);
    }

    /** Fetch a single CVE by ID directly from NVD API (no date-range restriction). */
    public NvdRecord fetchSingleCve(String cveId) {
        String uri = UriComponentsBuilder.fromUriString(baseUrl)
                .queryParam("cveId", cveId.trim().toUpperCase(Locale.ROOT))
                .build().toUriString();
        String body = fetchRaw(uri, null);
        NvdPage page = parsePage(body, 0);
        return page.records().isEmpty() ? null : page.records().get(0);
    }

    private String buildUri(int startIndex, Instant startInclusive, Instant endExclusive, NvdQueryFilters filters) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(baseUrl)
                .queryParam("startIndex", Math.max(0, startIndex))
                .queryParam("resultsPerPage", resultsPerPage());

        if (startInclusive != null) {
            builder.queryParam("lastModStartDate", REQUEST_TIME_FORMATTER.format(startInclusive));
        }
        if (endExclusive != null) {
            builder.queryParam("lastModEndDate", REQUEST_TIME_FORMATTER.format(endExclusive));
        }
        if (filters != null) {
            if (hasText(filters.cpeName())) {
                builder.queryParam("cpeName", filters.cpeName().trim());
            }
            if (filters.isVulnerable()) {
                builder.queryParam("isVulnerable");
            }
            if (filters.hasKev()) {
                builder.queryParam("hasKev");
            }
            if (hasText(filters.cvssV3Severity())) {
                builder.queryParam("cvssV3Severity", filters.cvssV3Severity().trim());
            }
            if (hasText(filters.cvssV4Severity())) {
                builder.queryParam("cvssV4Severity", filters.cvssV4Severity().trim());
            }
        }
        return builder.build().toUriString();
    }

    private String fetchRaw(String uri, String apiKeyOverride) {
        String requestApiKey = resolveRequestApiKey(apiKeyOverride);
        HttpHeaders headers = new HttpHeaders();
        if (!requestApiKey.isBlank()) {
            headers.add("apiKey", requestApiKey);
        }
        return outboundHttpClient.execute(
                uri,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class,
                "NVD API request",
                outboundPolicy(),
                this::classifyFailure,
                response -> {
                    String body = response.getBody();
                    if (body == null || body.isBlank()) {
                        throw new IllegalStateException("NVD response body is empty");
                    }
                    return body;
                }
        );
    }

    private NvdPage parsePage(String body, int requestedStartIndex) {
        try {
            JsonNode root = objectMapper.readTree(body);
            JsonNode vulnerabilities = root.path("vulnerabilities");
            List<NvdRecord> records = new ArrayList<>();
            if (vulnerabilities.isArray()) {
                for (JsonNode wrapper : vulnerabilities) {
                    JsonNode cve = wrapper.path("cve");
                    if (!cve.isMissingNode() && !cve.isNull()) {
                        records.add(parseRecord(cve));
                    }
                }
            }

            int total = root.path("totalResults").asInt(0);
            int startIndex = root.path("startIndex").asInt(requestedStartIndex);
            int pageSize = root.path("resultsPerPage").asInt(resultsPerPage());
            return new NvdPage(records, total, startIndex, pageSize);
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse NVD response", e);
        }
    }

    private NvdRecord parseRecord(JsonNode cve) {
        String cveId = cve.path("id").asText("");
        String title = cveId.isBlank() ? NVD_DEFAULT_TITLE : cveId;
        String description = pickEnglish(cve.path("descriptions"), "value");

        CvssSelection selection = selectBestCvssMetric(cve.path("metrics"));
        JsonNode cvssData = selection.cvssData();
        JsonNode metric = selection.metric();
        Double cvss = cvssData != null && cvssData.has("baseScore")
                ? cvssData.path("baseScore").asDouble()
                : null;
        String severity = "UNKNOWN";
        if (cvssData != null && cvssData.has("baseSeverity")) {
            severity = cvssData.path("baseSeverity").asText("UNKNOWN");
        } else if (selection.fallbackSeverity() != null) {
            severity = selection.fallbackSeverity();
        }

        Instant published = parseInstant(cve.path("published").asText(null));
        Instant modified = parseInstant(cve.path("lastModified").asText(null));
        String vulnStatus = textOrNull(cve.path("vulnStatus"));
        String sourceIdentifier = textOrNull(cve.path("sourceIdentifier"));
        String cweIds = extractCweIds(cve.path("weaknesses"));
        String referencesJson = extractReferencesJson(cve.path("references"));

        List<NvdRule> rules = new ArrayList<>();
        for (JsonNode config : cve.path("configurations")) {
            for (JsonNode node : config.path("nodes")) {
                collectRules(node, rules);
            }
        }

        return new NvdRecord(
                cveId,
                title,
                description,
                cvss,
                severity == null ? "UNKNOWN" : severity.toUpperCase(Locale.ROOT),
                normalizeUpper(vulnStatus),
                textOrNull(cvssData == null ? null : cvssData.path("version")),
                textOrNull(cvssData == null ? null : cvssData.path("vectorString")),
                textOrNull(cvssData == null ? null : cvssData.path("attackVector")),
                textOrNull(cvssData == null ? null : cvssData.path("attackComplexity")),
                textOrNull(cvssData == null ? null : cvssData.path("privilegesRequired")),
                textOrNull(cvssData == null ? null : cvssData.path("userInteraction")),
                textOrNull(cvssData == null ? null : cvssData.path("scope")),
                metric == null ? null : numericOrNull(metric.path("exploitabilityScore")),
                metric == null ? null : numericOrNull(metric.path("impactScore")),
                cweIds,
                referencesJson,
                sourceIdentifier,
                published,
                modified,
                rules,
                cve.toString());
    }

    private CvssSelection selectBestCvssMetric(JsonNode metrics) {
        CvssSelection v40 = firstMetric(metrics.path("cvssMetricV40"));
        if (v40 != null) {
            return v40;
        }
        CvssSelection v31 = firstMetric(metrics.path("cvssMetricV31"));
        if (v31 != null) {
            return v31;
        }
        CvssSelection v30 = firstMetric(metrics.path("cvssMetricV30"));
        if (v30 != null) {
            return v30;
        }
        CvssSelection v2 = firstMetric(metrics.path("cvssMetricV2"));
        if (v2 != null) {
            return v2;
        }
        return new CvssSelection(null, null, null);
    }

    private CvssSelection firstMetric(JsonNode metricArray) {
        if (!metricArray.isArray() || metricArray.isEmpty()) {
            return null;
        }
        JsonNode metric = metricArray.get(0);
        JsonNode cvssData = metric.path("cvssData");
        if (cvssData.isMissingNode() || cvssData.isNull()) {
            return null;
        }
        String fallbackSeverity = textOrNull(metric.path("baseSeverity"));
        return new CvssSelection(metric, cvssData, fallbackSeverity);
    }

    private void collectRules(JsonNode node, List<NvdRule> rules) {
        for (JsonNode match : node.path("cpeMatch")) {
            boolean vulnerable = !match.has("vulnerable") || match.path("vulnerable").asBoolean();
            if (!vulnerable) {
                continue;
            }

            String cpe = match.path("criteria").asText("");
            CpeUtil.ParsedCpe parsedCpe = CpeUtil.parse(cpe);
            String packageName = parsedCpe.product();
            if (packageName.isBlank()) {
                continue;
            }

            String exactVersion = parsedCpe.version();
            if (exactVersion.isBlank()) {
                exactVersion = null;
            }

            String start = textOrNull(match.path("versionStartIncluding"));
            Boolean startInclusive = null;
            if (start == null) {
                start = textOrNull(match.path("versionStartExcluding"));
                if (start != null) {
                    startInclusive = false;
                }
            } else {
                startInclusive = true;
            }

            String end = textOrNull(match.path("versionEndIncluding"));
            Boolean endInclusive = null;
            if (end == null) {
                end = textOrNull(match.path("versionEndExcluding"));
                if (end != null) {
                    endInclusive = false;
                }
            } else {
                endInclusive = true;
            }

            if (start != null || end != null) {
                exactVersion = null;
            }

            rules.add(new NvdRule(
                    "generic",
                    packageName,
                    exactVersion,
                    start,
                    startInclusive,
                    end,
                    endInclusive,
                    cpe,
                    parsedCpe.vendor(),
                    parsedCpe.product()));
        }

        for (JsonNode child : node.path("children")) {
            collectRules(child, rules);
        }
    }

    private String extractCweIds(JsonNode weaknesses) {
        Set<String> cwes = new LinkedHashSet<>();
        if (!weaknesses.isArray()) {
            return null;
        }
        for (JsonNode weakness : weaknesses) {
            JsonNode descriptions = weakness.path("description");
            if (!descriptions.isArray()) {
                continue;
            }
            for (JsonNode desc : descriptions) {
                String value = desc.path("value").asText("");
                if (!value.isBlank() && value.toUpperCase(Locale.ROOT).startsWith("CWE-")) {
                    cwes.add(value.toUpperCase(Locale.ROOT));
                }
            }
        }
        if (cwes.isEmpty()) {
            return null;
        }
        return String.join(",", cwes);
    }

    private String extractReferencesJson(JsonNode references) {
        if (!references.isArray() || references.isEmpty()) {
            return null;
        }
        List<java.util.Map<String, Object>> refObjects = new ArrayList<>();
        for (JsonNode ref : references) {
            String url = textOrNull(ref.path("url"));
            if (url == null) {
                continue;
            }
            java.util.Map<String, Object> entry = new java.util.LinkedHashMap<>();
            entry.put("url", url);
            String source = textOrNull(ref.path("source"));
            if (source != null) {
                entry.put("source", source);
            }
            JsonNode tagsNode = ref.path("tags");
            if (tagsNode.isArray() && !tagsNode.isEmpty()) {
                List<String> tags = new ArrayList<>();
                for (JsonNode tag : tagsNode) {
                    String t = tag.asText(null);
                    if (t != null && !t.isBlank()) {
                        tags.add(t);
                    }
                }
                if (!tags.isEmpty()) {
                    entry.put("tags", tags);
                }
            }
            refObjects.add(entry);
        }
        if (refObjects.isEmpty()) {
            return null;
        }
        try {
            return objectMapper.writeValueAsString(refObjects);
        } catch (Exception e) {
            return null;
        }
    }

    private String pickEnglish(JsonNode items, String valueField) {
        if (!items.isArray()) {
            return "";
        }
        for (JsonNode item : items) {
            if ("en".equalsIgnoreCase(item.path("lang").asText(""))) {
                return item.path(valueField).asText("");
            }
        }
        return items.isEmpty() ? "" : items.get(0).path(valueField).asText("");
    }

    private Double numericOrNull(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        if (!node.isNumber()) {
            return null;
        }
        return node.asDouble();
    }

    private String textOrNull(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        String value = node.asText("");
        return value.isBlank() ? null : value.trim();
    }

    private String normalizeUpper(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim().toUpperCase(Locale.ROOT);
    }

    private Instant parseInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            // NVD returns dates as "2024-01-09T18:15:45.917" — no zone suffix
            return LocalDateTime.parse(value).toInstant(ZoneOffset.UTC);
        } catch (Exception ignored) {
        }
        try {
            return Instant.parse(value);
        } catch (Exception ignored) {
            return null;
        }
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("nvd", minRequestIntervalMs, maxRetries, retryBaseBackoffMs);
    }

    private OutboundFailureDecision<RuntimeException> classifyFailure(OutboundFailureContext context) {
        Integer statusCode = context.statusCodeValue();
        if (statusCode != null) {
            RuntimeException terminal = new RuntimeException("NVD request failed with status " + statusCode, context.error());
            return new OutboundFailureDecision<>(
                    context.isRetryableByDefault(),
                    context.retryAfterDelayMs(),
                    terminal
            );
        }
        return new OutboundFailureDecision<>(
                true,
                null,
                new RuntimeException("Failed to fetch NVD response after retries", context.error())
        );
    }

    private String resolveApiKey() {
        String fileValue = readApiKeyFromFile(apiKeyFile);
        if (!fileValue.isBlank()) {
            return fileValue;
        }
        return apiKey == null ? "" : apiKey.trim();
    }

    private boolean hasText(String value) {
        return value != null && !value.trim().isEmpty();
    }

    private String resolveRequestApiKey(String apiKeyOverride) {
        if (apiKeyOverride != null && !apiKeyOverride.isBlank()) {
            return apiKeyOverride.trim();
        }
        return resolvedApiKey == null ? "" : resolvedApiKey.trim();
    }

    private String readApiKeyFromFile(String pathValue) {
        if (pathValue == null || pathValue.isBlank()) {
            return "";
        }
        try {
            String content = Files.readString(Path.of(pathValue.trim()));
            return content == null ? "" : content.trim();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to read NVD API key file", e);
        }
    }
}
