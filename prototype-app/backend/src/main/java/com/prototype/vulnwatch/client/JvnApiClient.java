package com.prototype.vulnwatch.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureContext;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * Client for the JVN Vulnerability Database (JVNdb) MyJVN API v3.3.
 * Endpoint: https://jvndb.jvn.jp/myjvn?method=getVulnOverviewList&version=3.3&feed=hnd
 * Response: RDF/RSS 1.0 with sec:, dc:, dcterms: namespaces.
 */
@Component
public class JvnApiClient {

    public record JvnRecord(
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
            String rawJson
    ) {}

    public record JvnPage(
            List<JvnRecord> records,
            int totalResults,
            int startItem,
            int maxCountItem
    ) {}

    private final ObjectMapper objectMapper;
    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;

    @Value("${app.jvn.api-url:https://jvndb.jvn.jp/myjvn}")
    private String apiUrl;

    @Value("${app.jvn.per-page:50}")
    private int perPage;

    @Value("${app.jvn.min-request-interval-ms:${app.http.outbound.min-request-interval-ms:200}}")
    private long minRequestIntervalMs;

    @Value("${app.jvn.max-retries:${app.http.outbound.max-retries:3}}")
    private int maxRetries;

    @Value("${app.jvn.retry-base-backoff-ms:${app.http.outbound.retry-base-backoff-ms:500}}")
    private long retryBaseBackoffMs;

    public JvnApiClient(
            ObjectMapper objectMapper,
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory
    ) {
        this.objectMapper = objectMapper;
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
    }

    public int perPage() {
        return Math.max(1, Math.min(50, perPage));
    }

    /**
     * Fetches one page from the JVN MyJVN API.
     * @param startItem 1-based start index (JVN convention)
     */
    public JvnPage fetchPage(int startItem) {
        int safeStart = Math.max(1, startItem);
        String uri = UriComponentsBuilder.fromUriString(apiUrl)
                .queryParam("method", "getVulnOverviewList")
                .queryParam("version", "3.3")
                .queryParam("lang", "en")
                .queryParam("feed", "hnd")
                .queryParam("startItem", safeStart)
                .queryParam("maxCountItem", perPage())
                .build()
                .toUriString();
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_XML, MediaType.TEXT_XML, MediaType.ALL));
        headers.set("User-Agent", "VulnWatch/1.0");
        String body = outboundHttpClient.execute(
                uri,
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class,
                "JVN API request",
                outboundPolicy(),
                this::classifyFailure,
                response -> response.getBody() == null ? "" : response.getBody()
        );
        return parsePage(body, safeStart);
    }

    private JvnPage parsePage(String body, int startItem) {
        if (body == null || body.isBlank()) {
            return new JvnPage(List.of(), 0, startItem, perPage());
        }
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setNamespaceAware(true);
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
            doc.getDocumentElement().normalize();

            // Parse pagination from <status:Status totalRes="..." totalResRet="..." .../>
            int totalResults = parseStatusTotalRes(doc);

            List<JvnRecord> records = new ArrayList<>();
            // RDF feed uses <item> (RSS 1.0), not <entry> (Atom)
            NodeList items = doc.getElementsByTagNameNS("*", "item");
            for (int i = 0; i < items.getLength(); i++) {
                JvnRecord record = parseItem((Element) items.item(i));
                if (record != null) {
                    records.add(record);
                }
            }
            if (totalResults == 0) {
                totalResults = records.size();
            }
            return new JvnPage(records, totalResults, startItem, perPage());
        } catch (Exception e) {
            throw new RuntimeException("Failed to parse JVN response", e);
        }
    }

    private int parseStatusTotalRes(Document doc) {
        // <status:Status totalRes="200" totalResRet="50" firstRes="1" .../>
        NodeList statusNodes = doc.getElementsByTagNameNS("*", "Status");
        if (statusNodes.getLength() > 0) {
            Element status = (Element) statusNodes.item(0);
            String total = status.getAttribute("totalRes");
            if (total != null && !total.isBlank()) {
                try {
                    return Integer.parseInt(total.trim());
                } catch (NumberFormatException ignored) {
                }
            }
        }
        return 0;
    }

    private JvnRecord parseItem(Element item) {
        // JVNDB ID is in <sec:identifier>JVNDB-2026-000072</sec:identifier>
        String sourceRecordId = textContentNs(item, "identifier");
        if (sourceRecordId == null || !sourceRecordId.toUpperCase(Locale.ROOT).startsWith("JVNDB")) {
            return null;
        }
        sourceRecordId = sourceRecordId.trim().toUpperCase(Locale.ROOT);

        String title = textContentNs(item, "title");
        String description = textContentNs(item, "description");

        // <link> is a text element in RDF (not an href attribute)
        String sourceUrl = textContentNs(item, "link");
        if (sourceUrl == null || sourceUrl.isBlank()) {
            // Fallback: build from JVNDB ID (JVNDB-YYYY-NNNNNN → /YYYY/JVNDB-YYYY-NNNNNN.html)
            String[] parts = sourceRecordId.split("-");
            sourceUrl = parts.length >= 2
                    ? "https://jvndb.jvn.jp/en/contents/" + parts[1] + "/" + sourceRecordId + ".html"
                    : "https://jvndb.jvn.jp/en/";
        }

        // CVE IDs from <sec:references source="CVE" id="CVE-2026-32661">
        String externalId = extractCveIdFromReferences(item);
        if (externalId == null) {
            externalId = sourceRecordId;
        }

        // CVSS from <sec:cvss score="9.8" severity="Critical" vector="..." version="3.0" type="Base"/>
        Double cvssScore = null;
        String cvssVector = null;
        String severity = null;

        NodeList cvssNodes = item.getElementsByTagNameNS("*", "cvss");
        // Prefer CVSS v3 over v2
        for (String preferVersion : List.of("3", "2")) {
            for (int i = 0; i < cvssNodes.getLength(); i++) {
                Element cvssEl = (Element) cvssNodes.item(i);
                String ver = cvssEl.getAttribute("version");
                if (ver == null || !ver.startsWith(preferVersion)) {
                    continue;
                }
                String score = cvssEl.getAttribute("score");
                if (score != null && !score.isBlank()) {
                    try {
                        cvssScore = Double.parseDouble(score.trim());
                    } catch (NumberFormatException ignored) {
                    }
                }
                String vector = cvssEl.getAttribute("vector");
                if (vector != null && !vector.isBlank()) {
                    cvssVector = vector.trim();
                }
                String sev = cvssEl.getAttribute("severity");
                if (sev != null && !sev.isBlank()) {
                    severity = sev.trim().toUpperCase(Locale.ROOT);
                }
                break;
            }
            if (cvssScore != null) {
                break;
            }
        }
        if (severity == null) {
            severity = severityFromCvss(cvssScore);
        }

        // Dates: <dcterms:issued> for publishedAt, <dcterms:modified> or <dc:date> for lastModifiedAt
        Instant publishedAt = parseInstant(textContentNs(item, "issued"));
        Instant lastModifiedAt = parseInstant(textContentNs(item, "modified"));
        if (lastModifiedAt == null) {
            lastModifiedAt = parseInstant(textContentNs(item, "date"));
        }

        String rawJson = buildRawJson(sourceRecordId, title, description, cvssScore, cvssVector, severity, sourceUrl);
        return new JvnRecord(
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
                rawJson
        );
    }

    /**
     * Extracts the first CVE ID from {@code <sec:references source="CVE" id="CVE-...">} elements.
     */
    private String extractCveIdFromReferences(Element item) {
        NodeList refs = item.getElementsByTagNameNS("*", "references");
        // Collect all CVE refs; return the first
        Set<String> cveIds = new LinkedHashSet<>();
        for (int i = 0; i < refs.getLength(); i++) {
            Node ref = refs.item(i);
            if (ref.getNodeType() != Node.ELEMENT_NODE) {
                continue;
            }
            NamedNodeMap attrs = ref.getAttributes();
            Node sourceAttr = attrs.getNamedItem("source");
            Node idAttr = attrs.getNamedItem("id");
            if (sourceAttr != null && "CVE".equalsIgnoreCase(sourceAttr.getNodeValue())
                    && idAttr != null) {
                String cveId = idAttr.getNodeValue();
                if (cveId != null && cveId.toUpperCase(Locale.ROOT).startsWith("CVE-")) {
                    cveIds.add(cveId.toUpperCase(Locale.ROOT));
                }
            }
        }
        return cveIds.isEmpty() ? null : cveIds.iterator().next();
    }

    /** Returns text content of the first element matching localName in any namespace. */
    private String textContentNs(Element parent, String localName) {
        NodeList nodes = parent.getElementsByTagNameNS("*", localName);
        if (nodes.getLength() == 0) {
            nodes = parent.getElementsByTagName(localName);
        }
        if (nodes.getLength() > 0) {
            String text = nodes.item(0).getTextContent();
            if (text != null && !text.isBlank()) {
                return text.trim();
            }
        }
        return null;
    }

    private Instant parseInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        // JVN dates are ISO 8601 with timezone offset, e.g. 2026-05-15T15:37:27+09:00
        try {
            return OffsetDateTime.parse(value).toInstant();
        } catch (Exception ignored) {
        }
        try {
            return Instant.parse(value);
        } catch (Exception ignored) {
        }
        return null;
    }

    private String severityFromCvss(Double cvss) {
        if (cvss == null) return "UNKNOWN";
        if (cvss >= 9.0) return "CRITICAL";
        if (cvss >= 7.0) return "HIGH";
        if (cvss >= 4.0) return "MEDIUM";
        if (cvss > 0.0) return "LOW";
        return "UNKNOWN";
    }

    private String buildRawJson(String id, String title, String description,
            Double cvssScore, String cvssVector, String severity, String url) {
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("id", id);
        if (title != null) map.put("title", title);
        if (description != null) map.put("description", description);
        if (cvssScore != null) map.put("cvssScore", cvssScore);
        if (cvssVector != null) map.put("cvssVector", cvssVector);
        if (severity != null) map.put("severity", severity);
        if (url != null) map.put("url", url);
        try {
            return objectMapper.writeValueAsString(map);
        } catch (Exception e) {
            return "{}";
        }
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("jvn", minRequestIntervalMs, maxRetries, retryBaseBackoffMs);
    }

    private OutboundFailureDecision<RuntimeException> classifyFailure(OutboundFailureContext context) {
        Integer statusCode = context.statusCodeValue();
        if (statusCode != null) {
            return new OutboundFailureDecision<>(
                    context.isRetryableByDefault(),
                    context.retryAfterDelayMs(),
                    new RuntimeException("JVN request failed with status " + statusCode, context.error())
            );
        }
        return new OutboundFailureDecision<>(
                true,
                null,
                new RuntimeException("Failed to fetch JVN response after retries", context.error())
        );
    }
}
