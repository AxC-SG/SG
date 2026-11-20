package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;

@Service
public class CsafDiscoveryService {

    private static final Logger LOG = LoggerFactory.getLogger(CsafDiscoveryService.class);
    private static final String MICROSOFT_CSAF_PROVIDER_METADATA_URL = "https://msrc.microsoft.com/csaf/provider-metadata.json";
    private static final String MICROSOFT_CSAF_ADVISORIES_DISTRIBUTION_URL = "https://msrc.microsoft.com/csaf/advisories";
    private static final String MICROSOFT_CSAF_VEX_DISTRIBUTION_URL = "https://msrc.microsoft.com/csaf/vex";
    private static final String REDHAT_CSAF_PROVIDER_METADATA_URL = "https://security.access.redhat.com/data/csaf/v2/provider-metadata.json";
    private static final String REDHAT_CSAF_ADVISORIES_DISTRIBUTION_URL = "https://security.access.redhat.com/data/csaf/v2/advisories";
    private static final String REDHAT_CSAF_VEX_DISTRIBUTION_URL = "https://security.access.redhat.com/data/csaf/v2/vex";
    private static final Pattern CSV_SPLIT_PATTERN = Pattern.compile(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");

    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;
    private final VulnerabilityIngestionCommonSupport support;

    @Value("${app.csaf.microsoft.provider-metadata-url:" + MICROSOFT_CSAF_PROVIDER_METADATA_URL + "}")
    private String microsoftCsafProviderMetadataUrl;

    @Value("${app.csaf.microsoft.advisories-distribution-url:" + MICROSOFT_CSAF_ADVISORIES_DISTRIBUTION_URL + "}")
    private String microsoftCsafAdvisoriesDistributionUrl;

    @Value("${app.csaf.microsoft.vex-distribution-url:" + MICROSOFT_CSAF_VEX_DISTRIBUTION_URL + "}")
    private String microsoftCsafVexDistributionUrl;

    @Value("${app.csaf.redhat.provider-metadata-url:" + REDHAT_CSAF_PROVIDER_METADATA_URL + "}")
    private String redhatCsafProviderMetadataUrl;

    @Value("${app.csaf.redhat.advisories-distribution-url:" + REDHAT_CSAF_ADVISORIES_DISTRIBUTION_URL + "}")
    private String redhatCsafAdvisoriesDistributionUrl;

    @Value("${app.csaf.redhat.vex-distribution-url:" + REDHAT_CSAF_VEX_DISTRIBUTION_URL + "}")
    private String redhatCsafVexDistributionUrl;

    public CsafDiscoveryService(
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper,
            VulnerabilityIngestionCommonSupport support
    ) {
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
        this.support = support;
    }

    public CsafDistributionSet discoverDistributions(CsafProvider provider) {
        String metadataUrl = providerMetadataUrl(provider);
        String advisoryFallback = providerAdvisoryDistributionFallback(provider);
        String vexFallback = providerVexDistributionFallback(provider);
        try {
            String body = fetchText(metadataUrl, provider);
            JsonNode metadata = objectMapper.readTree(body == null ? "{}" : body);
            List<String> directories = new ArrayList<>();
            JsonNode distributions = metadata.path("distributions");
            if (distributions.isArray()) {
                for (JsonNode distribution : distributions) {
                    String directoryUrl = support.textValue(distribution.path("directory_url"));
                    if (support.hasText(directoryUrl)) {
                        directories.add(directoryUrl.trim());
                    }
                }
            }
            String advisory = firstMatchingDistribution(directories, false, advisoryFallback);
            String vex = firstMatchingDistribution(directories, true, vexFallback);
            return new CsafDistributionSet(advisory, vex);
        } catch (Exception e) {
            LOG.warn("CSAF provider metadata discovery failed for {}: {}", provider.providerKey(), e.getMessage());
            return new CsafDistributionSet(advisoryFallback, vexFallback);
        }
    }

    public List<CsafDocumentRef> collectDocumentRefs(CsafDistributionSet distributions, CsafProvider provider) {
        LinkedHashMap<String, CsafDocumentRef> refs = new LinkedHashMap<>();
        for (CsafDocumentRef ref : collectDocumentRefsFromRoot(distributions.advisoriesDistributionUrl(), false, provider)) {
            refs.putIfAbsent(ref.url(), ref);
        }
        for (CsafDocumentRef ref : collectDocumentRefsFromRoot(distributions.vexDistributionUrl(), true, provider)) {
            refs.putIfAbsent(ref.url(), ref);
        }

        if (refs.isEmpty()) {
            LOG.warn("No CSAF documents discovered for {}", provider.providerKey());
            return List.of();
        }

        // Preserve the insertion order from changes.csv (newest-modified first) so that
        // the per-sync document limit processes recent CVEs before older ones.
        // Previously this sorted alphabetically, which buried 2024/2025 CVEs beyond the limit.
        return new ArrayList<>(refs.values());
    }

    private List<CsafDocumentRef> collectDocumentRefsFromRoot(String distributionRoot, boolean vexProfile, CsafProvider provider) {
        if (!support.hasText(distributionRoot)) {
            return List.of();
        }
        LinkedHashSet<String> urls = new LinkedHashSet<>();
        String normalizedRoot = normalizeDistributionRoot(distributionRoot);

        if (provider == CsafProvider.REDHAT) {
            // Red Hat's changes.csv can briefly advertise documents before they are
            // published into index.txt. Filter that transient window so a refresh does
            // not spend its entire document budget on guaranteed 404s.
            LinkedHashSet<String> indexedUrls = new LinkedHashSet<>();
            appendFromTextIndex(indexedUrls, normalizedRoot + "/index.txt", normalizedRoot, provider);
            if (!indexedUrls.isEmpty()) {
                LinkedHashSet<String> changedUrls = new LinkedHashSet<>();
                appendFromCsv(changedUrls, normalizedRoot + "/changes.csv", normalizedRoot, provider);
                for (String url : changedUrls) {
                    if (indexedUrls.contains(url)) {
                        urls.add(url);
                    }
                }
                urls.addAll(indexedUrls);
            } else {
                appendFromCsv(urls, normalizedRoot + "/changes.csv", normalizedRoot, provider);
            }
        } else {
            appendFromCsv(urls, normalizedRoot + "/changes.csv", normalizedRoot, provider);
            appendFromTextIndex(urls, normalizedRoot + "/index.txt", normalizedRoot, provider);
        }
        appendFromJsonIndex(urls, normalizedRoot, normalizedRoot, provider);

        if (urls.isEmpty() && provider == CsafProvider.REDHAT) {
            appendFromTextIndex(urls, normalizedRoot + "/vex/index.txt", normalizedRoot + "/vex", provider);
            appendFromTextIndex(urls, normalizedRoot + "/advisories/index.txt", normalizedRoot + "/advisories", provider);
        }

        List<CsafDocumentRef> refs = new ArrayList<>();
        for (String url : urls) {
            refs.add(new CsafDocumentRef(url, vexProfile));
        }
        return refs;
    }

    private void appendFromCsv(Set<String> sink, String csvUrl, String distributionRoot, CsafProvider provider) {
        Optional<String> csv = fetchTextOptional(csvUrl, provider);
        if (csv.isEmpty()) {
            return;
        }
        String[] lines = csv.get().split("\\r?\\n");
        for (String line : lines) {
            if (!support.hasText(line) || line.startsWith("#")) {
                continue;
            }
            String[] columns = CSV_SPLIT_PATTERN.split(line, -1);
            for (String column : columns) {
                String candidate = resolveDistributionToken(distributionRoot, unquoteCsv(column));
                if (isCsafJsonUrl(candidate)) {
                    sink.add(candidate);
                }
            }
        }
    }

    private void appendFromTextIndex(Set<String> sink, String indexUrl, String distributionRoot, CsafProvider provider) {
        Optional<String> index = fetchTextOptional(indexUrl, provider);
        if (index.isEmpty()) {
            return;
        }
        String[] lines = index.get().split("\\r?\\n");
        for (String line : lines) {
            String candidate = resolveDistributionToken(distributionRoot, line);
            if (isCsafJsonUrl(candidate)) {
                sink.add(candidate);
            }
        }
    }

    private void appendFromJsonIndex(Set<String> sink, String indexUrl, String distributionRoot, CsafProvider provider) {
        try {
            String body = fetchText(indexUrl, provider);
            if (!support.hasText(body)) {
                return;
            }
            JsonNode node = objectMapper.readTree(body);
            appendUrlsFromJsonNode(sink, node, distributionRoot, provider);
        } catch (Exception ignored) {
            // best-effort discovery
        }
    }

    private void appendUrlsFromJsonNode(Set<String> sink, JsonNode node, String distributionRoot, CsafProvider provider) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            return;
        }
        if (node.isTextual()) {
            String candidate = resolveDistributionToken(distributionRoot, node.asText(""));
            if (isCsafJsonUrl(candidate)) {
                sink.add(candidate);
            }
            return;
        }
        if (node.isArray()) {
            for (JsonNode child : node) {
                appendUrlsFromJsonNode(sink, child, distributionRoot, provider);
            }
            return;
        }
        if (!node.isObject()) {
            return;
        }

        List<String> fields = List.of("url", "href", "documentUrl", "advisoryUrl", "advisory", "document", "name", "id");
        for (String field : fields) {
            String candidate = resolveDistributionToken(distributionRoot, support.textValue(node.path(field)));
            if (isCsafJsonUrl(candidate)) {
                sink.add(candidate);
            }
        }
        String trackingId = resolveDistributionToken(distributionRoot, support.textValue(node.path("tracking").path("id")));
        if (isCsafJsonUrl(trackingId)) {
            sink.add(trackingId);
        }

        node.fields().forEachRemaining(entry -> appendUrlsFromJsonNode(sink, entry.getValue(), distributionRoot, provider));
    }

    private String providerMetadataUrl(CsafProvider provider) {
        return provider == CsafProvider.MICROSOFT ? microsoftCsafProviderMetadataUrl : redhatCsafProviderMetadataUrl;
    }

    private String providerAdvisoryDistributionFallback(CsafProvider provider) {
        return provider == CsafProvider.MICROSOFT
                ? microsoftCsafAdvisoriesDistributionUrl
                : redhatCsafAdvisoriesDistributionUrl;
    }

    private String providerVexDistributionFallback(CsafProvider provider) {
        return provider == CsafProvider.MICROSOFT
                ? microsoftCsafVexDistributionUrl
                : redhatCsafVexDistributionUrl;
    }

    private String firstMatchingDistribution(List<String> directories, boolean vex, String fallback) {
        String token = vex ? "/vex" : "/advisories";
        for (String value : directories) {
            if (support.hasText(value) && value.toLowerCase(Locale.ROOT).contains(token)) {
                return value;
            }
        }
        return fallback;
    }

    private String normalizeDistributionRoot(String root) {
        String normalized = root.trim();
        while (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        return normalized;
    }

    private String resolveDistributionToken(String distributionRoot, String token) {
        if (!support.hasText(token)) {
            return null;
        }
        String value = token.trim();
        if (value.startsWith("http://") || value.startsWith("https://")) {
            return value;
        }
        if (value.startsWith("./")) {
            value = value.substring(2);
        }
        if (value.startsWith("/")) {
            value = value.substring(1);
        }
        return normalizeDistributionRoot(distributionRoot) + "/" + value;
    }

    private Optional<String> fetchTextOptional(String url, CsafProvider provider) {
        try {
            String body = fetchText(url, provider);
            return support.hasText(body) ? Optional.of(body) : Optional.empty();
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private String fetchText(String url, CsafProvider provider) {
        try {
            return outboundHttpClient.execute(
                    url,
                    HttpMethod.GET,
                    HttpEntity.EMPTY,
                    String.class,
                    "CSAF discovery fetch",
                    outboundPolicy(provider),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException runtimeException
                                    ? runtimeException
                                    : new RuntimeException(context.error())
                    ),
                    response -> response.getBody() == null ? "" : response.getBody()
            );
        } catch (RuntimeException runtimeException) {
            throw runtimeException;
        } catch (Exception checkedException) {
            throw new RuntimeException(checkedException);
        }
    }

    private OutboundPolicy outboundPolicy(CsafProvider provider) {
        return outboundPolicyFactory.forProvider("csaf-" + provider.providerKey(), 0L, null, null);
    }

    private String unquoteCsv(String value) {
        if (!support.hasText(value)) {
            return "";
        }
        String normalized = value.trim();
        if (normalized.startsWith("\"") && normalized.endsWith("\"") && normalized.length() >= 2) {
            normalized = normalized.substring(1, normalized.length() - 1);
        }
        return normalized;
    }

    private boolean isCsafJsonUrl(String value) {
        if (!support.hasText(value)) {
            return false;
        }
        String normalized = value.toLowerCase(Locale.ROOT);
        return normalized.startsWith("http://") || normalized.startsWith("https://")
                ? normalized.endsWith(".json")
                : false;
    }
}
