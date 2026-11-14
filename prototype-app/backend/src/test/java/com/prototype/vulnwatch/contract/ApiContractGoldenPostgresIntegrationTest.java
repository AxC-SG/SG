package com.prototype.vulnwatch.contract;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.service.SbomIngestionService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriUtils;
import org.springframework.web.client.RestTemplate;

import static org.springframework.test.web.client.ExpectedCount.once;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;
import static org.springframework.http.HttpMethod.GET;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.correlation.backfill-targets-on-startup=false",
        "app.tenancy.require-tenant-context=false"
})
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class ApiContractGoldenPostgresIntegrationTest {

    private static final String API_KEY = "test-api-key";
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("api_contract_golden");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired org.springframework.context.ApplicationContext reviewContext;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private SbomIngestionService sbomIngestionService;

    @Autowired
    private WorkspaceService workspaceService;

    private MockRestServiceServer server;

    @BeforeAll
    void setUpDeterministicBaselineData() throws Exception {
        server = MockRestServiceServer.bindTo(restTemplate).ignoreExpectOrder(true).build();
        ingestCveAdvisories();
        com.prototype.vulnwatch.support.ReviewedIntelligenceTestSupport.publishAll(reviewContext);
        mockMvc.perform(post("/api/demo/seed").header("X-API-Key", API_KEY))
                .andExpect(status().isOk());

        String sourceUrl = "https://example.com/fixtures/cyclonedx-demo.json";
        byte[] sbomBytes = new ClassPathResource("fixtures/cyclonedx-demo.json").getInputStream().readAllBytes();
        server.expect(once(), requestTo(sourceUrl))
                .andExpect(method(GET))
                .andRespond(withSuccess(sbomBytes, MediaType.APPLICATION_JSON));

        sbomIngestionService.ingestFromEndpoint(
                workspaceService.getWorkspace(),
                new SbomEndpointIngestionRequest(
                        AssetType.APPLICATION,
                        "demo-app",
                        "app:demo",
                        sourceUrl,
                        null,
                        null
                )
        );
        server.verify();
    }

    @Test
    void vulnerabilityIntelligenceApi_contractAndGoldenHashesOnPostgres() throws Exception {
        JsonNode listBody = readJson(getWithApiKey("/api/vulnerability-intelligence?page=0&size=200&minCvssExclusive=8"));

        assertTrue(listBody.has("items"));
        assertTrue(listBody.has("page"));
        assertTrue(listBody.has("size"));
        assertTrue(listBody.has("totalItems"));
        assertTrue(listBody.has("totalPages"));

        JsonNode listItems = listBody.path("items");
        assertTrue(listItems.isArray());
        assertFalse(listItems.isEmpty());

        JsonNode first = listItems.get(0);
        assertTrue(first.hasNonNull("externalId"));
        assertTrue(first.hasNonNull("severity"));
        assertTrue(first.has("cvssScore"));
        assertTrue(optionalNumberField(first, "epssScore"));
        assertTrue(first.hasNonNull("inKev"));
        assertTrue(first.hasNonNull("sourceCount"));
        assertTrue(first.hasNonNull("sources"));
        assertTrue(first.hasNonNull("openFindings"));

        assertGoldenHash("fixtures/golden/vulnerability-intelligence-list.sha256", sha256(canonicalizeVulnIntelList(listBody)));

        String externalId = first.path("externalId").asText();
        String encodedExternalId = UriUtils.encodePathSegment(externalId, StandardCharsets.UTF_8);
        JsonNode detail = readJson(getWithApiKey("/api/vulnerability-intelligence/" + encodedExternalId));

        assertTrue(detail.hasNonNull("externalId"));
        assertTrue(detail.hasNonNull("severity"));
        assertTrue(detail.has("cvssScore"));
        assertTrue(optionalNumberField(detail, "epssScore"));
        assertTrue(detail.hasNonNull("inKev"));
        assertTrue(detail.hasNonNull("sourceCount"));
        assertTrue(detail.hasNonNull("sources"));
        assertTrue(detail.hasNonNull("openFindings"));
        assertTrue(detail.hasNonNull("observations"));
        assertTrue(detail.hasNonNull("references"));

        assertGoldenHash("fixtures/golden/vulnerability-intelligence-detail.sha256", sha256(canonicalizeVulnIntelDetail(detail)));
    }

    @Test
    void inventoryComponentsApi_contractAndGoldenHashOnPostgres() throws Exception {
        JsonNode body = readJson(getWithApiKey("/api/inventory/components?page=0&size=200"));

        assertTrue(body.has("items"));
        assertTrue(body.has("page"));
        assertTrue(body.has("size"));
        assertTrue(body.has("totalItems"));
        assertTrue(body.has("totalPages"));

        JsonNode items = body.path("items");
        assertTrue(items.isArray());
        assertFalse(items.isEmpty());

        JsonNode first = items.get(0);
        assertTrue(first.hasNonNull("assetId"));
        assertTrue(first.hasNonNull("assetName"));
        assertTrue(first.hasNonNull("assetIdentifier"));
        assertTrue(first.hasNonNull("assetType"));
        assertTrue(first.hasNonNull("ecosystem"));
        assertTrue(first.hasNonNull("packageName"));
        assertTrue(first.hasNonNull("version"));
        assertTrue(first.hasNonNull("purl"));
        assertTrue(first.hasNonNull("componentStatus"));

        assertGoldenHash("fixtures/golden/inventory-components.sha256", sha256(canonicalizeInventoryComponents(body)));
    }

    @Test
    void syncRunsApi_contractAndGoldenHashOnPostgres() throws Exception {
        JsonNode body = readJson(getWithApiKey("/api/sync-runs"));

        assertTrue(body.isArray());
        if (!body.isEmpty()) {
            JsonNode first = body.get(0);
            assertTrue(first.hasNonNull("id"));
            assertTrue(first.hasNonNull("syncType"));
            assertTrue(first.hasNonNull("status"));
            assertTrue(first.hasNonNull("recordsFetched"));
            assertTrue(first.hasNonNull("recordsInserted"));
            assertTrue(first.hasNonNull("recordsUpdated"));
            assertTrue(first.hasNonNull("recordsFailed"));
            assertTrue(first.hasNonNull("startedAt"));
        }

        assertGoldenHash("fixtures/golden/sync-runs.sha256", sha256(canonicalizeSyncRuns(body)));
    }

    private void ingestCveAdvisories() throws Exception {
        String body = """
                {
                  "advisories": [
                    {
                      "externalId": "CVE-2024-77701",
                      "title": "Demo CVE Log4j",
                      "description": "Demo normalized CVE for Log4j correlation",
                      "cvssScore": 9.8,
                      "severity": "CRITICAL",
                      "rules": [
                        {
                          "ecosystem": "maven",
                          "packageName": "log4j-core",
                          "versionStart": "2.0.0",
                          "versionEnd": "2.17.1",
                          "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
                        }
                      ]
                    },
                    {
                      "externalId": "CVE-2024-77702",
                      "title": "Demo CVE Requests",
                      "description": "Demo normalized CVE for Requests correlation",
                      "cvssScore": 8.7,
                      "severity": "HIGH",
                      "rules": [
                        {
                          "ecosystem": "pypi",
                          "packageName": "requests",
                          "versionStart": "2.0.0",
                          "versionEnd": "2.31.0",
                          "cpe": "cpe:2.3:a:python-requests_project:requests:2.25.0:*:*:*:*:*:*:*"
                        }
                      ]
                    },
                    {
                      "externalId": "CVE-2024-77703",
                      "title": "Demo CVE Lodash",
                      "description": "Demo normalized CVE for Lodash correlation",
                      "cvssScore": 8.2,
                      "severity": "HIGH",
                      "rules": [
                        {
                          "ecosystem": "npm",
                          "packageName": "lodash",
                          "versionStart": "4.0.0",
                          "versionEnd": "4.17.20",
                          "cpe": "cpe:2.3:a:lodash:lodash:4.17.19:*:*:*:*:*:*:*"
                        }
                      ]
                    }
                  ]
                }
                """;

        mockMvc.perform(post("/api/ingestion/advisories")
                        .header("X-API-Key", API_KEY)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk());
    }

    private MvcResult getWithApiKey(String path) throws Exception {
        return mockMvc.perform(get(path).header("X-API-Key", API_KEY))
                .andExpect(status().isOk())
                .andReturn();
    }

    private JsonNode readJson(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private void assertGoldenHash(String fixturePath, String actualHash) throws Exception {
        String expected = new ClassPathResource(fixturePath).getContentAsString(StandardCharsets.UTF_8).trim();
        assertEquals(expected, actualHash,
                "Golden hash mismatch for " + fixturePath + ". actual=" + actualHash + " (update fixture only for approved change)");
    }

    private String canonicalizeVulnIntelList(JsonNode root) {
        List<String> lines = new ArrayList<>();
        for (JsonNode item : root.path("items")) {
            String sources = sortedArray(item.path("sources"));
            lines.add(String.join("|",
                    text(item, "externalId"),
                    text(item, "title"),
                    text(item, "severity"),
                    number(item, "cvssScore"),
                    number(item, "epssScore"),
                    bool(item, "inKev"),
                    String.valueOf(item.path("sourceCount").asInt()),
                    sources,
                    String.valueOf(item.path("openFindings").asLong())
            ));
        }
        lines.sort(Comparator.naturalOrder());
        return "vuln-intel.totalItems=" + root.path("totalItems").asLong() + "\n" + String.join("\n", lines);
    }

    private String canonicalizeVulnIntelDetail(JsonNode detail) {
        List<String> observationLines = new ArrayList<>();
        for (JsonNode observation : detail.path("observations")) {
            observationLines.add(String.join("|",
                    text(observation, "sourceSystem"),
                    text(observation, "sourceRecordId"),
                    text(observation, "severity"),
                    number(observation, "cvssScore"),
                    number(observation, "epssScore"),
                    bool(observation, "inKev"),
                    text(observation, "vulnStatus"),
                    text(observation, "sourceIdentifier")
            ));
        }
        observationLines.sort(Comparator.naturalOrder());

        List<String> references = new ArrayList<>();
        detail.path("references").forEach(ref -> references.add(ref.asText("")));
        references.sort(Comparator.naturalOrder());

        String header = String.join("|",
                text(detail, "externalId"),
                text(detail, "severity"),
                number(detail, "cvssScore"),
                number(detail, "epssScore"),
                bool(detail, "inKev"),
                text(detail, "vulnStatus"),
                String.valueOf(detail.path("sourceCount").asInt()),
                sortedArray(detail.path("sources")),
                String.valueOf(detail.path("openFindings").asLong())
        );

        return "vuln-intel-detail=" + header
                + "\nreferences=" + String.join(",", references)
                + "\nobservations=" + String.join("\n", observationLines);
    }

    private String canonicalizeInventoryComponents(JsonNode root) {
        List<String> lines = new ArrayList<>();
        for (JsonNode item : root.path("items")) {
            lines.add(String.join("|",
                    text(item, "assetIdentifier"),
                    text(item, "assetType"),
                    text(item, "ecosystem"),
                    text(item, "packageName"),
                    text(item, "version"),
                    text(item, "purl"),
                    text(item, "componentStatus"),
                    text(item, "sourceSystem"),
                    text(item, "sourceReference"),
                    text(item, "softwareIdentity")
            ));
        }
        lines.sort(Comparator.naturalOrder());
        return "inventory.totalItems=" + root.path("totalItems").asLong() + "\n" + String.join("\n", lines);
    }

    private String canonicalizeSyncRuns(JsonNode root) {
        List<String> lines = new ArrayList<>();
        for (JsonNode item : root) {
            lines.add(String.join("|",
                    text(item, "syncType"),
                    text(item, "status"),
                    text(item, "queuePosition"),
                    String.valueOf(item.path("recordsFetched").asInt()),
                    String.valueOf(item.path("recordsInserted").asInt()),
                    String.valueOf(item.path("recordsUpdated").asInt()),
                    text(item, "errorMessage")
            ));
        }
        lines.sort(Comparator.naturalOrder());
        return "sync-runs.count=" + root.size() + "\n" + String.join("\n", lines);
    }

    private String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) {
            return "";
        }
        return value.asText("").trim();
    }

    private String bool(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull()) {
            return "";
        }
        return Boolean.toString(value.asBoolean());
    }

    private String number(JsonNode node, String field) {
        JsonNode value = node.path(field);
        if (value.isMissingNode() || value.isNull() || !value.isNumber()) {
            return "";
        }
        BigDecimal rounded = BigDecimal.valueOf(value.asDouble()).setScale(6, RoundingMode.HALF_UP);
        return rounded.stripTrailingZeros().toPlainString();
    }

    private String sortedArray(JsonNode arrayNode) {
        if (arrayNode == null || !arrayNode.isArray()) {
            return "";
        }
        return toList(arrayNode)
                .stream()
                .map(node -> node.asText(""))
                .sorted()
                .collect(Collectors.joining(","));
    }

    private boolean optionalNumberField(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isMissingNode() || value.isNull() || value.isNumber();
    }

    private List<JsonNode> toList(JsonNode arrayNode) {
        List<JsonNode> list = new ArrayList<>();
        arrayNode.forEach(list::add);
        return list;
    }

    private String sha256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte b : hash) {
                builder.append(String.format(Locale.ROOT, "%02x", b));
            }
            return builder.toString();
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to compute SHA-256", exception);
        }
    }
}
