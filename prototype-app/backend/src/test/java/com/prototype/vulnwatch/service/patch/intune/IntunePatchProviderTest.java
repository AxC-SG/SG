package com.prototype.vulnwatch.service.patch.intune;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.PatchConnectorConfig;
import com.prototype.vulnwatch.service.patch.PatchConnectionResult;
import com.prototype.vulnwatch.service.patch.PatchSnapshot;
import com.prototype.vulnwatch.service.patch.intune.IntunePatchProvider.IntuneMapper;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class IntunePatchProviderTest {

    private static final String DIRECTORY = "11111111-2222-3333-4444-555555555555";
    private static final String CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    private static final Instant NOW = Instant.parse("2026-10-28T12:00:00Z");
    private final ObjectMapper json = new ObjectMapper();

    private MockRestServiceServer server;
    private IntuneGraphClient graph;
    private IntunePatchProvider provider;

    @BeforeEach
    void setUp() {
        RestTemplate restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();
        graph = new IntuneGraphClient(new OutboundHttpClient(restTemplate, OutboundHostPolicy.forTests()),
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0, 0, 0, 0, false, false)), json);
        provider = new IntunePatchProvider(graph);
    }

    @Test
    void mintsAnAppOnlyTokenWithClientCredentials() {
        server.expect(requestTo("https://login.microsoftonline.com/" + DIRECTORY + "/oauth2/v2.0/token"))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("grant_type=client_credentials")))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("scope=https%3A%2F%2Fgraph.microsoft.com%2F.default")))
                .andRespond(withSuccess("{\"access_token\":\"graph-token\",\"expires_in\":3599}", MediaType.APPLICATION_JSON));

        assertThat(graph.token(DIRECTORY, CLIENT, "s3cret")).isEqualTo("graph-token");
        server.verify();
    }

    @Test
    void reportsEntraErrorsWithoutTheSecret() {
        server.expect(requestTo("https://login.microsoftonline.com/" + DIRECTORY + "/oauth2/v2.0/token"))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED).contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"invalid_client\",\"error_description\":\"AADSTS7000215: Invalid client secret provided.\\r\\nTrace ID: abc\"}"));

        assertThatThrownBy(() -> graph.token(DIRECTORY, CLIENT, "s3cret"))
                .hasMessageContaining("HTTP 401")
                .hasMessageNotContaining("s3cret");
    }

    @Test
    void followsNextLinksOnlyWithinGraph() {
        server.expect(requestTo("https://graph.microsoft.com/v1.0/deviceManagement/managedDevices"))
                .andExpect(header("Authorization", "Bearer t"))
                .andRespond(withSuccess("""
                        {"value":[{"id":"d1"}],"@odata.nextLink":"https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=2"}""",
                        MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$skiptoken=2"))
                .andRespond(withSuccess("""
                        {"value":[{"id":"d2"}],"@odata.nextLink":"https://evil.example.com/steal"}""", MediaType.APPLICATION_JSON));

        IntuneGraphClient.Listing listing = graph.list("t", "v1.0/deviceManagement/managedDevices", 10, 100);

        assertThat(listing.items()).hasSize(2);
        assertThat(listing.complete()).isFalse();
        assertThat(listing.warning()).contains("outside Microsoft Graph");
        server.verify();
    }

    @Test
    void connectionTestTreatsUpdateApisAsOptional() {
        server.expect(requestTo("https://login.microsoftonline.com/" + DIRECTORY + "/oauth2/v2.0/token"))
                .andRespond(withSuccess("{\"access_token\":\"t\"}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id&$top=1"))
                .andRespond(withSuccess("{\"value\":[]}", MediaType.APPLICATION_JSON));
        server.expect(requestTo("https://graph.microsoft.com/beta/admin/windows/updates/catalog/entries?$top=1"))
                .andRespond(withStatus(HttpStatus.FORBIDDEN));
        server.expect(requestTo("https://graph.microsoft.com/beta/admin/windows/updates/deployments?$top=1"))
                .andRespond(withStatus(HttpStatus.FORBIDDEN));

        PatchConnectionResult result = provider.test(null, config(), "s3cret");

        assertThat(result.status()).isEqualTo("SUCCESS_WITH_WARNINGS");
        assertThat(result.checks()).filteredOn(check -> !check.passed()).allMatch(check -> !check.required());
    }

    @Test
    void validationRequiresGuidsAndASecret() {
        PatchConnectorConfig bad = config();
        bad.setDirectoryId("contoso.onmicrosoft.com");
        assertThatThrownBy(() -> provider.validate(bad, true)).hasMessageContaining("Directory");
        assertThatThrownBy(() -> provider.validate(config(), false)).hasMessageContaining("client secret");

        PatchConnectorConfig good = config();
        good.setBaseUrl("https://evil.example.com");
        provider.validate(good, true);
        assertThat(good.getBaseUrl()).isNull();
    }

    @Test
    void mapsCatalogDeploymentsAndAudienceWithoutClaimingInstalls() throws Exception {
        List<JsonNode> devices = List.of(json.readTree("""
                {"id":"m-1","deviceName":"WS-01","serialNumber":"SN1","operatingSystem":"Windows","osVersion":"10.0.22631",
                 "azureADDeviceId":"E-1"}"""));
        List<JsonNode> catalog = List.of(
                json.readTree("""
                        {"id":"cat-1","displayName":"2026-10 Cumulative Update","releaseDateTime":"2026-10-14T00:00:00Z",
                         "qualityUpdateClassification":"security",
                         "cveSeverityInformation":{"maxSeverity":"critical","exploitedCves":[{"number":"cve-2026-1234"}]},
                         "productRevisions":[{"knowledgeBaseArticle":{"id":"KB5066666","url":"https://support.microsoft.com/kb/5066666"}}]}"""),
                // Old non-security entries nobody deploys are not imported.
                json.readTree("""
                        {"id":"cat-old","displayName":"2023-01 Preview","releaseDateTime":"2023-01-24T00:00:00Z",
                         "qualityUpdateClassification":"nonSecurity"}"""));
        List<JsonNode> deployments = List.of(json.readTree("""
                {"id":"dep-1","state":{"effectiveValue":"scheduled"},
                 "content":{"catalogEntry":{"id":"cat-1"}},
                 "settings":{"schedule":{"startDateTime":"2026-11-01T02:00:00Z"}}}"""));
        Map<String, List<JsonNode>> members = Map.of("dep-1", List.of(json.readTree("{\"id\":\"e-1\"}"), json.readTree("{\"id\":\"unknown\"}")));

        PatchSnapshot snapshot = IntuneMapper.snapshot(devices, catalog, deployments, members, NOW, true, List.of());

        assertThat(snapshot.patches()).singleElement().satisfies(patch -> {
            assertThat(patch.kbArticle()).isEqualTo("KB5066666");
            assertThat(patch.severity()).isEqualTo("CRITICAL");
            assertThat(patch.cves()).containsExactly("CVE-2026-1234");
        });
        assertThat(snapshot.statuses()).singleElement().satisfies(status -> {
            assertThat(status.deviceExternalId()).isEqualTo("m-1");
            assertThat(status.status()).isEqualTo(FixAssetStatus.SCHEDULED);
            assertThat(status.scheduledAt()).isEqualTo(Instant.parse("2026-11-01T02:00:00Z"));
        });
        assertThat(snapshot.devices()).singleElement().extracting(PatchSnapshot.Device::osName).isEqualTo("Windows 10.0.22631");
    }

    @Test
    void deploymentStatesMapConservatively() {
        assertThat(IntuneMapper.deviceStatus("offering", NOW.minusSeconds(60), NOW)).isEqualTo(FixAssetStatus.IN_PROGRESS);
        assertThat(IntuneMapper.deviceStatus("faulted", null, NOW)).isEqualTo(FixAssetStatus.FAILED);
        assertThat(IntuneMapper.deviceStatus("paused", null, NOW)).isEqualTo(FixAssetStatus.MISSING);
        assertThat(IntuneMapper.severity("Important")).isEqualTo("HIGH");
    }

    private static PatchConnectorConfig config() {
        PatchConnectorConfig config = new PatchConnectorConfig();
        config.setDirectoryId(DIRECTORY);
        config.setClientId(CLIENT);
        return config;
    }
}
