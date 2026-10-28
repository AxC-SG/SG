package com.prototype.vulnwatch.service.patch.tanium;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.PatchConnectorConfig;
import com.prototype.vulnwatch.service.patch.PatchSnapshot;
import java.net.URI;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TaniumPatchProviderTest {

    private static final URI BASE = URI.create("https://acme-api.cloud.tanium.com");
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void acceptsOnlyTheTenantsTaniumCloudHost() {
        assertThat(TaniumGateway.validateBaseUrl("https://ACME-api.cloud.tanium.com/")).isEqualTo(BASE);
        for (String bad : List.of("http://acme.cloud.tanium.com", "https://acme.cloud.tanium.com.evil.com",
                "https://evil.com/acme.cloud.tanium.com", "https://a.b.cloud.tanium.com", "https://acme.cloud.tanium.com:8443",
                "https://user@acme.cloud.tanium.com", "https://acme.cloud.tanium.com/plugin?x=1", "https://cloud.tanium.com")) {
            assertThatThrownBy(() -> TaniumGateway.validateBaseUrl(bad)).as(bad).isInstanceOf(IllegalArgumentException.class);
        }
    }

    @Test
    void sendsValuesAsGraphqlVariablesAndSurfacesErrors() throws Exception {
        TaniumGateway gateway = new TaniumGateway(json);
        JsonNode body = json.readTree(gateway.body(TaniumPatchProvider.ENDPOINTS, TaniumPatchProvider.variables(200, "cursor\" } evil")));
        assertThat(body.path("query").asText()).isEqualTo(TaniumPatchProvider.ENDPOINTS);
        assertThat(body.path("variables").path("after").asText()).isEqualTo("cursor\" } evil");
        assertThat(body.path("variables").path("sensors").get(0).path("name").asText()).isEqualTo("Patch - Available Patches");

        assertThatThrownBy(() -> gateway.data("{\"errors\":[{\"message\":\"Field 'sensorReadings' doesn't exist\"}]}"))
                .hasMessageContaining("sensorReadings");
        assertThat(gateway.data("{\"data\":{\"endpoints\":{}}}").has("endpoints")).isTrue();
    }

    @Test
    void validateNormalizesUrlAndRequiresAToken() {
        TaniumPatchProvider provider = new TaniumPatchProvider(mock(TaniumGateway.class));
        PatchConnectorConfig config = new PatchConnectorConfig();
        config.setBaseUrl("https://acme-api.cloud.tanium.com/");
        config.setUsername("ignored");
        provider.validate(config, true);
        assertThat(config.getBaseUrl()).isEqualTo(BASE.toString());
        assertThat(config.getUsername()).isNull();
        assertThatThrownBy(() -> provider.validate(config, false)).hasMessageContaining("API token");
    }

    @Test
    void pagesEndpointsAndMapsSensorReadings() throws Exception {
        TaniumGateway gateway = mock(TaniumGateway.class);
        when(gateway.query(eq(BASE), eq("token"), eq(TaniumPatchProvider.ENDPOINTS), argThat(v -> v != null && v.get("after") == null)))
                .thenReturn(json.readTree("""
                        {"endpoints":{"edges":[{"node":{"id":"1","name":"ws-01","serialNumber":"SN1","os":{"name":"Windows 11 Enterprise","platform":"Windows"},
                          "sensorReadings":{"columns":[
                            {"name":"Title","values":["2026-10 Cumulative Update","Edge 141"],"sensor":{"name":"Patch - Available Patches"}},
                            {"name":"Severity","values":["Critical","Moderate"],"sensor":{"name":"Patch - Available Patches"}},
                            {"name":"KB Articles","values":["KB5066666",""],"sensor":{"name":"Patch - Available Patches"}},
                            {"name":"CVE IDs","values":["CVE-2026-1111,CVE-2026-2222",""],"sensor":{"name":"Patch - Available Patches"}},
                            {"name":"Title","values":["2026-09 Cumulative Update"],"sensor":{"name":"Patch - Installed Patches"}},
                            {"name":"KB Articles","values":["KB5065555"],"sensor":{"name":"Patch - Installed Patches"}},
                            {"name":"Install Date","values":["2026-09-20"],"sensor":{"name":"Patch - Installed Patches"}}]}}}],
                          "pageInfo":{"hasNextPage":true,"endCursor":"c1"}}}"""));
        when(gateway.query(eq(BASE), eq("token"), eq(TaniumPatchProvider.ENDPOINTS), argThat(v -> v != null && "c1".equals(v.get("after")))))
                .thenReturn(json.readTree("""
                        {"endpoints":{"edges":[{"node":{"id":"2","name":"web-1","os":{"name":"Red Hat Enterprise Linux 9","platform":"Linux"},
                          "sensorReadings":{"columns":[{"name":"Title","values":["[no results]"],"sensor":{"name":"Patch - Available Patches"}}]}}}],
                          "pageInfo":{"hasNextPage":false}}}"""));
        PatchConnectorConfig config = new PatchConnectorConfig();
        config.setBaseUrl(BASE.toString());

        PatchSnapshot snapshot = new TaniumPatchProvider(gateway).fetch(null, config, "token");

        assertThat(snapshot.complete()).isTrue();
        assertThat(snapshot.devices()).extracting(PatchSnapshot.Device::externalId).containsExactly("1", "2");
        assertThat(snapshot.patches()).extracting(PatchSnapshot.Patch::externalId)
                .containsExactlyInAnyOrder("KB5065555", "KB5066666", "Edge 141");
        PatchSnapshot.Patch cumulative = snapshot.patches().stream().filter(p -> "KB5066666".equals(p.externalId())).findFirst().orElseThrow();
        assertThat(cumulative.severity()).isEqualTo("CRITICAL");
        assertThat(cumulative.cves()).containsExactly("CVE-2026-1111", "CVE-2026-2222");
        assertThat(cumulative.ecosystem()).isEqualTo(FixRecord.Ecosystem.WINDOWS);
        assertThat(snapshot.statuses()).extracting(PatchSnapshot.Status::status)
                .containsExactlyInAnyOrder(FixAssetStatus.INSTALLED, FixAssetStatus.MISSING, FixAssetStatus.MISSING);
    }

    @Test
    void aRepeatedCursorStopsPagingAndMarksThePartialRun() throws Exception {
        TaniumGateway gateway = mock(TaniumGateway.class);
        when(gateway.query(any(), any(), any(), anyMap())).thenReturn(json.readTree(
                "{\"endpoints\":{\"edges\":[],\"pageInfo\":{\"hasNextPage\":true,\"endCursor\":null}}}"));
        PatchConnectorConfig config = new PatchConnectorConfig();
        config.setBaseUrl(BASE.toString());
        PatchSnapshot snapshot = new TaniumPatchProvider(gateway).fetch(null, config, "token");
        assertThat(snapshot.complete()).isFalse();
        assertThat(snapshot.warnings()).anyMatch(w -> w.contains("partial"));
    }

    @Test
    void connectionTestFailsOnARejectedToken() {
        TaniumGateway gateway = mock(TaniumGateway.class);
        when(gateway.query(any(), any(), eq(TaniumPatchProvider.PROBE), anyMap()))
                .thenThrow(new IllegalStateException("Tanium rejected the API token (HTTP 401)"));
        PatchConnectorConfig config = new PatchConnectorConfig();
        config.setBaseUrl(BASE.toString());
        assertThat(new TaniumPatchProvider(gateway).test(null, config, "bad").message()).contains("HTTP 401");
    }

    @Test
    void sensorColumnsZipIntoRows() throws Exception {
        Map<String, List<Map<String, String>>> rows = TaniumPatchProvider.TaniumMapper.rowsBySensor(json.readTree("""
                [{"name":"Title","values":["A","B"],"sensor":{"name":"S"}},{"name":"KB","values":["1"],"sensor":{"name":"S"}}]"""));
        assertThat(rows.get("S")).hasSize(2);
        assertThat(rows.get("S").get(1).get("kb")).isNull();
    }
}
