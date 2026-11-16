package com.prototype.vulnwatch.ticketing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.ServiceNowAuthType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.service.ServiceNowCmdbConfigService;
import com.prototype.vulnwatch.service.ServiceNowIncidentService;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

/**
 * Phase 0B §4.9 / §5.1 (E12): on the canonical routing path the ServiceNow payload carries exactly the routed group and
 * never {@code App-Sec Manager} or the finding's free-text {@code owner_group}; the legacy path is unchanged.
 */
class ServiceNowRoutedGroupTest {

    private static final String INCIDENTS = "https://example.service-now.com/api/now/table/incident";
    private final ObjectMapper mapper = new ObjectMapper();
    private final Tenant tenant = mock(Tenant.class);
    private MockRestServiceServer server;
    private ServiceNowTicketingProvider provider;
    private final List<String> sentBodies = new ArrayList<>();

    @BeforeEach
    void setUp() {
        RestTemplate restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();
        ServiceNowCmdbConfigService configs = mock(ServiceNowCmdbConfigService.class);
        when(configs.resolveRuntimeConfig(tenant)).thenReturn(Optional.of(new ServiceNowCmdbConfigService.ServiceNowRuntimeConfig(
                "https://example.service-now.com", ServiceNowAuthType.BASIC, "scout", "secret",
                "cmdb_sam_sw_install", "cmdb_software_product_model", "cmdb_ci", "", "", "", "", 100, true, false, 60)));
        ServiceNowIncidentService incidents = new ServiceNowIncidentService(configs,
                new OutboundHttpClient(restTemplate, OutboundHostPolicy.forTests("servicenow=example.service-now.com")),
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0, 1, 0, 0, true, true)),
                mapper, mock(FindingRepository.class));
        provider = new ServiceNowTicketingProvider(incidents, configs);
    }

    @Test
    void aRoutedFindingTicketSendsTheMappedGroupNotTheOwnerGroupOrTheDefault() throws Exception {
        expectIncident();
        provider.createForFinding(tenant, finding("Legacy Owner Group"),
                new TicketRequest(null, null, null, null, null, "caller-group", null, null, "Payments Support"));
        JsonNode payload = sent();
        assertThat(payload.path("assignment_group").asText()).isEqualTo("Payments Support");
        assertThat(sentBodies.get(0)).doesNotContain("App-Sec Manager").doesNotContain("Legacy Owner Group").doesNotContain("caller-group");
        server.verify();
    }

    @Test
    void aLegacyFindingTicketKeepsTheOwnerGroupThenTheDefault() throws Exception {
        expectIncident();
        provider.createForFinding(tenant, finding("Legacy Owner Group"), TicketRequest.empty());
        assertThat(sent().path("assignment_group").asText()).isEqualTo("Legacy Owner Group");

        sentBodies.clear();
        server.reset();
        expectIncident();
        provider.createForFinding(tenant, finding(null), TicketRequest.empty());
        assertThat(sent().path("assignment_group").asText()).isEqualTo("App-Sec Manager");
    }

    @Test
    void aRoutedCveTicketSendsTheBatchGroupAndNeverTheDefault() throws Exception {
        expectIncident();
        provider.createForCve(tenant, new CveTicketRequest("CVE-2026-1", "Identity Support", "HIGH", null, null, null, null, null,
                List.of(new TicketAsset("c1", "web-01", null, "HOST", "openssl", "1.1.1", null)), true));
        assertThat(sent().path("assignment_group").asText()).isEqualTo("Identity Support");
        assertThat(sentBodies.get(0)).doesNotContain("App-Sec Manager");
    }

    @Test
    void aRoutedCveTicketWithoutAGroupIsRefusedInsteadOfDefaulting() {
        assertThatThrownBy(() -> provider.createForCve(tenant, new CveTicketRequest("CVE-2026-1", " ", "HIGH", null, null, null, null, null,
                List.of(), true))).isInstanceOf(IllegalStateException.class);
        server.verify();
    }

    @Test
    void aLegacyCveTicketStillFallsBackToTheDefaultGroup() throws Exception {
        expectIncident();
        provider.createForCve(tenant, new CveTicketRequest("CVE-2026-1", null, "HIGH", null, null, null, null, null, List.of()));
        assertThat(sent().path("assignment_group").asText()).isEqualTo("App-Sec Manager");
    }

    private void expectIncident() {
        server.expect(requestTo(INCIDENTS)).andExpect(method(HttpMethod.POST)).andExpect(request -> {
            sentBodies.add(((org.springframework.mock.http.client.MockClientHttpRequest) request).getBodyAsString());
        }).andRespond(withSuccess("{\"result\":{\"number\":\"INC0001\",\"sys_id\":\"abc\"}}", MediaType.APPLICATION_JSON));
    }

    private JsonNode sent() throws Exception {
        assertThat(sentBodies).hasSize(1);
        return mapper.readTree(sentBodies.get(0));
    }

    private static Finding finding(String ownerGroup) {
        Finding finding = mock(Finding.class);
        when(finding.getDisplayId()).thenReturn("F-1");
        when(finding.getTitle()).thenReturn("Weak guardrail");
        when(finding.getSeverityOverride()).thenReturn("HIGH");
        when(finding.getRiskScore()).thenReturn(8.0);
        when(finding.getOwnerGroup()).thenReturn(ownerGroup);
        return finding;
    }
}
