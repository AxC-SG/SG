package com.prototype.vulnwatch.ticketing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.JiraAuthType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.JiraTicketingConfigService;
import com.prototype.vulnwatch.service.JiraTicketingConfigService.JiraRuntimeConfig;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ResponseStatusException;

class JiraTicketingProviderTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final JiraTicketingConfigService configs = mock(JiraTicketingConfigService.class);
    private final OutboundHttpClient outbound = mock(OutboundHttpClient.class);
    private final Tenant tenant = mock(Tenant.class);

    private JiraTicketingProvider provider;

    @BeforeEach
    void setUp() {
        provider = new JiraTicketingProvider(configs, outbound,
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0, 1, 0, 0, true, true)),
                objectMapper);
    }

    @Test
    void createsAnIssueAndReturnsItsKeyAndBrowseUrl() throws Exception {
        givenConfig(config(true, null, "Task", "security,scout-managed"));
        givenCreateResponse("{\"id\":\"10042\",\"key\":\"SEC-42\"}");

        TicketRef ref = provider.createForFinding(tenant, finding(), TicketRequest.empty());

        assertEquals(TicketingSystem.JIRA, ref.system());
        assertEquals("SEC-42", ref.externalKey());
        assertEquals("10042", ref.externalId());
        assertEquals("https://acme.atlassian.net/browse/SEC-42", ref.url());
    }

    @Test
    void sendsTheConfiguredProjectAndIssueTypeName() throws Exception {
        givenConfig(config(true, null, "Bug", null));
        givenCreateResponse("{\"id\":\"1\",\"key\":\"SEC-1\"}");

        JsonNode fields = captureCreatePayload().path("fields");

        assertEquals("SEC", fields.path("project").path("key").asText());
        assertEquals("Bug", fields.path("issuetype").path("name").asText());
        assertTrue(fields.path("issuetype").path("id").isMissingNode());
    }

    /** Issue type names are not unique across schemes, so an explicit id must win. */
    @Test
    void prefersAnExplicitIssueTypeIdOverTheName() throws Exception {
        givenConfig(config(true, "10004", "Task", null));
        givenCreateResponse("{\"id\":\"1\",\"key\":\"SEC-1\"}");

        JsonNode issueType = captureCreatePayload().path("fields").path("issuetype");

        assertEquals("10004", issueType.path("id").asText());
        assertTrue(issueType.path("name").isMissingNode());
    }

    /** The v3 API rejects a plain string for description; it must be an ADF document. */
    @Test
    void sendsTheDescriptionAsAnAtlassianDocumentFormatDocument() throws Exception {
        givenConfig(config(true, null, "Task", null));
        givenCreateResponse("{\"id\":\"1\",\"key\":\"SEC-1\"}");

        JsonNode description = captureCreatePayload().path("fields").path("description");

        assertEquals("doc", description.path("type").asText());
        assertEquals(1, description.path("version").asInt());
        assertTrue(description.path("content").isArray());
        assertTrue(description.path("content").size() > 0);
        assertEquals("paragraph", description.path("content").get(0).path("type").asText());
    }

    @Test
    void labelsEveryIssueWithItsProvenanceAndTheConfiguredLabels() throws Exception {
        givenConfig(config(true, null, "Task", "security, scout managed"));
        givenCreateResponse("{\"id\":\"1\",\"key\":\"SEC-1\"}");

        JsonNode labels = captureCreatePayload().path("fields").path("labels");
        String rendered = labels.toString();

        assertTrue(rendered.contains("\"scout\""), rendered);
        assertTrue(rendered.contains("\"F-AI000000001\""), rendered);
        assertTrue(rendered.contains("\"security\""), rendered);
        // Jira rejects labels containing whitespace.
        assertTrue(rendered.contains("\"scout-managed\""), rendered);
    }

    @Test
    void mapsSeverityOntoJiraPriorityNames() throws Exception {
        givenConfig(config(true, null, "Task", null));
        givenCreateResponse("{\"id\":\"1\",\"key\":\"SEC-1\"}");

        JsonNode fields = captureCreatePayload().path("fields");

        assertEquals("High", fields.path("priority").path("name").asText());
    }

    /** Instances that removed Priority from the create screen reject the field outright. */
    @Test
    void omitsPriorityWhenTheConnectorDisablesIt() throws Exception {
        givenConfig(config(false, null, "Task", null));
        givenCreateResponse("{\"id\":\"1\",\"key\":\"SEC-1\"}");

        assertTrue(captureCreatePayload().path("fields").path("priority").isMissingNode());
    }

    @Test
    void failsWhenJiraOmitsTheIssueKey() throws Exception {
        givenConfig(config(true, null, "Task", null));
        givenCreateResponse("{\"id\":\"10042\"}");

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> provider.createForFinding(tenant, finding(), TicketRequest.empty()));

        assertEquals(502, ex.getStatusCode().value());
    }

    @Test
    void refusesToCreateWhenTheConnectorIsDisabled() {
        when(configs.resolveRuntimeConfig(tenant)).thenReturn(Optional.of(new JiraRuntimeConfig(
                "https://acme.atlassian.net", JiraAuthType.BASIC, "bot@acme.test", "token",
                "SEC", null, "Task", null, true, false)));

        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> provider.createForFinding(tenant, finding(), TicketRequest.empty()));

        assertEquals(503, ex.getStatusCode().value());
    }

    @Test
    void readsTheWorkflowStatusName() throws Exception {
        givenConfig(config(true, null, "Task", null));
        givenStatusResponse("In Progress", "indeterminate");

        TicketStatus status = provider.fetchStatus(tenant, "SEC-42").orElseThrow();

        assertEquals("In Progress", status.label());
        assertFalse(status.resolved());
    }

    /**
     * Jira status names are renameable per workflow, so completion has to come from the stable
     * statusCategory. A board that calls its final column "Shipped" must still read as resolved.
     */
    @Test
    void treatsTheDoneStatusCategoryAsResolvedWhateverTheColumnIsCalled() throws Exception {
        givenConfig(config(true, null, "Task", null));
        givenStatusResponse("Shipped", "done");

        TicketStatus status = provider.fetchStatus(tenant, "SEC-42").orElseThrow();

        assertEquals("Shipped", status.label());
        assertTrue(status.resolved());
    }

    /** A transient outage must leave the last known status in place, not blank it. */
    @Test
    void reportsNoStatusWhenTheFetchFails() throws Exception {
        givenConfig(config(true, null, "Task", null));
        when(outbound.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class),
                anyString(), any(), any()))
                .thenThrow(new RuntimeException("connection reset"));

        assertTrue(provider.fetchStatus(tenant, "SEC-42").isEmpty());
    }

    @Test
    void reportsNoStatusWhenTheTenantHasNoJiraConnector() {
        when(configs.resolveRuntimeConfig(tenant)).thenReturn(Optional.empty());

        assertTrue(provider.fetchStatus(tenant, "SEC-42").isEmpty());
        assertTrue(provider.fetchStatus(tenant, null).isEmpty());
    }

    @Test
    void reportsConfiguredFromTheConnectorReadinessCheck() {
        when(configs.isReadyForTicketing(tenant)).thenReturn(true);
        assertTrue(provider.isConfigured(tenant));

        when(configs.isReadyForTicketing(tenant)).thenReturn(false);
        assertFalse(provider.isConfigured(tenant));
    }

    private JsonNode captureCreatePayload() throws Exception {
        provider.createForFinding(tenant, finding(), TicketRequest.empty());
        ArgumentCaptor<HttpEntity<?>> captor = captor();
        org.mockito.Mockito.verify(outbound).exchange(anyString(), eq(HttpMethod.POST), captor.capture(),
                eq(String.class), anyString(), any(), any());
        return objectMapper.readTree(String.valueOf(captor.getValue().getBody()));
    }

    @SuppressWarnings("unchecked")
    private static ArgumentCaptor<HttpEntity<?>> captor() {
        return (ArgumentCaptor<HttpEntity<?>>) (ArgumentCaptor<?>) ArgumentCaptor.forClass(HttpEntity.class);
    }

    private void givenStatusResponse(String name, String categoryKey) throws Exception {
        when(outbound.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class),
                anyString(), any(), any()))
                .thenReturn(ResponseEntity.ok("{\"fields\":{\"status\":{\"name\":\"" + name
                        + "\",\"statusCategory\":{\"key\":\"" + categoryKey + "\"}}}}"));
    }

    private void givenConfig(JiraRuntimeConfig config) {
        when(configs.resolveRuntimeConfig(tenant)).thenReturn(Optional.of(config));
    }

    private void givenCreateResponse(String body) throws Exception {
        when(outbound.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class),
                anyString(), any(), any())).thenReturn(ResponseEntity.ok(body));
    }

    @Test
    void createsOneCveIssueCoveringTheGroupsAssets() throws Exception {
        givenConfig(config(true, null, "Task", null));
        givenCreateResponse("{\"id\":\"10050\",\"key\":\"SEC-50\"}");

        TicketRef ref = provider.createForCve(tenant, new CveTicketRequest(
                "CVE-2026-1234", "Platform Team", "HIGH", "HIGH", "2026-10-01", null, null, null,
                List.of(new TicketAsset("c1", "web-01", "sys-1", "HOST", "openssl", "1.1.1", "Platform Team"))));

        assertEquals("SEC-50", ref.externalKey());
        assertEquals("https://acme.atlassian.net/browse/SEC-50", ref.url());
    }

    @Test
    void cveIssueNamesTheCveAndListsTheAffectedAssets() throws Exception {
        givenConfig(config(true, null, "Task", null));
        givenCreateResponse("{\"id\":\"1\",\"key\":\"SEC-1\"}");

        provider.createForCve(tenant, new CveTicketRequest(
                "CVE-2026-1234", "Platform Team", "HIGH", null, null, null, null, null,
                List.of(new TicketAsset("c1", "web-01", "sys-1", "HOST", "openssl", "1.1.1", "Platform Team"))));

        ArgumentCaptor<HttpEntity<?>> captor = captor();
        org.mockito.Mockito.verify(outbound).exchange(anyString(), eq(HttpMethod.POST), captor.capture(),
                eq(String.class), anyString(), any(), any());
        String body = String.valueOf(captor.getValue().getBody());

        assertTrue(body.contains("CVE-2026-1234"), body);
        assertTrue(body.contains("web-01"), body);
        assertTrue(body.contains("openssl"), body);
    }

    /** Jira cannot be told to "set status" — resolution has to travel a workflow transition. */
    @Test
    void resolvesByTakingTheTransitionIntoTheDoneCategory() throws Exception {
        givenConfig(config(true, null, "Task", null));
        when(outbound.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class),
                anyString(), any(), any()))
                .thenReturn(ResponseEntity.ok("{\"transitions\":["
                        + "{\"id\":\"11\",\"to\":{\"statusCategory\":{\"key\":\"indeterminate\"}}},"
                        + "{\"id\":\"31\",\"to\":{\"statusCategory\":{\"key\":\"done\"}}}]}"));
        when(outbound.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class),
                anyString(), any(), any())).thenReturn(ResponseEntity.ok("{}"));

        assertTrue(provider.pushFindingStatus(tenant, "SEC-42", TicketPush.resolve("remediated")));

        ArgumentCaptor<HttpEntity<?>> captor = captor();
        org.mockito.Mockito.verify(outbound, org.mockito.Mockito.atLeastOnce())
                .exchange(anyString(), eq(HttpMethod.POST), captor.capture(), eq(String.class),
                        anyString(), any(), any());
        assertTrue(captor.getAllValues().stream()
                        .anyMatch(entity -> String.valueOf(entity.getBody()).contains("\"id\":\"31\"")),
                "expected the done-category transition to be applied");
    }

    /**
     * A workflow with no route to done must not wedge the sync into retrying forever, so the
     * note still lands and the push counts as applied.
     */
    @Test
    void recordsACommentWhenNoTransitionReachesDone() throws Exception {
        givenConfig(config(true, null, "Task", null));
        when(outbound.exchange(anyString(), eq(HttpMethod.GET), any(HttpEntity.class), eq(String.class),
                anyString(), any(), any()))
                .thenReturn(ResponseEntity.ok("{\"transitions\":["
                        + "{\"id\":\"11\",\"to\":{\"statusCategory\":{\"key\":\"indeterminate\"}}}]}"));
        when(outbound.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class),
                anyString(), any(), any())).thenReturn(ResponseEntity.ok("{}"));

        assertTrue(provider.pushFindingStatus(tenant, "SEC-42", TicketPush.resolve("remediated")));
    }

    @Test
    void reportsFailureWhenTheCommentCannotBePosted() throws Exception {
        givenConfig(config(true, null, "Task", null));
        when(outbound.exchange(anyString(), eq(HttpMethod.POST), any(HttpEntity.class), eq(String.class),
                anyString(), any(), any())).thenThrow(new RuntimeException("connection reset"));

        assertFalse(provider.pushFindingStatus(tenant, "SEC-42", TicketPush.comment("note")));
    }

    @Test
    void refusesToPushWhenTheConnectorIsDisabled() {
        when(configs.resolveRuntimeConfig(tenant)).thenReturn(Optional.of(new JiraRuntimeConfig(
                "https://acme.atlassian.net", JiraAuthType.BASIC, "bot@acme.test", "token",
                "SEC", null, "Task", null, true, false)));

        assertFalse(provider.pushFindingStatus(tenant, "SEC-42", TicketPush.resolve("remediated")));
    }

    private static JiraRuntimeConfig config(boolean includePriority, String issueTypeId,
                                            String issueTypeName, String labels) {
        return new JiraRuntimeConfig(
                "https://acme.atlassian.net", JiraAuthType.BASIC, "bot@acme.test", "token",
                "SEC", issueTypeId, issueTypeName, labels, includePriority, true);
    }

    private static Finding finding() {
        Finding finding = mock(Finding.class);
        when(finding.getDisplayId()).thenReturn("F-AI000000001");
        when(finding.getTitle()).thenReturn("Weak attached guardrail");
        when(finding.getSeverityOverride()).thenReturn("HIGH");
        when(finding.getOwnerGroup()).thenReturn("AI Platform Team");
        when(finding.getPolicyId()).thenReturn("AWS_BEDROCK_WEAK_GUARDRAIL");
        return finding;
    }
}
