package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** Milestone 3 remediation operations for CRYPTO findings against real PostgreSQL. */
@PostgresControllerIntegrationTest
class CryptoRemediationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("crypto_remediation");
    private static final String SERIAL = "urn:uuid:5c1b7a52-3f0e-4d7b-9a1e-0b6c2d4e8f11";

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private FindingDeltaQueueService deltaQueue;
    @Autowired private TenantService tenantService;
    @Autowired private JdbcTemplate jdbc;

    private List<String> crypto;

    @BeforeEach
    void cryptoFindings() throws Exception {
        String body = Files.readString(Path.of("src/test/resources/fixtures/bom/cbom-9-assets.cdx.json"))
                .replace(SERIAL, "urn:uuid:" + UUID.randomUUID())
                .replace("scoutgrid-prototype-app", "remediation-" + UUID.randomUUID());
        mockMvc.perform(asPlatformOwner(authedPost("/api/bom/ingest?bomType=CBOM")).contentType("application/json")
                .content(body.getBytes(StandardCharsets.UTF_8))).andExpect(status().is2xxSuccessful());
        for (int i = 0; i < 5; i++) deltaQueue.processPendingDeltas();
        crypto = new ArrayList<>();
        get("/api/findings?findingKind=CRYPTO&status=OPEN&page=0&size=200").path("items").forEach(item -> crypto.add(item.path("id").asText()));
        assertTrue(crypto.size() >= 2, "the fixture yields at least two open CRYPTO findings");
    }

    @Test
    void cryptoTicketTemplateCarriesEvidenceAndFailedAttemptsAreVisibleForRetry() throws Exception {
        String finding = crypto.get(0);
        JsonNode template = get("/api/findings/" + finding + "/ticket-template");
        assertTrue(template.path("title").asText().startsWith("[Crypto]["), template.path("title").asText());
        assertTrue(template.path("notes").asText().contains("Rule: CBOM-"), template.path("notes").asText());
        assertTrue(template.path("notes").asText().contains("Source CBOM:"));
        assertTrue(template.path("solutionInfo").asText().contains("Verification steps"));
        assertTrue(template.path("assignee").isMissingNode() || template.path("assignee").isNull(), "provider-native identifiers are not guessed");

        // No ticketing connector is configured, so the push fails and the failure is recorded.
        mockMvc.perform(asPlatformOwner(authedPost("/api/findings/" + finding + "/ticket")).contentType("application/json").content("{}"))
                .andExpect(status().isServiceUnavailable());
        JsonNode attempts = get("/api/findings/" + finding + "/ticket-attempts");
        assertEquals(1, attempts.size());
        assertEquals("FAILED", attempts.get(0).path("outcome").asText());
        assertEquals("CRYPTO", attempts.get(0).path("template").asText());
        assertTrue(attempts.get(0).path("errorMessage").asText().contains("No ticketing system"));
        mockMvc.perform(asPlatformOwner(authedGet("/api/findings/" + UUID.randomUUID() + "/ticket-attempts"))).andExpect(status().isNotFound());
    }

    @Test
    void campaignsFromFindingsLinkAndBulkAssignAtomically() throws Exception {
        String ids = "[\"" + crypto.get(0) + "\",\"" + crypto.get(1) + "\"]";
        mockMvc.perform(asPlatformOwner(authedPost("/api/campaigns/from-findings")).contentType("application/json")
                .content("{\"name\":\"Rotate weak keys\",\"findingIds\":" + ids + ",\"assignedTo\":\"alice\"}"))
                .andExpect(status().isBadRequest());
        long before = inTenant(() -> jdbc.queryForObject("select count(*) from campaigns", Long.class));
        mockMvc.perform(asPlatformOwner(authedPost("/api/campaigns/from-findings")).contentType("application/json")
                .content("{\"name\":\"Bad\",\"findingIds\":[\"" + crypto.get(0) + "\",\"" + UUID.randomUUID() + "\"]}"))
                .andExpect(status().isBadRequest());
        assertEquals(before, (long) inTenant(() -> jdbc.queryForObject("select count(*) from campaigns", Long.class)),
                "an unknown finding rolls the whole campaign back");

        JsonNode campaign = json(mockMvc.perform(asPlatformOwner(authedPost("/api/campaigns/from-findings")).contentType("application/json")
                .content("{\"name\":\"Rotate weak keys\",\"findingIds\":" + ids + ",\"assignedTo\":\"alice\",\"dueAt\":\"2027-01-31T00:00:00Z\","
                        + "\"launchNote\":\"Q1 crypto hygiene\"}"))
                .andExpect(status().isCreated()).andReturn());
        String campaignId = campaign.path("summary").path("id").asText();
        JsonNode linked = get("/api/campaigns/" + campaignId + "/findings");
        assertEquals(2, linked.size());
        linked.forEach(row -> {
            assertEquals("alice", row.path("assignedTo").asText());
            assertEquals("CRYPTO", row.path("findingKind").asText());
            assertTrue(row.path("dueAt").asText().startsWith("2027-01-31"));
        });
    }

    @Test
    void queuesAndEffectivenessReflectCanonicalWorkflowState() throws Exception {
        String overdue = crypto.get(0);
        String verifying = crypto.get(1);
        inTenant(() -> {
            jdbc.update("update findings set due_at = now() - interval '2 days' where id = ?::uuid", overdue);
            jdbc.update("update findings set verification_required = true, verification_status = 'REQUESTED',"
                    + " verification_requested_at = now(), target_state = 'RSA-3072' where id = ?::uuid", verifying);
            return null;
        });
        JsonNode queue = get("/api/bom/cbom/remediation/queue");
        assertTrue(contains(queue.path("overdue"), overdue));
        assertTrue(contains(queue.path("verificationQueue"), verifying));
        int open = 0, late = 0;
        for (JsonNode sla : queue.path("slaBySeverity")) { open += sla.path("open").asInt(); late += sla.path("overdue").asInt(); }
        assertEquals(crypto.size(), open);
        assertTrue(late >= 1);

        inTenant(() -> jdbc.update("update findings set status = 'RESOLVED', closed_at = now(), closed_reason = 'VERIFIED_REASSESSMENT',"
                + " due_at = now() + interval '1 day' where id = ?::uuid", verifying));
        JsonNode effectiveness = get("/api/bom/cbom/remediation/effectiveness?days=30");
        assertTrue(effectiveness.path("closed").asInt() >= 1);
        assertEquals(1, effectiveness.path("closuresByReason").path("VERIFIED_REASSESSMENT").asInt());
        assertEquals(1, effectiveness.path("verifiedClosures").asInt());
        assertTrue(effectiveness.path("opened").asInt() >= crypto.size());
        JsonNode bySeverity = effectiveness.path("bySeverity").get(0);
        assertEquals(1.0, bySeverity.path("closedWithinSla").asDouble(), 0.0001);
    }

    private boolean contains(JsonNode items, String findingId) {
        for (JsonNode item : items) if (findingId.equals(item.path("findingId").asText())) return true;
        return false;
    }

    private <T> T inTenant(Supplier<T> work) {
        Tenant tenant = tenantService.getDefaultTenant();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
        try {
            return work.get();
        } finally {
            TenantContext.clear();
        }
    }

    private JsonNode json(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private JsonNode get(String path) throws Exception {
        return json(mockMvc.perform(asPlatformOwner(authedGet(path))).andExpect(status().isOk()).andReturn());
    }
}
