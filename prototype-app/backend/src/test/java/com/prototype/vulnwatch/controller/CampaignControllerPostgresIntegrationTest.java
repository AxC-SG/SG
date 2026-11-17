package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asAnalyst;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.FindingWorkspaceSeedSupport;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@PostgresControllerIntegrationTest
class CampaignControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("campaign_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SbomUploadRepository sbomUploadRepository;

    @Autowired
    private InventoryComponentRepository inventoryComponentRepository;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private TenantSchemaExecutionService tenantSchemaExecutionService;

    @Autowired
    private TenantKeyRegistry keys;

    private Tenant tenant;
    private FindingWorkspaceSeedSupport.SeededWorkspace seededWorkspace;

    @BeforeEach
    void seedWorkspace() {
        tenant = tenantService.getDefaultTenant();
        // Custom recipient addresses are tenant ciphertext (Phase 0B §4.6).
        keys.provision(tenant.getId());
        seededWorkspace = new FindingWorkspaceSeedSupport(
                assetRepository,
                sbomUploadRepository,
                inventoryComponentRepository,
                vulnerabilityRepository,
                findingRepository,
                tenantSchemaExecutionService
        ).seedCriticalWorkspace(tenant, 3, 1);
    }

    @Test
    void createCampaignReturnsScopedFindingsAssetsAndNotificationAttempts() throws Exception {
        String body = """
                {
                  "name": "Kernel patch sprint",
                  "summary": "Drive resolver action for the active Linux package backlog.",
                  "cveIds": ["%s"],
                  "dueAt": "2026-07-01T00:00:00Z",
                  "notifyGroups": [
                    {
                      "groupName": "Platform Ops",
                      "groupEmail": "platform.ops@example.com",
                      "roleLabel": "Owner group",
                      "triggerSummary": "Status changes, notes, closure risk",
                      "notificationsPaused": false
                    }
                  ],
                  "watchlist": [
                    {
                      "entryType": "USER",
                      "label": "Alex Analyst",
                      "email": "alex.analyst@example.com",
                      "triggerPolicy": "ALL_EVENTS",
                      "active": true
                    }
                  ],
                  "launchNote": "Launch the resolver swarm today."
                }
                """.formatted(seededWorkspace.vulnerabilityId());

        MvcResult result = mockMvc.perform(asAnalyst(authedPost("/api/campaigns")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.summary.name").value("Kernel patch sprint"))
                .andExpect(jsonPath("$.summary.status").value("ACTIVE"))
                .andExpect(jsonPath("$.summary.cveIds[0]").value(seededWorkspace.vulnerabilityId()))
                .andExpect(jsonPath("$.summary.totalFindings").value(3))
                .andExpect(jsonPath("$.summary.scopeKind").value("CVE"))
                .andExpect(jsonPath("$.summary.membershipState").value("COMPLETE"))
                .andExpect(jsonPath("$.summary.remediatedCount").value(0))
                .andExpect(jsonPath("$.summary.activeRemainingCount").value(3))
                .andExpect(jsonPath("$.summary.outcomes.OPEN").value(3))
                .andExpect(jsonPath("$.summary.assetCount").value(1))
                .andExpect(jsonPath("$.notifyGroups[0].recipientType").value("CUSTOM"))
                .andExpect(jsonPath("$.notifyGroups[0].ownerRecipient").value(false))
                .andExpect(jsonPath("$.notifyGroups[0].groupEmail").value("platform.ops@example.com"))
                .andExpect(jsonPath("$.watchlist[0].email").value("alex.analyst@example.com"))
                .andExpect(jsonPath("$.notes[0].body").value("Launch the resolver swarm today."))
                .andExpect(jsonPath("$.deliveryAttempts.length()").value(2))
                .andExpect(jsonPath("$.activity[0].activityType").value("NOTIFIED"))
                .andReturn();

        JsonNode created = objectMapper.readTree(result.getResponse().getContentAsString());
        String campaignId = created.path("summary").path("id").asText();

        mockMvc.perform(asAnalyst(authedGet("/api/campaigns")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(campaignId))
                .andExpect(jsonPath("$[0].name").value("Kernel patch sprint"));

        mockMvc.perform(asAnalyst(authedGet("/api/campaigns?status=ACTIVE")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(campaignId));
    }

    @Test
    void campaignLifecycleEndpointsUpdateStatusExceptionsAndEditableTargets() throws Exception {
        JsonNode created = createCampaign("Resolver runway");
        String campaignId = created.path("summary").path("id").asText();
        String notifyGroupId = created.path("notifyGroups").get(0).path("id").asText();
        String watchlistEntryId = created.path("watchlist").get(0).path("id").asText();

        String exceptionBody = """
                {
                  "findingDisplayId": "%s",
                  "assetName": "findings-workspace-scale-host",
                  "packageName": "workspace-seed-000",
                  "title": "Patch train dependency freeze",
                  "reason": "Upstream maintenance window blocks immediate rollout.",
                  "decisionDueAt": "2026-06-20T00:00:00Z"
                }
                """.formatted(created.path("findings").get(0).path("displayId").asText());

        MvcResult exceptionResult = mockMvc.perform(asAnalyst(authedPost("/api/campaigns/" + campaignId + "/exceptions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(exceptionBody)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.title").value("Patch train dependency freeze"))
                .andExpect(jsonPath("$.status").value("PENDING_DECISION"))
                .andReturn();

        String exceptionId = objectMapper.readTree(exceptionResult.getResponse().getContentAsString()).path("id").asText();

        mockMvc.perform(asAnalyst(authedPost("/api/campaigns/" + campaignId + "/notify-groups/" + notifyGroupId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "groupName": "Platform Resolve",
                                  "groupEmail": "resolve@example.com",
                                  "roleLabel": "Resolver group",
                                  "triggerSummary": "Notes only",
                                  "notificationsPaused": true
                                }
                                """)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.notifyGroups[0].groupName").value("Platform Resolve"))
                .andExpect(jsonPath("$.notifyGroups[0].notificationsPaused").value(true));

        mockMvc.perform(asAnalyst(authedPost("/api/campaigns/" + campaignId + "/watchlist/" + watchlistEntryId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "label": "Jordan Resolver",
                                  "email": "jordan@example.com",
                                  "triggerPolicy": "STATUS_CHANGES",
                                  "active": true
                                }
                                """)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.watchlist[0].label").value("Jordan Resolver"))
                .andExpect(jsonPath("$.watchlist[0].triggerPolicy").value("STATUS_CHANGES"));

        mockMvc.perform(asAnalyst(authedPost("/api/campaigns/" + campaignId + "/exceptions/" + exceptionId + "/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"status": "APPROVED"}
                                """)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.exceptions[0].status").value("APPROVED"));

        MvcResult statusResult = mockMvc.perform(asAnalyst(authedPost("/api/campaigns/" + campaignId + "/status")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "status": "CLOSED",
                                  "note": "Resolver handoff completed."
                                }
                                """)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.status").value("CLOSED"))
                .andExpect(jsonPath("$.notes[0].body").value("Resolver handoff completed."))
                .andReturn();

        JsonNode updated = objectMapper.readTree(statusResult.getResponse().getContentAsString());
        assertEquals("CLOSED", updated.path("summary").path("status").asText());
        assertTrue(updated.path("activity").isArray());
        assertTrue(updated.path("deliveryAttempts").size() >= 4);
        assertTrue(updated.path("exceptions").isArray());
    }

    @Test
    void ledgerEndpointsPageMembersReportReconciliationAndRejectOwnershipFields() throws Exception {
        JsonNode created = createCampaign("Ledger reads");
        String campaignId = created.path("summary").path("id").asText();

        MvcResult first = mockMvc.perform(asAnalyst(authedGet("/api/campaigns/" + campaignId + "/members?limit=2")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items.length()").value(2))
                .andExpect(jsonPath("$.items[0].addSource").value("CREATE"))
                .andExpect(jsonPath("$.items[0].outcome").value("OPEN"))
                .andExpect(jsonPath("$.items[0].currentOwnership.authorityState").value("LEGACY_PENDING_MIGRATION"))
                .andReturn();
        String cursor = objectMapper.readTree(first.getResponse().getContentAsString()).path("nextCursor").asText();
        mockMvc.perform(asAnalyst(authedGet("/api/campaigns/" + campaignId + "/members?limit=2&cursor=" + cursor)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.items.length()").value(1))
                .andExpect(jsonPath("$.nextCursor").doesNotExist());
        mockMvc.perform(asAnalyst(authedGet("/api/campaigns/" + campaignId + "/members?outcome=BOGUS")))
                .andExpect(status().isBadRequest());

        mockMvc.perform(asAnalyst(authedGet("/api/campaigns/" + campaignId + "/reconciliation")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.scopeKind").value("CVE"))
                .andExpect(jsonPath("$.membershipState").value("COMPLETE"))
                .andExpect(jsonPath("$.members").value(3));
        mockMvc.perform(asAnalyst(authedGet("/api/campaigns/" + campaignId + "/owner-buckets?groupBy=atAdd")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].members").value(3));

        mockMvc.perform(asAnalyst(authedPost("/api/campaigns/preview")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Preview\",\"cveIds\":[\"%s\"]}".formatted(seededWorkspace.vulnerabilityId()))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.memberCount").value(3))
                .andExpect(jsonPath("$.exceedsCreateBound").value(false));

        mockMvc.perform(asAnalyst(authedPost("/api/campaigns")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Owned\",\"cveIds\":[\"%s\"],\"ownerGroup\":\"Platform Ops\"}"
                                .formatted(seededWorkspace.vulnerabilityId()))))
                .andExpect(status().isBadRequest());
        mockMvc.perform(asAnalyst(authedPost("/api/campaigns")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"name\":\"Both\",\"cveIds\":[\"%s\"],\"findingIds\":[\"%s\"]}"
                                .formatted(seededWorkspace.vulnerabilityId(), java.util.UUID.randomUUID()))))
                .andExpect(status().isBadRequest());
        mockMvc.perform(asAnalyst(authedPost("/api/campaigns/" + campaignId + "/exceptions")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"findingId\":\"%s\",\"title\":\"t\",\"reason\":\"r\"}".formatted(java.util.UUID.randomUUID()))))
                .andExpect(status().isNotFound());
    }

    private JsonNode createCampaign(String name) throws Exception {
        String body = """
                {
                  "name": "%s",
                  "summary": "Campaign integration test fixture.",
                  "cveIds": ["%s"],
                  "dueAt": "%s",
                  "notifyGroups": [
                    {
                      "groupName": "Platform Ops",
                      "groupEmail": "platform.ops@example.com",
                      "roleLabel": "Owner group",
                      "triggerSummary": "Status changes",
                      "notificationsPaused": false
                    }
                  ],
                  "watchlist": [
                    {
                      "entryType": "USER",
                      "label": "Alex Analyst",
                      "email": "alex@example.com",
                      "triggerPolicy": "ALL_EVENTS",
                      "active": true
                    }
                  ]
                }
                """.formatted(name, seededWorkspace.vulnerabilityId(), Instant.parse("2026-07-01T00:00:00Z"));

        MvcResult result = mockMvc.perform(asAnalyst(authedPost("/api/campaigns")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body)))
                .andExpect(status().isCreated())
                .andReturn();
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }
}
