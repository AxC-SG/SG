package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static com.prototype.vulnwatch.support.AuthRequest.authedPut;
import static com.prototype.vulnwatch.support.AuthRequest.withUser;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/** Fix Intelligence and patch connector routes through real HTTP, so role checks are exercised. */
@PostgresControllerIntegrationTest
class FixIntelligenceControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("fix_intelligence_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;

    private static final String CONTROL = """
            {"fixType":"WORKAROUND","title":"Disable SMBv1","severity":"HIGH","ecosystem":"WINDOWS",
             "cveIds":["CVE-2017-0144"],"assetIds":[],"submit":true}
            """;

    @Test
    void readsAreOpenAndSummaryNeverDividesByZero() throws Exception {
        mockMvc.perform(authedGet("/api/fix-intelligence/summary?view=patches"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalFixes").value(0));
        mockMvc.perform(authedGet("/api/fix-intelligence/fixes/{id}", UUID.randomUUID()))
                .andExpect(status().isNotFound());
        mockMvc.perform(authedGet("/api/fix-intelligence/fixes?view=bogus"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void analystProposesAndADifferentAdminApproves() throws Exception {
        String body = mockMvc.perform(withUser(authedPost("/api/fix-intelligence/fixes"), "analyst-1")
                        .contentType(MediaType.APPLICATION_JSON).content(CONTROL))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("PROPOSED"))
                .andReturn().getResponse().getContentAsString();
        String fixId = objectMapper.readTree(body).get("id").asText();

        // An analyst cannot approve at all; an admin cannot approve their own proposal.
        mockMvc.perform(withUser(authedPost("/api/fix-intelligence/fixes/{id}/approve", fixId), "analyst-2"))
                .andExpect(status().isForbidden());
        mockMvc.perform(withUser(asPlatformOwner(authedPost("/api/fix-intelligence/fixes/{id}/approve", fixId)), "analyst-1"))
                .andExpect(status().isForbidden());
        mockMvc.perform(withUser(asPlatformOwner(authedPost("/api/fix-intelligence/fixes/{id}/approve", fixId)), "admin-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("ACTIVE"))
                .andExpect(jsonPath("$.approvedBy").value("admin-1"));

        mockMvc.perform(authedGet("/api/fix-intelligence/context?cveId=CVE-2017-0144"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fixes.length()").value(1));
    }

    @Test
    void patchConnectorsRequireAnAdminAndRejectUnknownProviders() throws Exception {
        mockMvc.perform(authedGet("/api/connectors/patch/altiris"))
                .andExpect(status().isNotFound());
        mockMvc.perform(authedPut("/api/connectors/patch/tanium")
                        .contentType(MediaType.APPLICATION_JSON).content("{\"baseUrl\":\"https://acme.cloud.tanium.com\"}"))
                .andExpect(status().isForbidden());
    }
}
