package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.hamcrest.Matchers.anyOf;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Controller-layer integration tests for the Phase 4 run-agent endpoint.
 * OpenAI is not available in CI so the service falls back to algorithmic confidence.
 */
@PostgresControllerIntegrationTest
class InvestigationAgentControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("investigation_agent_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private TenantRepository tenantRepository;

    @Test
    void runAgentWithEmptyCriteriaReturnsWellFormedResponse() throws Exception {
        String body = """
                {"criteria": []}
                """;
        mockMvc.perform(authedPost("/api/cve-detail/CVE-2024-99100/investigation/run-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.resolved").isArray())
                .andExpect(jsonPath("$.totalAssets").value(0))
                .andExpect(jsonPath("$.fpResults").isArray())
                .andExpect(jsonPath("$.eolResults").isArray())
                .andExpect(jsonPath("$.taskMeta").isMap())
                .andExpect(jsonPath("$.completedTaskIds").isArray())
                .andExpect(jsonPath("$.ranAt").isString());
    }

    @Test
    void runAgentWithUnknownSoftwareReturnsLowConfidence() throws Exception {
        String body = """
                {"criteria": [
                  {"id": "c1", "software": "nonexistent-agent-pkg", "version": "9.9.9", "vendor": ""}
                ]}
                """;
        mockMvc.perform(authedPost("/api/cve-detail/CVE-2024-99101/investigation/run-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.taskMeta['review-asset-inventory'].confidence")
                        .value(anyOf(is("LOW"), is("MEDIUM"), is("HIGH"))))
                .andExpect(jsonPath("$.taskMeta['review-asset-inventory'].producedBy").value("AGENT"))
                .andExpect(jsonPath("$.taskMeta['find-false-positive'].confidence")
                        .value(anyOf(is("LOW"), is("MEDIUM"), is("HIGH"))))
                .andExpect(jsonPath("$.taskMeta['end-of-life-analysis'].confidence")
                        .value(anyOf(is("LOW"), is("MEDIUM"), is("HIGH"))));
    }

    @Test
    void runAgentPersistsConfidenceOntoRunbook() throws Exception {
        String cveId = "CVE-2024-99102";
        String runBody = """
                {"criteria": []}
                """;
        mockMvc.perform(authedPost("/api/cve-detail/" + cveId + "/investigation/run-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(runBody))
                .andExpect(status().isOk());

        // Runbook should now exist with agent confidence populated.
        mockMvc.perform(authedGet("/api/cve-detail/" + cveId + "/investigation/runbook"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveExternalId").value(cveId))
                .andExpect(jsonPath("$.agentConfidence").isMap());
    }

    @Test
    void runAgentRequiresAuthentication() throws Exception {
        mockMvc.perform(
                org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .post("/api/cve-detail/CVE-2024-99103/investigation/run-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"criteria\":[]}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void internalTenantCanRunAgent() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        tenant.setPlanCode("ENTERPRISE");
        tenantRepository.save(tenant);

        mockMvc.perform(authedPost("/api/cve-detail/CVE-2024-99104/investigation/run-agent")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"criteria\":[]}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.taskMeta").isMap())
                .andExpect(jsonPath("$.completedTaskIds").isArray());
    }
}
