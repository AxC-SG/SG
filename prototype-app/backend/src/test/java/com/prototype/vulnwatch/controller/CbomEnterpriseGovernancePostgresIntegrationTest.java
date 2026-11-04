package com.prototype.vulnwatch.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.cbom.CbomAssessmentWorkerService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * Milestone 5 enterprise governance with real JWT tenant members and a real ingest key: the
 * single-job CI gate token, environment gate policies, rule activation by a direct tenant admin
 * with the richer preview, PQC migration campaigns and portfolio rollups.
 */
@PostgresControllerIntegrationTest
class CbomEnterpriseGovernancePostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("cbom_enterprise");
    private static final String JWT_SECRET = "cbom-enterprise-regression-secret-32-bytes";
    private static final String PASSWORD = "password-123";
    private static final String PASSWORD_HASH = BCrypt.hashpw(PASSWORD, BCrypt.gensalt(10));
    private static final String SERIAL = "urn:uuid:5c1b7a52-3f0e-4d7b-9a1e-0b6c2d4e8f11";

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("APP_JWT_HMAC_SECRET", () -> JWT_SECRET);
        registry.add("app.security.jwt.keycloak-client-id", () -> "scout-ui");
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private AppUserRepository users;
    @Autowired private TenantMembershipRepository memberships;
    @Autowired private TenantService tenantService;
    @Autowired private CbomAssessmentWorkerService worker;
    @Autowired private FindingDeltaQueueService deltaQueue;

    @Test
    void ciGateTokenReadsOnlyItsOwnDocumentUnderTheEnvironmentPolicy() throws Exception {
        String admin = tokenFor("TENANT_ADMIN");
        String analyst = tokenFor("SECURITY_ANALYST");
        String key = json(mockMvc.perform(post("/api/bom/ingest-keys").header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"ci\"}")).andExpect(status().isCreated()).andReturn())
                .path("token").asText();

        mockMvc.perform(put("/api/bom/cbom/governance/gate-policies/production").header("Authorization", "Bearer " + analyst)
                .contentType(MediaType.APPLICATION_JSON).content("{\"failOnSeverities\":[\"CRITICAL\"]}")).andExpect(status().isForbidden());
        JsonNode policy = json(mockMvc.perform(put("/api/bom/cbom/governance/gate-policies/production").header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).content("{\"failOnSeverities\":[\"CRITICAL\"],\"minimumCompleteness\":0.5}"))
                .andExpect(status().isOk()).andReturn());
        assertEquals(List.of("CRITICAL"), objectMapper.convertValue(policy.path("failOnSeverities"), List.class));
        mockMvc.perform(put("/api/bom/cbom/governance/gate-policies/production").header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).content("{\"failOnSeverities\":[\"HIGH\"],\"version\":42}")).andExpect(status().isConflict());
        mockMvc.perform(get("/api/bom/cbom/governance/gate-policies").header("Authorization", "Bearer " + key)).andExpect(status().isForbidden());

        mockMvc.perform(push(key, "?bomType=CBOM&environment=Prod%20Env", "gate-" + UUID.randomUUID())).andExpect(status().isBadRequest());
        JsonNode pushed = json(mockMvc.perform(push(key, "?bomType=CBOM&environment=production&pipeline=release", "gate-" + UUID.randomUUID()))
                .andExpect(status().is2xxSuccessful()).andReturn());
        String bomId = pushed.path("bomId").asText();
        String gateToken = pushed.path("gateToken").asText();
        assertTrue(gateToken.startsWith("sgg_"));
        assertEquals("production", pushed.path("gateEnvironment").asText());

        JsonNode plain = pollStatus(key, bomId, null);
        assertTrue(plain.path("gate").isMissingNode() || plain.path("gate").isNull(), "the ingest key alone sees no gate result");
        assertEquals("PENDING", pollStatus(key, bomId, gateToken).path("gate").path("state").asText());

        awaitAssessment(admin, bomId);
        JsonNode gate = pollStatus(key, bomId, gateToken).path("gate");
        assertTrue(List.of("PASS", "FAIL").contains(gate.path("state").asText()), gate.toString());
        assertEquals("FAIL".equals(gate.path("state").asText()), gate.path("reasons").size() > 0);
        assertTrue(gate.path("rulePackageDigest").asText().startsWith("sha256:"));

        String other = json(mockMvc.perform(push(key, "?bomType=CBOM", "gate-" + UUID.randomUUID())).andExpect(status().is2xxSuccessful()).andReturn())
                .path("bomId").asText();
        mockMvc.perform(get("/api/bom/ingest/" + other + "/status").header("Authorization", "Bearer " + key)
                .header("X-Scout-Gate-Token", gateToken)).andExpect(status().isForbidden());
        mockMvc.perform(get("/api/bom/ingest/" + bomId + "/status").header("Authorization", "Bearer " + key)
                .header("X-Scout-Gate-Token", "sgg_not-a-token")).andExpect(status().isForbidden());
        assertEquals(0L, (long) inTenant(() -> jdbc.queryForObject(
                "select count(*) from cbom_gate_tokens where token_hash = ?", Long.class, gateToken)), "tokens are stored hashed");
    }

    @Test
    void directTenantAdminActivatesRulesWithARuleAndParameterDiffAndHistory() throws Exception {
        String admin = tokenFor("TENANT_ADMIN");
        String draft = "{\"versionPolicy\":\"PINNED\",\"pinnedVersion\":\"1.0.0\",\"parameters\":{\"minimumRsaBits\":3072},\"reason\":\"raise baseline\"}";
        JsonNode preview = json(mockMvc.perform(post("/api/bom/cbom/governance/rules/preview").header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).content(draft)).andExpect(status().isOk()).andReturn());
        assertEquals("1.0.0", preview.path("toVersion").asText());
        assertEquals(2048, preview.path("changedParameters").path("minimumRsaBits").get(0).asInt());
        assertEquals(3072, preview.path("changedParameters").path("minimumRsaBits").get(1).asInt());
        assertEquals(0, preview.path("addedRules").size());

        // An existing CBOM with an RSA-2048 key: compliant under the default 2048-bit minimum.
        String bomId = json(mockMvc.perform(push(admin, "?bomType=CBOM", "rules-" + UUID.randomUUID())).andExpect(status().is2xxSuccessful()).andReturn())
                .path("bomId").asText();
        inTenant(() -> jdbc.update("""
                insert into cbom_components (id, tenant_id, asset_id, source_bom_id, bom_ref, component_fingerprint, name, asset_type,
                    primitive, key_size, active, created_at, updated_at)
                select gen_random_uuid(), tenant_id, asset_id, id, 'crypto/algorithm/rsa-2048', 'rsa-2048-' || id, 'RSA-2048', 'ALGORITHM',
                       'rsa', 2048, true, now(), now() from bom_ingestion_records where id = ?::uuid
                """, bomId));
        assertEquals(0L, (long) rsaFindings(bomId));

        JsonNode saved = json(mockMvc.perform(put("/api/bom/cbom/governance/rules").header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).content(draft)).andExpect(status().isOk()).andReturn());
        assertEquals(1L, (long) rsaFindings(bomId), "activating a 3072-bit minimum re-evaluates existing CBOMs");
        assertEquals("RSA key size below 3072 bits", inTenant(() -> jdbc.queryForObject("""
                select r.title from cbom_risk_findings r join cbom_components c on c.id = r.cbom_component_id
                 where c.source_bom_id = ?::uuid and r.rule_id = 'CBOM-RSA-SMALL-KEY' and r.status = 'OPEN'
                """, String.class, bomId)));
        assertTrue(saved.path("history").get(0).path("impactJson").asText().contains("reevaluatedCboms"));
        assertEquals("PINNED", saved.path("versionPolicy").asText());
        assertEquals(3072, saved.path("parameters").path("minimumRsaBits").asInt());
        assertEquals("TENANT_UPDATE", saved.path("history").get(0).path("action").asText());
        assertEquals("raise baseline", saved.path("history").get(0).path("reason").asText());
    }

    @Test
    void pqcCampaignsTrackProgressAndPortfolioRollsUpByGroup() throws Exception {
        String admin = tokenFor("TENANT_ADMIN");
        String key = json(mockMvc.perform(post("/api/bom/ingest-keys").header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"pqc\"}")).andExpect(status().isCreated()).andReturn()).path("token").asText();
        mockMvc.perform(push(key, "?bomType=CBOM", "pqc-" + UUID.randomUUID())).andExpect(status().is2xxSuccessful());
        for (int i = 0; i < 5; i++) deltaQueue.processPendingDeltas();
        int quantum = inTenant(() -> jdbc.update("""
                update findings set reason_code = 'QUANTUM_VULNERABLE'
                 where id in (select id from findings where finding_kind = 'CRYPTO' and status = 'OPEN' order by created_at limit 2)
                """));
        assertEquals(2, quantum);

        mockMvc.perform(post("/api/bom/cbom/pqc/campaigns").header("Authorization", "Bearer " + admin).contentType(MediaType.APPLICATION_JSON)
                .content("{\"name\":\"PQC wave 1\"}")).andExpect(status().isBadRequest());
        JsonNode campaign = json(mockMvc.perform(post("/api/bom/cbom/pqc/campaigns").header("Authorization", "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"PQC wave 1\",\"dueAt\":\"2027-06-30T00:00:00Z\",\"assignedTo\":\"pqc-team\"}"))
                .andExpect(status().isCreated()).andReturn());
        String campaignId = campaign.path("summary").path("id").asText();

        JsonNode progress = json(mockMvc.perform(get("/api/bom/cbom/pqc/progress").header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk()).andReturn());
        assertEquals(2, progress.path("openQuantumVulnerable").asInt());
        assertEquals(2, progress.path("inCampaigns").asInt());
        assertEquals(0, progress.path("notInCampaign").asInt());
        JsonNode wave = progress.path("campaigns").get(0);
        assertEquals(campaignId, wave.path("campaignId").asText());
        assertEquals(2, wave.path("open").asInt());
        assertEquals(0.0, wave.path("percentComplete").asDouble(), 0.0001);
        assertEquals("pqc-team", wave.path("owners").get(0).asText());

        JsonNode portfolio = json(mockMvc.perform(get("/api/bom/cbom/portfolio?groupBy=environment").header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk()).andReturn());
        assertTrue(portfolio.path("groups").size() >= 1);
        int components = 0;
        for (JsonNode group : portfolio.path("groups")) components += group.path("components").asInt();
        assertTrue(components >= 9);
        mockMvc.perform(get("/api/bom/cbom/portfolio?groupBy=password").header("Authorization", "Bearer " + admin)).andExpect(status().isBadRequest());
    }

    // ---------------------------------------------------------------- helpers

    private org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder push(String key, String query, String application) throws Exception {
        String body = Files.readString(Path.of("src/test/resources/fixtures/bom/cbom-9-assets.cdx.json"))
                .replace(SERIAL, "urn:uuid:" + UUID.randomUUID()).replace("scoutgrid-prototype-app", application);
        return post("/api/bom/ingest" + query).header("Authorization", "Bearer " + key)
                .contentType(MediaType.APPLICATION_JSON).content(body.getBytes(StandardCharsets.UTF_8));
    }

    private JsonNode pollStatus(String key, String bomId, String gateToken) throws Exception {
        var request = get("/api/bom/ingest/" + bomId + "/status").header("Authorization", "Bearer " + key);
        if (gateToken != null) request.header("X-Scout-Gate-Token", gateToken);
        return json(mockMvc.perform(request).andExpect(status().isOk()).andReturn());
    }

    private void awaitAssessment(String admin, String bomId) throws Exception {
        for (int attempt = 0; attempt < 60; attempt++) {
            worker.poll();
            JsonNode runs = json(mockMvc.perform(get("/api/bom/cbom/assessments?bomId=" + bomId).header("Authorization", "Bearer " + admin))
                    .andExpect(status().isOk()).andReturn());
            for (JsonNode run : runs) if ("SUCCEEDED".equals(run.path("status").asText())) return;
            Thread.sleep(250);
        }
        throw new AssertionError("assessment did not complete");
    }

    private String tokenFor(String role) throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser user = new AppUser();
        user.setExternalSubject(role.toLowerCase() + "-" + UUID.randomUUID() + "@example.test");
        user.setEmail(user.getExternalSubject());
        user.setDisplayName(role);
        user.setPasswordHash(PASSWORD_HASH);
        user.setPasswordSetAt(Instant.now());
        user.setStatus("ACTIVE");
        user = users.save(user);
        TenantMembership membership = new TenantMembership();
        membership.setUser(user);
        membership.setTenant(tenant);
        membership.setRole(role);
        membership.setStatus("ACTIVE");
        memberships.save(membership);
        MvcResult result = mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(Map.of("email", user.getEmail(), "password", PASSWORD))))
                .andExpect(status().isOk()).andReturn();
        return com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.token");
    }

    private long rsaFindings(String bomId) {
        return inTenant(() -> jdbc.queryForObject("""
                select count(*) from cbom_risk_findings r join cbom_components c on c.id = r.cbom_component_id
                 where c.source_bom_id = ?::uuid and r.rule_id = 'CBOM-RSA-SMALL-KEY' and r.status = 'OPEN'
                """, Long.class, bomId));
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
}
