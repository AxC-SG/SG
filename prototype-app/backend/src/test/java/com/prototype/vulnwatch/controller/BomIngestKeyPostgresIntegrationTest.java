package com.prototype.vulnwatch.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Ingest keys end to end: a real tenant admin manages them, a pipeline pushes with them. */
@PostgresControllerIntegrationTest
class BomIngestKeyPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("bom_ingest_keys");
    private static final String JWT_SECRET = "bom-ingest-key-regression-secret-32-bytes";
    private static final String PASSWORD = "password-123";
    private static final String PASSWORD_HASH = BCrypt.hashpw(PASSWORD, BCrypt.gensalt(10));

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("APP_JWT_HMAC_SECRET", () -> JWT_SECRET);
        registry.add("app.security.jwt.keycloak-client-id", () -> "scout-ui");
    }

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private AppUserRepository users;
    @Autowired
    private TenantMembershipRepository memberships;
    @Autowired
    private TenantService tenantService;

    private String adminToken() throws Exception {
        return tokenFor("TENANT_ADMIN");
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

    private JsonNode json(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private JsonNode createKey(String adminToken, String name, Integer expiresInDays) throws Exception {
        String body = expiresInDays == null
                ? "{\"name\":\"" + name + "\"}"
                : "{\"name\":\"" + name + "\",\"expiresInDays\":" + expiresInDays + "}";
        return json(mockMvc.perform(post("/api/bom/ingest-keys")
                        .header("Authorization", "Bearer " + adminToken)
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isCreated()).andReturn());
    }

    private static String sbom(String app) {
        return "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"serialNumber\":\"urn:uuid:"
                + UUID.randomUUID() + "\",\"metadata\":{\"component\":{\"type\":\"application\",\"name\":\""
                + app + "\"}},\"components\":[{\"type\":\"library\",\"name\":\"left-pad\","
                + "\"version\":\"1.0.0\",\"purl\":\"pkg:npm/left-pad@1.0.0\"}]}";
    }

    private MockHttpServletRequestBuilder keyedPush(String token, String query, String body) {
        return post("/api/bom/ingest" + query)
                .header("Authorization", "Bearer " + token)
                .contentType(MediaType.APPLICATION_JSON)
                .content(body.getBytes(StandardCharsets.UTF_8));
    }

    @Test
    void aKeyIsShownOnceAndAPushWithItNeedsNoOtherCredential() throws Exception {
        String admin = adminToken();
        JsonNode created = createKey(admin, "ci-prod", 30);
        String token = created.path("token").asText();
        assertTrue(token.startsWith("sgk_"));
        assertEquals("ACTIVE", created.path("key").path("state").asText());

        String listBody = mockMvc.perform(get("/api/bom/ingest-keys").header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        assertTrue(listBody.contains(created.path("key").path("keyPrefix").asText()));
        assertFalse(listBody.contains(token), "the full key must never be returned again");
        assertFalse(listBody.contains("key_hash") || listBody.contains("keyHash"));

        JsonNode pushed = json(mockMvc.perform(keyedPush(token, "?bomType=SBOM&pipeline=gitlab-ci&buildId=77",
                        sbom("keyed-" + UUID.randomUUID().toString().substring(0, 8))))
                .andExpect(status().isCreated()).andReturn());
        assertEquals("CREATED", pushed.path("action").asText());

        JsonNode state = json(mockMvc.perform(get(pushed.path("statusUrl").asText())
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk()).andReturn());
        assertEquals("gitlab-ci", state.path("pipeline").asText());
        assertEquals("77", state.path("build").asText());
    }

    @Test
    void aKeyCannotBeUsedOutsideTheIngestEndpoints() throws Exception {
        String token = createKey(adminToken(), "scope-check", null).path("token").asText();

        for (MockHttpServletRequestBuilder request : List.of(
                get("/api/bom/components").header("Authorization", "Bearer " + token),
                get("/api/bom/ingest-keys").header("Authorization", "Bearer " + token),
                post("/api/bom/ingest-keys").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"escalate\"}"),
                get("/api/findings").header("Authorization", "Bearer " + token))) {
            JsonNode error = json(mockMvc.perform(request).andExpect(status().isForbidden()).andReturn());
            assertEquals("KEY_SCOPE", error.path("code").asText());
        }
    }

    @Test
    void aKeyCannotAssertCompleteInventory() throws Exception {
        String token = createKey(adminToken(), "completeness", null).path("token").asText();

        JsonNode error = json(mockMvc.perform(keyedPush(token,
                        "?bomType=SBOM&completeness=COMPLETE_ASSET_SOFTWARE", sbom("complete-app")))
                .andExpect(status().isForbidden()).andReturn());
        assertEquals("COMPLETENESS_NOT_PERMITTED", error.path("code").asText());
    }

    @Test
    void revokedExpiredWrongAndMalformedKeysAreRejectedAlike() throws Exception {
        String admin = adminToken();
        JsonNode revoked = createKey(admin, "to-revoke", null);
        String revokedToken = revoked.path("token").asText();
        mockMvc.perform(delete("/api/bom/ingest-keys/{id}", revoked.path("key").path("id").asText())
                        .header("Authorization", "Bearer " + admin))
                .andExpect(status().isNoContent());

        JsonNode expiring = createKey(admin, "to-expire", 1);
        jdbc.update("UPDATE platform.bom_ingest_api_keys SET expires_at = now() - interval '1 hour' WHERE id = ?",
                UUID.fromString(expiring.path("key").path("id").asText()));

        String live = createKey(admin, "live", null).path("token").asText();
        String wrongSecret = live.substring(0, live.length() - 4) + (live.endsWith("0000") ? "1111" : "0000");

        for (String token : List.of(revokedToken, expiring.path("token").asText(), wrongSecret,
                "sgk_short", "sgk_" + "z".repeat(81))) {
            JsonNode error = json(mockMvc.perform(keyedPush(token, "?bomType=SBOM", sbom("rejected")))
                    .andExpect(status().isUnauthorized()).andReturn());
            assertEquals("INVALID_KEY", error.path("code").asText());
        }
        // The live key is untouched by revoking and expiring its siblings.
        mockMvc.perform(keyedPush(live, "?bomType=SBOM", sbom("still-live-" + UUID.randomUUID().toString().substring(0, 8))))
                .andExpect(status().isCreated());
    }

    @Test
    void anOrdinaryBearerTokenStillGoesThroughJwtValidation() throws Exception {
        mockMvc.perform(post("/api/bom/ingest?bomType=SBOM")
                        .header("Authorization", "Bearer not-an-ingest-key")
                        .contentType(MediaType.APPLICATION_JSON).content(sbom("jwt")))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void onlyTenantAdminsMintKeysAndInventoryAdminsMayListThem() throws Exception {
        String inventoryAdmin = tokenFor("INVENTORY_ADMIN");
        String auditor = tokenFor("READ_ONLY_AUDITOR");

        mockMvc.perform(post("/api/bom/ingest-keys").header("Authorization", "Bearer " + inventoryAdmin)
                        .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"nope\"}"))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/bom/ingest-keys").header("Authorization", "Bearer " + inventoryAdmin))
                .andExpect(status().isOk());
        mockMvc.perform(get("/api/bom/ingest-keys").header("Authorization", "Bearer " + auditor))
                .andExpect(status().isForbidden());
    }

    @Test
    void keyManagementValidatesInputAndOnlyRevokesActiveKeys() throws Exception {
        String admin = adminToken();
        for (String body : List.of("{\"name\":\"  \"}", "{\"name\":\"x\",\"expiresInDays\":0}")) {
            mockMvc.perform(post("/api/bom/ingest-keys").header("Authorization", "Bearer " + admin)
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isBadRequest());
        }
        mockMvc.perform(delete("/api/bom/ingest-keys/{id}", UUID.randomUUID())
                        .header("Authorization", "Bearer " + admin))
                .andExpect(status().isNotFound());
    }
}
