package com.prototype.vulnwatch.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/**
 * Phase 0B §4.12 (decided November 14, 2026): the CVE ticket endpoints and the ticket preview admit only PLATFORM_OWNER,
 * TENANT_ADMIN and SECURITY_ANALYST, like single-finding tickets. Before E11 the CVE endpoints had no role check.
 */
@PostgresControllerIntegrationTest
class TicketAuthorizationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ticket_authorization");
    private static final String PASSWORD = "password-123";
    private static final String PASSWORD_HASH = BCrypt.hashpw(PASSWORD, BCrypt.gensalt(10));
    private static final List<String> ROLES = List.of("TENANT_ADMIN", "INVENTORY_ADMIN", "SECURITY_ANALYST", "READ_ONLY_AUDITOR");
    private static final Set<String> WRITERS = Set.of("TENANT_ADMIN", "SECURITY_ANALYST");
    private static final Map<String, String> TOKENS = new java.util.concurrent.ConcurrentHashMap<>();

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("APP_JWT_HMAC_SECRET", () -> "ticket-authz-regression-secret-32-bytes!");
        registry.add("app.security.jwt.keycloak-client-id", () -> "scout-ui");
    }

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper json;
    @Autowired private AppUserRepository users;
    @Autowired private TenantMembershipRepository memberships;
    @Autowired private TenantService tenantService;
    @Autowired private TenantKeyRegistry keys;

    private record Endpoint(boolean write, String method, String path, Object body) { }

    static Stream<Arguments> matrix() {
        String missing = UUID.randomUUID().toString();
        Map<String, Object> cveBody = Map.of("severity", "HIGH", "affectedAssets", List.of());
        List<Endpoint> endpoints = List.of(
                new Endpoint(true, "POST", "/api/cve-detail/CVE-1900-0001/ticket", cveBody),
                new Endpoint(true, "POST", "/api/cve-detail/CVE-1900-0001/servicenow-incident", cveBody),
                new Endpoint(true, "POST", "/api/tickets/preview", Map.of("findingIds", List.of(missing))),
                new Endpoint(true, "POST", "/api/findings/" + missing + "/ticket", Map.of()),
                new Endpoint(false, "GET", "/api/ticketing/status", null));
        List<Arguments> cases = new ArrayList<>();
        for (String role : ROLES) for (Endpoint e : endpoints) cases.add(Arguments.of(role, e));
        return cases.stream();
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("matrix")
    void everyRoleGetsExactlyTheMatrixDecision(String role, Endpoint endpoint) throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        keys.provision(tenant.getId());
        String token = TOKENS.computeIfAbsent(role, r -> login(member(r, tenant)));
        int status = mvc.perform(request(endpoint).header("Authorization", "Bearer " + token)).andReturn().getResponse().getStatus();
        boolean allowed = !endpoint.write() || WRITERS.contains(role);
        // 503 is the business answer "no ticketing system is configured", reached only after authorization passed.
        if (allowed) assertThat(status).as(role + " " + endpoint).isNotIn(401, 403, 500);
        else assertThat(status).as(role + " " + endpoint).isEqualTo(403);
    }

    private MockHttpServletRequestBuilder request(Endpoint e) throws Exception {
        MockHttpServletRequestBuilder builder = "GET".equals(e.method()) ? get(e.path()) : post(e.path());
        if (e.body() != null) builder.contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(e.body()));
        return builder;
    }

    private AppUser member(String role, Tenant tenant) {
        AppUser user = new AppUser();
        user.setExternalSubject(role.toLowerCase() + "-" + UUID.randomUUID() + "@example.test");
        user.setEmail(user.getExternalSubject());
        user.setDisplayName(role);
        user.setPasswordHash(PASSWORD_HASH);
        user.setPasswordSetAt(Instant.now());
        user.setStatus("ACTIVE");
        user.setPlatformOwner(false);
        AppUser saved = users.save(user);
        TenantMembership membership = new TenantMembership();
        membership.setUser(saved);
        membership.setTenant(tenant);
        membership.setRole(role);
        membership.setStatus("ACTIVE");
        memberships.save(membership);
        return saved;
    }

    private String login(AppUser user) {
        try {
            MvcResult result = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                    .content(json.writeValueAsString(Map.of("email", user.getEmail(), "password", PASSWORD)))).andExpect(status().isOk()).andReturn();
            return com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.token");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
