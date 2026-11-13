package com.prototype.vulnwatch.controller;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorization;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorization.Action;
import com.prototype.vulnwatch.service.ownership.TeamNamespaceService;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Plan §5: role × endpoint matrix for the ownership controllers, through the real filter chain and method security. */
@PostgresControllerIntegrationTest
class OwnershipAuthorizationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_authorization");
    private static final String PASSWORD = "password-123";
    private static final String PASSWORD_HASH = BCrypt.hashpw(PASSWORD, BCrypt.gensalt(10));
    private static final List<String> ROLES = List.of("TENANT_ADMIN", "INVENTORY_ADMIN", "SECURITY_ANALYST", "READ_ONLY_AUDITOR");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("APP_JWT_HMAC_SECRET", () -> "ownership-authz-regression-secret-32-bytes");
        registry.add("app.security.jwt.keycloak-client-id", () -> "scout-ui");
    }

    @Autowired private MockMvc mvc;
    @Autowired private ObjectMapper json;
    @Autowired private AppUserRepository users;
    @Autowired private TenantMembershipRepository memberships;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private TeamNamespaceService teams;

    /** One login per role for the whole class: the login endpoint is rate limited. */
    private static final Map<String, String> TOKENS = new java.util.concurrent.ConcurrentHashMap<>();

    private record Endpoint(Action action, String method, String path, Object body) { }

    static Stream<Arguments> matrix() {
        String missing = UUID.randomUUID().toString();
        List<Endpoint> endpoints = List.of(
                new Endpoint(Action.VIEW_DIRECTORY, "GET", "/api/directory/users?q=ab", null),
                new Endpoint(Action.WRITE_DIRECTORY, "POST", "/api/directory/users", Map.of("displayName", "Person " + UUID.randomUUID())),
                new Endpoint(Action.WRITE_DIRECTORY, "POST", "/api/directory/groups", Map.of("displayName", "Group " + UUID.randomUUID())),
                new Endpoint(Action.IMPORT_DIRECTORY, "GET", "/api/directory/imports/templates/users", null),
                new Endpoint(Action.VIEW_OWNERSHIP, "GET", "/api/ownership/teams", null),
                new Endpoint(Action.WRITE_TEAMS, "POST", "/api/ownership/teams", Map.of("name", "Team " + UUID.randomUUID())),
                new Endpoint(Action.VIEW_OWNERSHIP, "GET", "/api/ownership/review-items", null),
                new Endpoint(Action.RESOLVE_REVIEW, "PATCH", "/api/ownership/review-items/" + missing, Map.of("state", "DISMISSED")),
                new Endpoint(Action.MANAGE_ENCRYPTION, "GET", "/api/ownership/encryption", null));
        List<Arguments> cases = new ArrayList<>();
        for (String role : ROLES) for (Endpoint e : endpoints) cases.add(Arguments.of(role, e));
        return cases.stream();
    }

    @ParameterizedTest(name = "{0} {1}")
    @MethodSource("matrix")
    void everyRoleGetsExactlyTheMatrixDecision(String role, Endpoint endpoint) throws Exception {
        Tenant tenant = readyDefaultTenant();
        String token = tokenFor(role, tenant);
        int status = mvc.perform(request(endpoint).header("Authorization", "Bearer " + token)).andReturn().getResponse().getStatus();
        boolean allowed = OwnershipAuthorization.allowed(endpoint.action(), Set.of(role));
        if (allowed) assertThat(status).as(role + " " + endpoint).isNotIn(401, 403).isLessThan(500);
        else assertThat(status).as(role + " " + endpoint).isEqualTo(403);
    }

    @Test
    void directoryReadsAreMaskedAndOtherTenantsTeamsAreNotFound() throws Exception {
        Tenant tenant = readyDefaultTenant();
        String admin = tokenFor("TENANT_ADMIN", tenant);
        String name = "Zelda" + UUID.randomUUID().toString().substring(0, 6);
        mvc.perform(post("/api/directory/users").header("Authorization", "Bearer " + admin).contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("displayName", name, "email", name.toLowerCase() + "@corp.test")))).andExpect(status().isCreated());
        MvcResult found = mvc.perform(get("/api/directory/users").param("q", name.substring(0, 5)).header("Authorization", "Bearer " + admin))
                .andExpect(status().isOk()).andReturn();
        String body = found.getResponse().getContentAsString();
        assertThat(body).contains(name).contains("z***@corp.test").doesNotContain(name.toLowerCase() + "@corp.test");

        String slug = "own-authz-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant other = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(other);
        Tenant resolved = tenantService.resolveTenantUuid(other.getId());
        UUID foreignTeam;
        TenantContext.setCurrentTenantId(resolved.getId());
        TenantContext.setCurrentSchemaName(resolved.getSchemaName());
        try {
            foreignTeam = teams.createTeam("Foreign", null, null, "test").id();
        } finally {
            TenantContext.clear();
        }
        mvc.perform(get("/api/ownership/teams/{id}", foreignTeam).header("Authorization", "Bearer " + admin)).andExpect(status().isNotFound());
    }

    private String tokenFor(String role, Tenant tenant) throws Exception {
        String token = TOKENS.get(role);
        if (token == null) {
            token = login(member(role, tenant));
            TOKENS.put(role, token);
        }
        return token;
    }

    private MockHttpServletRequestBuilder request(Endpoint e) throws Exception {
        MockHttpServletRequestBuilder builder = switch (e.method()) {
            case "GET" -> get(e.path());
            case "POST" -> post(e.path());
            case "PATCH" -> patch(e.path());
            default -> throw new IllegalArgumentException(e.method());
        };
        if (e.body() != null) builder.contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(e.body()));
        return builder;
    }

    private Tenant readyDefaultTenant() {
        Tenant tenant = tenantService.getDefaultTenant();
        keys.provision(tenant.getId());
        return tenant;
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

    private String login(AppUser user) throws Exception {
        MvcResult result = mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(Map.of("email", user.getEmail(), "password", PASSWORD)))).andExpect(status().isOk()).andReturn();
        return com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.token");
    }
}
