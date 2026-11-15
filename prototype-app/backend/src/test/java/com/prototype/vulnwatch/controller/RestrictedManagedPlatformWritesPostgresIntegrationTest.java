package com.prototype.vulnwatch.controller;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.CognitoBrowserIdentityClient;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.migration.ProductionBootstrapCli;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.service.ManagedBrowserAuthService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.zaxxer.hikari.HikariDataSource;
import jakarta.servlet.http.Cookie;
import java.net.URI;
import java.sql.DriverManager;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * The lab's failing actor: a managed (Cognito) platform owner with no workspace, served by the
 * non-bypass runtime role under the prod profile's tenancy settings. Each platform-scope write
 * must commit its mutation, its audit row and its delivery intent, not just return 200.
 */
@PostgresControllerIntegrationTest
class RestrictedManagedPlatformWritesPostgresIntegrationTest {
    private static final String ISSUER = "https://cognito-idp.ap-southeast-2.amazonaws.com/ap-southeast-2_restricted";
    private static final LocalPostgresTestDatabase.DatabaseConfig DB =
            LocalPostgresTestDatabase.provision("restricted_managed_platform_writes");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DB);
        registry.add("app.runtime.role", () -> "api");
        registry.add("app.security.allow-api-key-auth", () -> "false");
        registry.add("app.security.managed-auth.enabled", () -> "true");
        registry.add("app.security.jwt.mode", () -> "EXTERNAL");
        registry.add("app.security.jwt.hmac-secret", () -> "");
        registry.add("app.security.jwt.issuer-uri", () -> ISSUER);
        registry.add("app.security.jwt.jwk-set-uri", () -> ISSUER + "/.well-known/jwks.json");
        registry.add("app.cors.allowed-origins", () -> "https://app.example.test");
        // application-prod.yml tenancy settings.
        registry.add("app.tenancy.allow-header-tenant-selection", () -> "false");
        registry.add("app.tenancy.require-tenant-context", () -> "true");
        registry.add("app.tenancy.enforce-schema-version", () -> "true");
        registry.add("app.tenancy.minimum-compatible-schema-version", () -> "23");
        registry.add("app.tenancy.maximum-compatible-schema-version", () -> "23");
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired AppUserRepository users;
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired HikariDataSource pool;
    @Autowired JdbcTemplate jdbc;
    @MockitoBean CognitoBrowserIdentityClient provider;

    JdbcTemplate owner;
    String runtimeRole;
    Tenant customer;
    Cookie session;
    Cookie csrfCookie;
    String csrfHeader;
    String csrfToken;

    @BeforeEach
    void setup() throws Exception {
        TenantContext.clear();
        owner = new JdbcTemplate(new DriverManagerDataSource(DB.url(), DB.username(), DB.password()));
        String slug = "managed-" + UUID.randomUUID().toString().substring(0, 8);
        customer = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(customer);
        customer = tenants.resolveTenantUuid(customer.getId());

        AppUser platformOwner = new AppUser();
        platformOwner.setExternalSubject("managed-owner-" + slug);
        platformOwner.setPlatformOwner(true);
        platformOwner.setStatus("ACTIVE");
        users.saveAndFlush(platformOwner);
        String subject = UUID.randomUUID().toString();
        owner.update("insert into platform.managed_identities (issuer, subject, user_id) values (?, ?, ?)",
                ISSUER, subject, platformOwner.getId());

        runtimeRole = "managed_" + UUID.randomUUID().toString().replace("-", "");
        String password = UUID.randomUUID().toString();
        try (var connection = DriverManager.getConnection(DB.url(), DB.username(), DB.password())) {
            ReflectionTestUtils.invokeMethod(ProductionBootstrapCli.class, "provisionRuntimeRole",
                    connection, runtimeRole, password, 0);
        }
        pool.getHikariConfigMXBean().setUsername(runtimeRole);
        pool.getHikariConfigMXBean().setPassword(password);
        pool.getHikariPoolMXBean().softEvictConnections();
        assertEquals(runtimeRole, jdbc.queryForObject("select current_user", String.class));
        assertFalse(jdbc.queryForObject(
                "select rolsuper or rolbypassrls from pg_roles where rolname = current_user", Boolean.class));

        when(provider.issuer()).thenReturn(ISSUER);
        when(provider.authorizationUri(anyString(), anyString(), anyString())).thenAnswer(call ->
                URI.create("https://cognito.example.test/authorize?state=" + call.getArgument(0)));
        when(provider.exchange(eq("owner-code"), anyString(), anyString())).thenReturn(
                new CognitoBrowserIdentityClient.Identity(subject, Instant.now().plusSeconds(600), null));
        signIn();
    }

    @AfterEach
    void cleanup() {
        TenantContext.clear();
        pool.getHikariConfigMXBean().setUsername(DB.username());
        pool.getHikariConfigMXBean().setPassword(DB.password());
        pool.getHikariPoolMXBean().softEvictConnections();
        if (runtimeRole != null && Boolean.TRUE.equals(owner.queryForObject(
                "select exists (select 1 from pg_roles where rolname = ?)", Boolean.class, runtimeRole))) {
            owner.execute("drop owned by " + runtimeRole);
            owner.execute("drop role " + runtimeRole);
        }
    }

    @Test
    void approvalQueuesStandardOnboardingAndIsAudited() throws Exception {
        UUID requestId = pendingRequest("approve");

        mvc.perform(write(post("/api/platform/demo-requests/{id}/approve", requestId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("QUEUED"))
                .andExpect(jsonPath("$.bootstrapStatus").value("STANDARD_APPROVED"));

        // Managed approval sends nothing itself: the queued request is the delivery intent that
        // the operator's Standard onboarding steps (and Cognito's setup email) consume.
        Map<String, Object> request = owner.queryForMap(
                "select status, bootstrap_status, decided_by from tenant_default.demo_requests where id = ?", requestId);
        assertEquals("QUEUED", request.get("status"));
        assertEquals("STANDARD_APPROVED", request.get("bootstrap_status"));
        assertNotNull(request.get("decided_by"));
        assertEquals(0, owner.queryForObject(
                "select count(*) from tenant_default.demo_invites where request_id = ?", Integer.class, requestId));
        assertEquals(1, platformScopeAuditCount("demo.request.standard_approved", requestId));
    }

    @Test
    void rejectionIsCommittedAndAudited() throws Exception {
        UUID requestId = pendingRequest("reject");

        mvc.perform(write(post("/api/platform/demo-requests/{id}/reject", requestId))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("reason", "Not a fit"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("REJECTED"));

        assertEquals("REJECTED", owner.queryForObject(
                "select status from tenant_default.demo_requests where id = ?", String.class, requestId));
        assertEquals(1, platformScopeAuditCount("demo.request.rejected", requestId));
    }

    @Test
    void deletionRemovesTheRequestAndItsCustomerTenantInvitesAndIsAudited() throws Exception {
        UUID requestId = UUID.randomUUID();
        UUID inviteId = UUID.randomUUID();
        String email = "delete-" + requestId + "@example.test";
        owner.update("""
                insert into tenant_default.demo_requests(id, company, email, full_name, status, requested_at, tenant_id, bootstrap_status)
                values (?, 'Delete Co', ?, 'Delete Owner', 'SENT', now(), ?, 'INVITE_SENT')
                """, requestId, email, customer.getId());
        owner.update("""
                insert into tenant_default.demo_invites(id, token_hash, email, status, created_at, expires_at, request_id, tenant_id)
                values (?, ?, ?, 'SENT', now(), now() + interval '1 day', ?, ?)
                """, inviteId, "b".repeat(64), email, requestId, customer.getId());

        mvc.perform(write(delete("/api/platform/demo-requests/{id}", requestId))).andExpect(status().isOk());

        assertEquals(0, owner.queryForObject(
                "select count(*) from tenant_default.demo_requests where id = ?", Integer.class, requestId));
        assertEquals(0, owner.queryForObject(
                "select count(*) from tenant_default.demo_invites where id = ?", Integer.class, inviteId));
        assertEquals(1, platformScopeAuditCount("demo.request.deleted", requestId));
    }

    private void signIn() throws Exception {
        var login = mvc.perform(get("/api/auth/managed/login")).andExpect(status().isSeeOther())
                .andReturn().getResponse();
        Cookie browser = login.getCookie(ManagedBrowserAuthService.LOGIN_COOKIE);
        assertNotNull(browser);
        String state = UriComponentsBuilder.fromUriString(login.getHeader("Location"))
                .build().getQueryParams().getFirst("state");
        session = mvc.perform(get("/api/auth/callback").param("state", state).param("code", "owner-code").cookie(browser))
                .andExpect(status().isSeeOther())
                .andReturn().getResponse().getCookie(ManagedBrowserAuthService.SESSION_COOKIE);
        assertNotNull(session);
        mvc.perform(get("/api/auth/context").cookie(session))
                .andExpect(status().isOk()).andExpect(jsonPath("$.tenantId").doesNotExist());
        var csrf = mvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn().getResponse();
        csrfCookie = csrf.getCookie("__Host-sg-csrf");
        assertNotNull(csrfCookie);
        JsonNode token = json.readTree(csrf.getContentAsString());
        csrfHeader = token.get("headerName").asText();
        csrfToken = token.get("token").asText();
    }

    private MockHttpServletRequestBuilder write(MockHttpServletRequestBuilder request) {
        return request.cookie(session, csrfCookie).header(csrfHeader, csrfToken);
    }

    private UUID pendingRequest(String label) {
        UUID requestId = UUID.randomUUID();
        owner.update("""
                insert into tenant_default.demo_requests(id, company, email, full_name, status, requested_at)
                values (?, 'Queue Co', ?, 'Queue Owner', 'PENDING', now())
                """, requestId, label + "-" + requestId + "@example.test");
        return requestId;
    }

    private int platformScopeAuditCount(String action, UUID requestId) {
        return owner.queryForObject("""
                select count(*) from tenant_default.audit_events
                where action = ? and target_id = ? and tenant_id is null
                """, Integer.class, action, requestId.toString());
    }
}
