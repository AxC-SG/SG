package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.CognitoBrowserIdentityClient;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantSupportGrant;
import com.prototype.vulnwatch.domain.TenantUserInvite;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantSupportGrantRepository;
import com.prototype.vulnwatch.repo.TenantUserInviteRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import jakarta.servlet.http.Cookie;
import java.net.URI;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.util.UriComponentsBuilder;

@PostgresControllerIntegrationTest
class ManagedBrowserAuthPostgresIntegrationTest {
    private static final String ISSUER = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_testpool";
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("managed_browser_auth");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.runtime.role", () -> "api");
        registry.add("app.tenancy.require-tenant-context", () -> "true");
        registry.add("app.security.allow-api-key-auth", () -> "false");
        registry.add("app.security.managed-auth.enabled", () -> "true");
        registry.add("app.security.jwt.mode", () -> "EXTERNAL");
        registry.add("app.security.jwt.hmac-secret", () -> "");
        registry.add("app.security.jwt.issuer-uri", () -> ISSUER);
        registry.add("app.security.jwt.jwk-set-uri", () -> ISSUER + "/.well-known/jwks.json");
        registry.add("app.cors.allowed-origins", () -> "https://app.example.test");
    }

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired @Qualifier("platformJdbcTemplate") JdbcTemplate jdbc;
    @Autowired ManagedBrowserSessionStore store;
    @Autowired AppUserRepository users;
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migration;
    @Autowired TenantSupportGrantRepository grants;
    @Autowired TenantUserInviteRepository invites;
    @MockitoBean CognitoBrowserIdentityClient provider;

    @BeforeEach
    void stubProvider() {
        when(provider.issuer()).thenReturn(ISSUER);
        when(provider.authorizationUri(anyString(), anyString(), anyString())).thenAnswer(call ->
                URI.create("https://cognito.example.test/authorize?state=" + call.getArgument(0)));
    }

    @Test
    void cookieSessionRevalidatesTwoIndependentWorkspacesAndRevokesOnLogout() throws Exception {
        AppUser owner = new AppUser();
        owner.setExternalSubject("managed-platform-owner");
        owner.setPlatformOwner(true);
        users.saveAndFlush(owner);
        String subject = UUID.randomUUID().toString();
        jdbc.update("insert into platform.managed_identities (issuer, subject, user_id) values (?, ?, ?)",
                ISSUER, subject, owner.getId());
        when(provider.exchange(eq("fixture-code"), anyString(), anyString())).thenReturn(
                new CognitoBrowserIdentityClient.Identity(subject, Instant.now().plusSeconds(600), null));

        Tenant first = tenants.getDefaultTenant();
        Tenant second = tenants.createTenant("Managed Support Test", "managed-support-test", "ENTERPRISE", null);
        migration.provisionNewTenant(second);
        TenantSupportGrant firstGrant = grant(owner, first);
        grant(owner, second);
        var login = login();
        mvc.perform(get("/api/auth/callback").param("state", login.state()).param("code", "fixture-code")
                        .cookie(new Cookie(ManagedBrowserAuthService.LOGIN_COOKIE, "x".repeat(43))))
                .andExpect(status().isUnauthorized());
        Cookie session = mvc.perform(get("/api/auth/callback").param("state", login.state())
                        .param("code", "fixture-code").cookie(login.browser()))
                .andExpect(status().isSeeOther())
                .andExpect(header().string("Location", "https://app.example.test/"))
                .andReturn().getResponse().getCookie(ManagedBrowserAuthService.SESSION_COOKIE);
        assertNotNull(session);
        assertTrue(session.isHttpOnly() && session.getSecure());
        assertEquals("/", session.getPath());
        mvc.perform(get("/api/auth/callback").param("state", login.state()).param("code", "fixture-code")
                        .cookie(login.browser()))
                .andExpect(status().isUnauthorized());

        mvc.perform(get("/api/auth/context").cookie(session))
                .andExpect(status().isOk()).andExpect(jsonPath("$.tenantId").doesNotExist())
                .andExpect(jsonPath("$.allowedTenants.length()").value(2));
        mvc.perform(get("/api/tenants").cookie(session)).andExpect(status().isOk());
        mvc.perform(get("/api/auth/support-grants").cookie(session)).andExpect(status().isOk());
        for (Tenant workspace : new Tenant[]{first, second, first}) {
            mvc.perform(get("/api/auth/context").cookie(session)
                            .header(ManagedBrowserAuthService.WORKSPACE_HEADER, workspace.getId()))
                    .andExpect(status().isOk()).andExpect(jsonPath("$.tenantId").value(workspace.getId().toString()));
        }
        firstGrant.setStatus("REVOKED");
        grants.saveAndFlush(firstGrant);
        mvc.perform(get("/api/auth/context").cookie(session)
                        .header(ManagedBrowserAuthService.WORKSPACE_HEADER, first.getId()))
                .andExpect(status().isForbidden());
        mvc.perform(get("/api/auth/context").cookie(session)
                        .header(ManagedBrowserAuthService.WORKSPACE_HEADER, second.getId()))
                .andExpect(status().isOk());

        mvc.perform(post("/api/auth/managed/logout").cookie(session)).andExpect(status().isForbidden());
        var csrf = mvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn().getResponse();
        Cookie csrfCookie = csrf.getCookie("__Host-sg-csrf");
        assertNotNull(csrfCookie);
        assertTrue(csrfCookie.getSecure() && csrfCookie.isHttpOnly());
        var token = json.readTree(csrf.getContentAsString());
        UUID demoRequest = UUID.randomUUID();
        jdbc.update("""
                insert into tenant_default.demo_requests(id, company, email, full_name, status, requested_at)
                values (?, 'Orchard Systems', 'requested-admin@example.test', 'Requested Admin', 'PENDING', now())
                """, demoRequest);
        for (int attempt = 0; attempt < 2; attempt++) {
            mvc.perform(post("/api/platform/demo-requests/{id}/approve", demoRequest).cookie(session, csrfCookie)
                            .header(token.get("headerName").asText(), token.get("token").asText()))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.status").value("QUEUED"))
                    .andExpect(jsonPath("$.bootstrapStatus").value("STANDARD_APPROVED"))
                    .andExpect(jsonPath("$.tenantId").doesNotExist())
                    .andExpect(jsonPath("$.latestInvite").doesNotExist());
        }
        mvc.perform(post("/api/platform/demo-requests/{id}/reject", demoRequest).cookie(session, csrfCookie)
                        .header(token.get("headerName").asText(), token.get("token").asText()))
                .andExpect(status().isConflict());
        mvc.perform(post("/api/auth/managed/logout").cookie(session, csrfCookie)
                        .header(token.get("headerName").asText(), token.get("token").asText()))
                .andExpect(status().isNoContent());
        mvc.perform(get("/api/auth/context").cookie(session)).andExpect(status().isUnauthorized());
    }

    @Test
    void platformScopeOwnerCanUsePlatformConsoleRoutesAndDeleteQueuedDemoRequests() throws Exception {
        AppUser owner = new AppUser();
        owner.setExternalSubject("managed-platform-console-owner");
        owner.setPlatformOwner(true);
        users.saveAndFlush(owner);
        String subject = UUID.randomUUID().toString();
        jdbc.update("insert into platform.managed_identities (issuer, subject, user_id) values (?, ?, ?)",
                ISSUER, subject, owner.getId());
        mockIdentity("console-code", subject, null, Instant.now().plusSeconds(600));
        Cookie session = callback(login(), "console-code").andExpect(status().isSeeOther())
                .andReturn().getResponse().getCookie(ManagedBrowserAuthService.SESSION_COOKIE);
        assertNotNull(session);

        for (String path : new String[]{"/api/audit-events/platform-users", "/api/sync-runs/sources-summary",
                "/api/sync-runs", "/api/eol/products", "/api/ingestion/vex-assertion-repair/summary",
                "/api/ai-frameworks"}) {
            mvc.perform(get(path).cookie(session)).andExpect(status().isOk());
        }
        mvc.perform(get("/api/findings").cookie(session)).andExpect(status().isForbidden());
        mvc.perform(get("/api/eolx/products").cookie(session)).andExpect(status().isForbidden());

        var csrf = mvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn().getResponse();
        Cookie csrfCookie = csrf.getCookie("__Host-sg-csrf");
        var token = json.readTree(csrf.getContentAsString());
        UUID demoRequest = UUID.randomUUID();
        jdbc.update("""
                insert into tenant_default.demo_requests(id, company, email, full_name, status, requested_at)
                values (?, 'Delete Systems', 'delete-me@example.test', 'Delete Me', 'PENDING', now())
                """, demoRequest);
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .delete("/api/platform/demo-requests/{id}", demoRequest).cookie(session, csrfCookie)
                        .header(token.get("headerName").asText(), token.get("token").asText()))
                .andExpect(status().isOk());
        assertEquals(0, jdbc.queryForObject("select count(*) from tenant_default.demo_requests where id=?",
                Integer.class, demoRequest));
    }

    @Test
    void unlinkedSubjectAndLocalCredentialIssuanceAreDenied() throws Exception {
        when(provider.exchange(eq("unlinked-code"), anyString(), anyString())).thenReturn(
                new CognitoBrowserIdentityClient.Identity(UUID.randomUUID().toString(), Instant.now().plusSeconds(600), null));
        var login = login();
        mvc.perform(get("/api/auth/callback").param("state", login.state())
                        .param("code", "unlinked-code").cookie(login.browser()))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"fixture@example.test\",\"password\":\"fixture-password\"}"))
                .andExpect(status().isConflict());
        mvc.perform(post("/api/auth/setup-session").contentType(MediaType.APPLICATION_JSON)
                        .header("X-Scout-Setup", "1").content("{\"setupToken\":\"fixture-token\"}"))
                .andExpect(status().isConflict());
    }

    @Test
    void concurrentCallbacksCanConsumeAnAttemptOnlyOnce() throws Exception {
        String stateHash = "a".repeat(64);
        String browserHash = "b".repeat(64);
        store.saveAttempt(stateHash, browserHash, "verifier", "nonce", null);
        var pool = Executors.newFixedThreadPool(2);
        var start = new CyclicBarrier(2);
        try {
            java.util.concurrent.Callable<Integer> redeem = () -> {
                start.await(10, TimeUnit.SECONDS);
                return store.consumeAttempt(stateHash, browserHash).isPresent() ? 1 : 0;
            };
            var one = pool.submit(redeem);
            var two = pool.submit(redeem);
            assertEquals(1, one.get(15, TimeUnit.SECONDS) + two.get(15, TimeUnit.SECONDS));
        } finally {
            pool.shutdownNow();
        }
    }

    @Test
    void verifiedInvitationCreatesMembershipAndSessionExactlyOnce() throws Exception {
        Invitation invite = invite("new-member", false);
        String subject = UUID.randomUUID().toString();
        mockIdentity("invite-code", subject, invite.email().toUpperCase(java.util.Locale.ROOT), Instant.now().plusSeconds(600));

        mvc.perform(post("/api/auth/managed/invitation").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(java.util.Map.of("token", invite.token()))))
                .andExpect(status().isForbidden());
        Login first = invitationLogin(invite.token());
        Login second = invitationLogin(invite.token());
        assertEquals(2, jdbc.queryForObject("""
                select count(*) from platform.managed_login_attempts where invite_hash=?
                """, Integer.class, InvitationTokens.hash(invite.token())));
        var pool = Executors.newFixedThreadPool(2);
        var start = new CyclicBarrier(2);
        Cookie session;
        try {
            var callbacks = new java.util.ArrayList<java.util.concurrent.Future<org.springframework.mock.web.MockHttpServletResponse>>();
            for (Login login : new Login[]{first, second}) {
                callbacks.add(pool.submit(() -> {
                    start.await(10, TimeUnit.SECONDS);
                    return callback(login, "invite-code").andReturn().getResponse();
                }));
            }
            var a = callbacks.get(0).get(15, TimeUnit.SECONDS);
            var b = callbacks.get(1).get(15, TimeUnit.SECONDS);
            assertEquals(java.util.Set.of(303, 400), java.util.Set.of(a.getStatus(), b.getStatus()));
            session = (a.getStatus() == 303 ? a : b).getCookie(ManagedBrowserAuthService.SESSION_COOKIE);
        } finally {
            pool.shutdownNow();
        }
        assertNotNull(session);
        assertEquals("ACCEPTED", invites.findById(invite.id()).orElseThrow().getStatus());
        assertEquals(1, count("select count(*) from platform.managed_identities where user_id=?", invite.userId()));
        assertEquals(1, count("select count(*) from platform.tenant_memberships where user_id=?", invite.userId()));
        assertEquals(1, count("select count(*) from platform.managed_browser_sessions where user_id=?", invite.userId()));
        assertEquals(1, jdbc.queryForObject("""
                select count(*) from tenant_default.audit_events
                where action='member.invite.accepted' and target_id=?
                """, Integer.class, invite.id().toString()));
        org.junit.jupiter.api.Assertions.assertNull(users.findById(invite.userId()).orElseThrow().getPasswordSetupTokenHash());
        mvc.perform(get("/api/auth/context").cookie(session)
                        .header(ManagedBrowserAuthService.WORKSPACE_HEADER, invite.tenantId()))
                .andExpect(status().isOk()).andExpect(jsonPath("$.userId").value(invite.email()))
                .andExpect(jsonPath("$.tenantId").value(invite.tenantId().toString()));
        mvc.perform(get("/api/tenants").cookie(session)).andExpect(status().isForbidden());
        mvc.perform(get("/api/auth/support-grants").cookie(session)).andExpect(status().isForbidden());
        callback(login(), "invite-code").andExpect(status().isSeeOther());
    }

    @Test
    void mismatchedIdentityAndFailedSessionLeaveInviteAvailable() throws Exception {
        Invitation invite = invite("retry-member", false);
        String subject = UUID.randomUUID().toString();
        mockIdentity("unverified", subject, null, Instant.now().plusSeconds(600));
        mockIdentity("different-email", subject, "different@example.test", Instant.now().plusSeconds(600));
        mockIdentity("expired", subject, invite.email(), Instant.now().minusSeconds(1));
        callback(invitationLogin(invite.token()), "unverified").andExpect(status().isForbidden());
        callback(invitationLogin(invite.token()), "different-email").andExpect(status().isForbidden());
        callback(invitationLogin(invite.token()), "expired").andExpect(status().isUnauthorized());
        assertEquals("READY", invites.findById(invite.id()).orElseThrow().getStatus());
        assertEquals(0, count("select count(*) from platform.managed_identities where user_id=?", invite.userId()));
        assertEquals(0, count("select count(*) from platform.tenant_memberships where user_id=?", invite.userId()));

        Login stale = invitationLogin(invite.token());
        var rotated = invites.findById(invite.id()).orElseThrow();
        String replacement = UUID.randomUUID().toString();
        rotated.setToken(replacement);
        invites.saveAndFlush(rotated);
        mockIdentity("correct", subject, invite.email(), Instant.now().plusSeconds(600));
        callback(stale, "correct").andExpect(status().isForbidden());
        callback(invitationLogin(replacement), "correct").andExpect(status().isSeeOther());
    }

    @Test
    void invitationCannotLinkAUserWithExistingLocalCredentials() throws Exception {
        Invitation invite = invite("existing-member", true);
        mockIdentity("takeover", UUID.randomUUID().toString(), invite.email(), Instant.now().plusSeconds(600));
        callback(invitationLogin(invite.token()), "takeover").andExpect(status().isForbidden());
        assertEquals("READY", invites.findById(invite.id()).orElseThrow().getStatus());
        assertEquals(0, count("select count(*) from platform.managed_identities where user_id=?", invite.userId()));
    }

    @Test
    void aManagedSubjectAlreadyLinkedElsewhereCannotClaimAnInvitation() throws Exception {
        Invitation invite = invite("conflict-member", false);
        AppUser other = new AppUser();
        other.setExternalSubject("previously-linked");
        users.saveAndFlush(other);
        String subject = UUID.randomUUID().toString();
        jdbc.update("insert into platform.managed_identities (issuer, subject, user_id) values (?, ?, ?)",
                ISSUER, subject, other.getId());

        mockIdentity("conflict-code", subject, invite.email(), Instant.now().plusSeconds(600));
        callback(invitationLogin(invite.token()), "conflict-code").andExpect(status().isForbidden());
        assertEquals("READY", invites.findById(invite.id()).orElseThrow().getStatus());
        assertEquals(0, count("select count(*) from platform.tenant_memberships where user_id=?", invite.userId()));
        assertEquals(1, count("select count(*) from platform.managed_identities where user_id=?", other.getId()));
    }

    private int count(String sql, UUID userId) {
        return jdbc.queryForObject(sql, Integer.class, userId);
    }

    private void mockIdentity(String code, String subject, String email, Instant expiry) {
        when(provider.exchange(eq(code), anyString(), anyString()))
                .thenReturn(new CognitoBrowserIdentityClient.Identity(subject, expiry, email));
    }

    private Login invitationLogin(String inviteToken) throws Exception {
        var csrf = mvc.perform(get("/api/auth/csrf")).andExpect(status().isOk()).andReturn().getResponse();
        var token = json.readTree(csrf.getContentAsString());
        var response = mvc.perform(post("/api/auth/managed/invitation")
                        .cookie(csrf.getCookie("__Host-sg-csrf"))
                        .header(token.get("headerName").asText(), token.get("token").asText())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(java.util.Map.of("token", inviteToken))))
                .andExpect(status().isOk()).andReturn().getResponse();
        var browser = response.getCookie(ManagedBrowserAuthService.LOGIN_COOKIE);
        assertNotNull(browser);
        String authorizationUrl = json.readTree(response.getContentAsString()).get("authorizationUrl").asText();
        org.junit.jupiter.api.Assertions.assertFalse(authorizationUrl.contains(inviteToken));
        String state = UriComponentsBuilder.fromUriString(authorizationUrl).build().getQueryParams().getFirst("state");
        return new Login(browser, state);
    }

    private ResultActions callback(Login login, String code) throws Exception {
        return mvc.perform(get("/api/auth/callback").param("state", login.state()).param("code", code).cookie(login.browser()));
    }

    private Invitation invite(String label, boolean hasPassword) {
        String email = label + "@example.test";
        AppUser user = new AppUser();
        user.setEmail(email);
        user.setExternalSubject(email);
        if (hasPassword) {
            user.setPasswordHash(org.springframework.security.crypto.bcrypt.BCrypt.hashpw("fixture", org.springframework.security.crypto.bcrypt.BCrypt.gensalt(4)));
        }
        users.saveAndFlush(user);
        var tenant = tenants.getDefaultTenant();
        TenantUserInvite invite = new TenantUserInvite();
        invite.setTenant(tenant);
        invite.setEmail(email);
        invite.setExternalSubject(email);
        invite.setRole("TENANT_ADMIN");
        invite.setStatus("READY");
        invite.setExpiresAt(Instant.now().plusSeconds(900));
        String token = UUID.randomUUID().toString();
        invite.setToken(token);
        invites.saveAndFlush(invite);
        return new Invitation(invite.getId(), user.getId(), tenant.getId(), email, token);
    }

    private record Invitation(UUID id, UUID userId, UUID tenantId, String email, String token) { }

    private Login login() throws Exception {
        var response = mvc.perform(get("/api/auth/managed/login")).andExpect(status().isSeeOther())
                .andReturn().getResponse();
        var browser = response.getCookie(ManagedBrowserAuthService.LOGIN_COOKIE);
        assertNotNull(browser);
        String state = UriComponentsBuilder.fromUriString(response.getHeader("Location"))
                .build().getQueryParams().getFirst("state");
        return new Login(browser, state);
    }

    private TenantSupportGrant grant(AppUser owner, Tenant tenant) {
        var grant = new TenantSupportGrant();
        grant.setTenant(tenant);
        grant.setInvitedPlatformSubject(owner.getExternalSubject());
        grant.setGrantedBy(owner);
        grant.setAcceptedBy(owner);
        grant.setReason("Managed session test");
        grant.setAccessMode("READ_ONLY");
        grant.setStatus("ACTIVE");
        grant.setAcceptedAt(Instant.now());
        grant.setExpiresAt(Instant.now().plusSeconds(600));
        return grants.saveAndFlush(grant);
    }

    private record Login(Cookie browser, String state) { }
}
