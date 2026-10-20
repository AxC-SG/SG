package com.prototype.vulnwatch.security;

import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasItem;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.AppUserGlobalRole;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantUserInvite;
import com.prototype.vulnwatch.domain.TenantSupportGrant;
import com.prototype.vulnwatch.repo.AppUserGlobalRoleRepository;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantUserInviteRepository;
import com.prototype.vulnwatch.repo.TenantSupportGrantRepository;
import com.prototype.vulnwatch.service.TenantSupportGrantService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.AppUserGlobalRoleService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionTemplate;

/** Exercises the real decoder, authentication filter, method security and persisted authority. */
@PostgresControllerIntegrationTest
class PhaseOneAuthorizationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("phase_one_authorization");
    private static final String JWT_SECRET = "phase-one-auth-regression-secret-32-bytes";
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
    private AppUserRepository users;
    @Autowired
    private AppUserGlobalRoleRepository globalRoles;
    @Autowired
    private TenantMembershipRepository memberships;
    @Autowired
    private TenantUserInviteRepository invites;
    @Autowired
    private TenantService tenantService;
    @Autowired
    private AppUserGlobalRoleService globalRoleService;
    @Autowired
    private TransactionTemplate transactions;
    @Autowired
    private TenantSupportGrantRepository supportGrants;
    @Autowired
    private TenantSupportGrantService supportGrantService;

    @ParameterizedTest
    @ValueSource(strings = {"PLATFORM_OWNER", "ROLE_ROLE_PLATFORM_OWNER", "creator", "SERVICE_ACCOUNT", "OPERATOR", "unknown"})
    void tenantAdministratorCannotAssignGlobalSystemOrUnknownRolesThroughHttp(String role) throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser admin = user("assigning-admin", false);
        membership(admin, tenant, "TENANT_ADMIN");
        String adminToken = login(admin);
        AppUser target = user("assignment-target", false);
        TenantMembership existing = membership(target, tenant, "READ_ONLY_AUDITOR");
        String newSubject = subject("new-member");
        String invitedEmail = subject("invited-member");

        mockMvc.perform(post("/api/tenants/{tenantId}/members", tenant.getId())
                        .header("Authorization", bearer(adminToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("subject", newSubject, "email", newSubject,
                                "displayName", "New member", "role", role))))
                .andExpect(status().isBadRequest());
        mockMvc.perform(patch("/api/tenants/{tenantId}/members/{memberId}", tenant.getId(), existing.getId())
                        .header("Authorization", bearer(adminToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("role", role, "status", "ACTIVE"))))
                .andExpect(status().isBadRequest());
        mockMvc.perform(post("/api/tenants/{tenantId}/invites", tenant.getId())
                        .header("Authorization", bearer(adminToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", invitedEmail, "displayName", "Invited member", "role", role))))
                .andExpect(status().isBadRequest());

        assertTrue(memberships.findFirstByUserExternalSubjectAndTenantId(newSubject, tenant.getId()).isEmpty());
        assertEquals("READ_ONLY_AUDITOR", memberships.findById(existing.getId()).orElseThrow().getRole());
        assertTrue(invites.findByTenantIdOrderByCreatedAtDesc(tenant.getId()).stream()
                .noneMatch(invite -> invitedEmail.equals(invite.getEmail())));
        assertNoOwnerAuthority(admin);
        assertNoOwnerAuthority(target);
        mockMvc.perform(get("/api/platform/users").header("Authorization", bearer(adminToken)))
                .andExpect(status().isForbidden());
    }

    @Test
    void acceptedTenantRoleAliasesRemainTenantScoped() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser admin = user("ordinary-admin", false);
        membership(admin, tenant, "TENANT_ADMIN");
        String adminToken = login(admin);
        String targetSubject = subject("ordinary-target");

        MvcResult created = mockMvc.perform(post("/api/tenants/{tenantId}/members", tenant.getId())
                        .header("Authorization", bearer(adminToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("subject", targetSubject, "email", targetSubject,
                                "displayName", "Ordinary member", "role", "role-role-security-analyst"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("SECURITY_ANALYST"))
                .andReturn();
        String memberId = com.jayway.jsonpath.JsonPath.read(created.getResponse().getContentAsString(), "$.id");

        mockMvc.perform(patch("/api/tenants/{tenantId}/members/{memberId}", tenant.getId(), memberId)
                        .header("Authorization", bearer(adminToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("role", "read only auditor"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("READ_ONLY_AUDITOR"));
        assertNoOwnerAuthority(users.findByExternalSubject(targetSubject).orElseThrow());
    }

    @ParameterizedTest
    @ValueSource(strings = {"PLATFORM_OWNER", "ROLE_ROLE_PLATFORM_OWNER", "CREATOR", "SERVICE_ACCOUNT", "unknown"})
    void invalidStoredMembershipRejectsLoginAndPreviouslyIssuedTenantJwt(String role) throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser user = user("invalid-stored-role", false);
        TenantMembership membership = membership(user, tenant, "TENANT_ADMIN");
        String ordinaryToken = login(user);
        membership.setRole(role);
        memberships.save(membership);

        mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", user.getEmail(), "password", PASSWORD))))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/auth/context").header("Authorization", bearer(ordinaryToken)))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/platform/users").header("Authorization", bearer(ordinaryToken)))
                .andExpect(status().isForbidden());

        assertEquals(role, memberships.findById(membership.getId()).orElseThrow().getRole());
        assertNoOwnerAuthority(user);
    }

    @Test
    void oldOwnerJwtCannotRestoreRevokedGlobalGrantOrCompatibilityFlag() throws Exception {
        AppUser owner = user("revoked-owner", true);
        globalRole(owner, "PLATFORM_OWNER");
        String oldToken = login(owner);
        globalRoles.deleteAll(globalRoles.findByUser_IdOrderByCreatedAtAsc(owner.getId()));
        AppUser revoked = users.findById(owner.getId()).orElseThrow();
        revoked.setPlatformOwner(false);
        users.save(revoked);

        mockMvc.perform(get("/api/platform/users").header("Authorization", bearer(oldToken)))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/auth/context").header("Authorization", bearer(oldToken)))
                .andExpect(status().isForbidden());

        assertNoOwnerAuthority(owner);
    }

    @Test
    void ownerRevocationRemovesEveryStoredAliasWithoutRemovingOtherRoles() throws Exception {
        AppUser owner = user("alias-grant-owner", true);
        globalRole(owner, "PLATFORM_OWNER");
        globalRole(owner, "ROLE_PLATFORM_OWNER");
        globalRole(owner, "role-role-platform-owner");
        globalRole(owner, "SERVICE_ACCOUNT");
        String oldToken = login(owner);

        globalRoleService.revokeRole(users.findById(owner.getId()).orElseThrow(), "ROLE_ROLE_PLATFORM_OWNER");

        assertEquals(Set.of("SERVICE_ACCOUNT"), globalRoleService.rolesForUser(owner.getId()));
        assertFalse(users.findById(owner.getId()).orElseThrow().isPlatformOwner());
        assertEquals(1, globalRoles.findByUser_IdOrderByCreatedAtAsc(owner.getId()).size());
        mockMvc.perform(get("/api/platform/users").header("Authorization", bearer(oldToken)))
                .andExpect(status().isForbidden());
        assertFalse(users.findById(owner.getId()).orElseThrow().isPlatformOwner());
    }

    @Test
    void oldJwtWaitsForConcurrentRevocationAndCannotRestoreOwnerAuthority() throws Exception {
        AppUser owner = user("concurrent-revocation-owner", true);
        globalRole(owner, "PLATFORM_OWNER");
        String oldToken = login(owner);
        var executor = Executors.newFixedThreadPool(2);
        CountDownLatch revocationApplied = new CountDownLatch(1);
        CountDownLatch allowRevocationCommit = new CountDownLatch(1);
        CountDownLatch authenticationStarted = new CountDownLatch(1);
        try {
            var revocation = executor.submit(() -> TenantContext.runAsPlatform(() -> transactions.execute(tx -> {
                globalRoleService.revokeRole(users.findById(owner.getId()).orElseThrow(), "PLATFORM_OWNER");
                users.flush();
                revocationApplied.countDown();
                await(allowRevocationCommit);
                return null;
            })));
            assertTrue(revocationApplied.await(10, TimeUnit.SECONDS), "revocation must acquire the user row before authentication");
            var authentication = executor.submit(() -> {
                authenticationStarted.countDown();
                return mockMvc.perform(get("/api/platform/users").header("Authorization", bearer(oldToken)))
                        .andReturn().getResponse().getStatus();
            });
            assertTrue(authenticationStarted.await(10, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> authentication.get(300, TimeUnit.MILLISECONDS),
                    "authentication must wait for the in-flight authority transaction");

            allowRevocationCommit.countDown();
            revocation.get(10, TimeUnit.SECONDS);
            assertEquals(403, authentication.get(10, TimeUnit.SECONDS).intValue());
            assertNoOwnerAuthority(owner);
            mockMvc.perform(get("/api/platform/users").header("Authorization", bearer(oldToken)))
                    .andExpect(status().isForbidden());
            assertNoOwnerAuthority(owner);
        } finally {
            allowRevocationCommit.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    @Test
    void staleManagedProfileUpdatePreservesCommittedOwnerRevocation() throws Exception {
        AppUser owner = user("stale-profile-owner", true);
        globalRole(owner, "PLATFORM_OWNER");
        String oldToken = login(owner);
        var executor = Executors.newSingleThreadExecutor();
        CountDownLatch staleProfileLoaded = new CountDownLatch(1);
        CountDownLatch revocationCommitted = new CountDownLatch(1);
        String changedName = "Profile edited after revocation";
        try {
            var profileUpdate = executor.submit(() -> TenantContext.runAsPlatform(() -> transactions.execute(tx -> {
                AppUser staleProfile = users.findById(owner.getId()).orElseThrow();
                assertTrue(staleProfile.isPlatformOwner());
                staleProfileLoaded.countDown();
                await(revocationCommitted);
                staleProfile.setDisplayName(changedName);
                staleProfile.setUpdatedAt(Instant.now());
                users.saveAndFlush(staleProfile);
                return null;
            })));
            assertTrue(staleProfileLoaded.await(10, TimeUnit.SECONDS), "profile transaction must load before revocation");

            globalRoleService.revokeRole(users.findById(owner.getId()).orElseThrow(), "PLATFORM_OWNER");
            assertNoOwnerAuthority(owner);
            revocationCommitted.countDown();
            profileUpdate.get(10, TimeUnit.SECONDS);

            assertEquals(changedName, users.findById(owner.getId()).orElseThrow().getDisplayName());
            assertNoOwnerAuthority(owner);
            mockMvc.perform(get("/api/platform/users").header("Authorization", bearer(oldToken)))
                    .andExpect(status().isForbidden());
            assertNoOwnerAuthority(owner);
        } finally {
            revocationCommitted.countDown();
            executor.shutdownNow();
            assertTrue(executor.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"PLATFORM_OWNER", "platform-owner", "platform owner", "ROLE_ROLE_PLATFORM_OWNER"})
    void oldElevatedRoleAliasesCannotCreateGlobalAuthority(String role) throws Exception {
        AppUser user = user("old-role-alias", false);
        TenantMembership membership = membership(user, tenantService.getDefaultTenant(), "SECURITY_ANALYST");
        Map<String, Object> claims = membershipClaims(membership);
        claims.put("roles", List.of(role));
        String token = historicalToken(user, claims);

        mockMvc.perform(get("/api/platform/users").header("Authorization", bearer(token)))
                .andExpect(status().isForbidden());

        assertNoOwnerAuthority(user);
    }

    @Test
    void namespacedAndKeycloakClaimsCannotRecreateGlobalAuthority() throws Exception {
        AppUser user = user("old-provider-alias", false);
        TenantMembership membership = membership(user, tenantService.getDefaultTenant(), "SECURITY_ANALYST");
        List<Map<String, Object>> claims = List.of(
                Map.of("https://identity.example/roles", List.of("ROLE_ROLE_PLATFORM_OWNER")),
                Map.of("realm_access", Map.of("roles", List.of("platform-owner"))),
                Map.of("resource_access", Map.of("scout-ui", Map.of("roles", List.of("ROLE_ROLE_PLATFORM_OWNER")))));

        for (Map<String, Object> claim : claims) {
            Map<String, Object> tenantClaims = membershipClaims(membership);
            tenantClaims.putAll(claim);
            mockMvc.perform(get("/api/platform/users")
                            .header("Authorization", bearer(historicalToken(user, tenantClaims))))
                    .andExpect(status().isForbidden());
            assertNoOwnerAuthority(user);
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void legitimateCurrentOwnersKeepPlatformAndSelectedMembershipAccess(boolean compatibilityFlag) throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser owner = user("current-owner", compatibilityFlag);
        if (!compatibilityFlag) {
            globalRole(owner, "ROLE_PLATFORM_OWNER");
        }
        membership(owner, tenant, "TENANT_ADMIN");
        String platformToken = login(owner);

        mockMvc.perform(get("/api/platform/users").header("Authorization", bearer(platformToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[*].userId", hasItem(owner.getId().toString())));
        mockMvc.perform(get("/api/auth/context").header("Authorization", bearer(platformToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.platformScope").value(true));
        MvcResult switched = mockMvc.perform(post("/api/auth/tenant-context")
                        .header("Authorization", bearer(platformToken))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("tenantId", tenant.getId()))))
                .andExpect(status().isOk()).andReturn();
        String tenantToken = com.jayway.jsonpath.JsonPath.read(switched.getResponse().getContentAsString(), "$.token");

        mockMvc.perform(get("/api/auth/context").header("Authorization", bearer(tenantToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.tenantId").value(tenant.getId().toString()))
                .andExpect(jsonPath("$.actingAsPlatformOwner").value(true))
                .andExpect(jsonPath("$.tenantAccessMode").value("TENANT_MEMBERSHIP"));
        mockMvc.perform(get("/api/tenants/{tenantId}/members", tenant.getId())
                        .header("Authorization", bearer(tenantToken)))
                .andExpect(status().isOk());
        assertEquals(compatibilityFlag, users.findById(owner.getId()).orElseThrow().isPlatformOwner());
    }

    @Test
    void tenantAdminDemotionChangesNextActionWithOldToken() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser admin = user("demoted-admin", false);
        TenantMembership membership = membership(admin, tenant, "TENANT_ADMIN");
        String oldToken = login(admin);
        membership.setRole("READ_ONLY_AUDITOR");
        memberships.save(membership);

        mockMvc.perform(get("/api/tenants/{tenantId}/members", tenant.getId())
                        .header("Authorization", bearer(oldToken)))
                .andExpect(status().isForbidden());
        mockMvc.perform(get("/api/auth/context").header("Authorization", bearer(oldToken)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.roles", contains("READ_ONLY_AUDITOR")));
        String newToken = login(admin);
        mockMvc.perform(get("/api/tenants/{tenantId}/members", tenant.getId())
                        .header("Authorization", bearer(newToken))).andExpect(status().isForbidden());
        assertNoOwnerAuthority(admin);
    }

    @Test
    void disabledUserCannotLoginOrReuseExistingJwt() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser user = user("disabled-user", false);
        membership(user, tenant, "TENANT_ADMIN");
        String oldToken = login(user);
        user.setStatus("INACTIVE");
        users.save(user);

        mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", user.getEmail(), "password", PASSWORD))))
                .andExpect(status().is4xxClientError());
        mockMvc.perform(get("/api/auth/context").header("Authorization", bearer(oldToken)))
                .andExpect(status().is4xxClientError());
        assertEquals("INACTIVE", users.findById(user.getId()).orElseThrow().getStatus());
        assertNoOwnerAuthority(user);
    }

    @Test
    void corruptedStoredInviteCannotBeAcceptedOrRedelivered() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser admin = user("invite-admin", false);
        membership(admin, tenant, "TENANT_ADMIN");
        String adminToken = login(admin);
        TenantUserInvite invite = new TenantUserInvite();
        invite.setTenant(tenant);
        invite.setEmail(subject("corrupt-invite"));
        invite.setExternalSubject(invite.getEmail());
        invite.setRole("ROLE_ROLE_PLATFORM_OWNER");
        invite.setToken(UUID.randomUUID().toString());
        invite.setExpiresAt(Instant.now().plusSeconds(3600));
        String originalToken = invite.getToken();
        invite = invites.save(invite);

        mockMvc.perform(post("/api/tenant-invites/accept").contentType(MediaType.APPLICATION_JSON).content("{\"token\":\"" + originalToken + "\"}"))
                .andExpect(status().is4xxClientError());
        mockMvc.perform(post("/api/tenants/{tenantId}/invites/{inviteId}/resend", tenant.getId(), invite.getId())
                        .header("Authorization", bearer(adminToken)))
                .andExpect(status().is4xxClientError());

        TenantUserInvite unchanged = invites.findById(invite.getId()).orElseThrow();
        assertEquals(com.prototype.vulnwatch.service.InvitationTokens.hash(originalToken), unchanged.getTokenHash());
        assertNull(unchanged.getToken());
        assertNull(unchanged.getAcceptedAt());
        assertTrue(memberships.findFirstByUserExternalSubjectAndTenantId(invite.getExternalSubject(), tenant.getId()).isEmpty());
    }

    @Test
    void membershipRevocationRejectsOldAndFreshlySignedCredentials() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser member = user("revoked-member", false);
        TenantMembership membership = membership(member, tenant, "TENANT_ADMIN");
        String oldToken = login(member);
        membership.setStatus("REVOKED");
        memberships.saveAndFlush(membership);
        Map<String, Object> claims = new LinkedHashMap<>(membershipClaims(membership));
        claims.put("roles", List.of("TENANT_ADMIN"));
        for (String token : List.of(oldToken, historicalToken(member, claims))) {
            mockMvc.perform(get("/api/me").header("Authorization", bearer(token)))
                    .andExpect(status().isForbidden());
        }
        mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", member.getEmail(), "password", PASSWORD))))
                .andExpect(status().isForbidden());
    }

    @Test
    void revokedOwnerCannotConsumeSurvivingSupportGrantThroughTokenWithoutOwnerClaim() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser owner = user("revoked-support-owner", true);
        TenantSupportGrant grant = supportGrant(owner, tenant);
        Map<String, Object> claims = supportClaims(grant);
        // An external/legacy credential need not carry PLATFORM_OWNER. Stored
        // authority, not the presence of that token role, must govern support.
        claims.put("roles", List.of("SECURITY_ANALYST"));
        String token = historicalToken(owner, claims);
        mockMvc.perform(get("/api/me").header("Authorization", bearer(token)))
                .andExpect(status().isOk());

        globalRoleService.revokeRole(users.findById(owner.getId()).orElseThrow(), "PLATFORM_OWNER");

        mockMvc.perform(get("/api/me").header("Authorization", bearer(token)))
                .andExpect(status().isForbidden());
        assertTrue(supportGrantService.listActiveGrantsForPlatformOwner(owner.getExternalSubject()).isEmpty());
        assertNoOwnerAuthority(owner);
    }

    @ParameterizedTest
    @ValueSource(strings = {"REVOKED", "EXPIRED", "READ_ONLY"})
    void supportRevocationExpiryAndDowngradeRejectNextOldAndNewAction(String change) throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser owner = user("changed-support-owner", true);
        TenantSupportGrant grant = supportGrant(owner, tenant);
        Map<String, Object> claims = supportClaims(grant);
        claims.put("roles", List.of("PLATFORM_OWNER"));
        String oldToken = historicalToken(owner, claims);
        mockMvc.perform(get("/api/me").header("Authorization", bearer(oldToken))).andExpect(status().isOk());
        if ("EXPIRED".equals(change)) {
            grant.setExpiresAt(Instant.now().minusSeconds(1));
        } else if ("READ_ONLY".equals(change)) {
            grant.setAccessMode("READ_ONLY");
        } else {
            supportGrantService.revoke(tenant.getId(), grant.getId(), owner.getExternalSubject());
            grant = supportGrants.findById(grant.getId()).orElseThrow();
        }
        if (!"REVOKED".equals(change)) supportGrants.saveAndFlush(grant);
        for (String token : List.of(oldToken, historicalToken(owner, claims))) {
            mockMvc.perform(get("/api/me").header("Authorization", bearer(token)))
                    .andExpect(status().isForbidden());
        }
        if ("READ_ONLY".equals(change)) {
            Map<String, Object> readClaims = supportClaims(grant);
            readClaims.put("tenant_access_mode", "SUPPORT_READ_ONLY");
            readClaims.put("roles", List.of("PLATFORM_OWNER"));
            mockMvc.perform(get("/api/me").header("Authorization", bearer(historicalToken(owner, readClaims))))
                    .andExpect(status().isOk());
        }
    }

    @Test
    void supportAcceptanceCannotOverwriteCommittedRevocation() {
        Tenant tenant = tenantService.getDefaultTenant();
        AppUser owner = user("concurrent-support-owner", true);
        TenantSupportGrant grant = supportGrant(owner, tenant);
        var executor = Executors.newFixedThreadPool(2);
        CountDownLatch revoked = new CountDownLatch(1);
        CountDownLatch commit = new CountDownLatch(1);
        CountDownLatch accepting = new CountDownLatch(1);
        try {
            var revocation = executor.submit(() -> TenantContext.runAsPlatform(() -> transactions.execute(tx -> {
                supportGrantService.revoke(tenant.getId(), grant.getId(), owner.getExternalSubject());
                supportGrants.flush();
                revoked.countDown();
                await(commit);
                return null;
            })));
            assertTrue(revoked.await(10, TimeUnit.SECONDS));
            var acceptance = executor.submit(() -> {
                accepting.countDown();
                return assertThrows(org.springframework.web.server.ResponseStatusException.class,
                        () -> supportGrantService.accept(grant.getId(), owner.getExternalSubject())).getStatusCode().value();
            });
            assertTrue(accepting.await(10, TimeUnit.SECONDS));
            assertThrows(TimeoutException.class, () -> acceptance.get(300, TimeUnit.MILLISECONDS));
            commit.countDown();
            revocation.get(10, TimeUnit.SECONDS);
            assertEquals(403, acceptance.get(10, TimeUnit.SECONDS).intValue());
            assertEquals("REVOKED", supportGrants.findById(grant.getId()).orElseThrow().getStatus());
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        } finally {
            commit.countDown();
            executor.shutdownNow();
        }
    }

    private TenantSupportGrant supportGrant(AppUser owner, Tenant tenant) {
        TenantSupportGrant grant = new TenantSupportGrant();
        grant.setTenant(tenant);
        grant.setInvitedPlatformSubject(owner.getExternalSubject());
        grant.setGrantedBy(owner);
        grant.setAcceptedBy(owner);
        grant.setReason("Controlled revocation regression");
        grant.setStatus("ACTIVE");
        grant.setAccessMode("WRITE_ENABLED");
        grant.setAcceptedAt(Instant.now());
        grant.setExpiresAt(Instant.now().plusSeconds(3600));
        return supportGrants.saveAndFlush(grant);
    }

    private Map<String, Object> supportClaims(TenantSupportGrant grant) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("active_tenant_id", grant.getTenant().getId().toString());
        claims.put("tenant_access_mode", "SUPPORT_WRITE_ENABLED");
        claims.put("tenant_access_ref", grant.getId().toString());
        return claims;
    }

    private String login(AppUser user) throws Exception {
        MvcResult result = mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json(Map.of("email", user.getEmail(), "password", PASSWORD))))
                .andExpect(status().isOk()).andReturn();
        return com.jayway.jsonpath.JsonPath.read(result.getResponse().getContentAsString(), "$.token");
    }

    private AppUser user(String label, boolean platformOwner) {
        AppUser user = new AppUser();
        user.setExternalSubject(subject(label));
        user.setEmail(user.getExternalSubject());
        user.setDisplayName(label);
        user.setPasswordHash(PASSWORD_HASH);
        user.setPasswordSetAt(Instant.now());
        user.setStatus("ACTIVE");
        user.setPlatformOwner(platformOwner);
        return users.save(user);
    }

    private TenantMembership membership(AppUser user, Tenant tenant, String role) {
        TenantMembership membership = new TenantMembership();
        membership.setUser(user);
        membership.setTenant(tenant);
        membership.setRole(role);
        membership.setStatus("ACTIVE");
        return memberships.save(membership);
    }

    private void globalRole(AppUser user, String role) {
        AppUserGlobalRole grant = new AppUserGlobalRole();
        grant.setUser(user);
        grant.setRole(role);
        globalRoles.save(grant);
    }

    private void assertNoOwnerAuthority(AppUser user) {
        assertFalse(users.findById(user.getId()).orElseThrow().isPlatformOwner());
        assertTrue(globalRoles.findByUser_IdOrderByCreatedAtAsc(user.getId()).isEmpty());
    }

    private String historicalToken(AppUser user, Map<String, Object> roleClaims) throws Exception {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss","urn:scoutgrid:local");
        claims.put("aud",java.util.List.of("scoutgrid-api"));
        claims.put("token_use","access");
        claims.put("sub", user.getExternalSubject());
        claims.put("email", user.getEmail());
        claims.put("iat", Instant.now().getEpochSecond());
        claims.put("exp", Instant.now().plusSeconds(3600).getEpochSecond());
        claims.putAll(roleClaims);
        String unsigned = base64(json(Map.of("alg", "HS256", "typ", "JWT")).getBytes(StandardCharsets.UTF_8))
                + "." + base64(json(claims).getBytes(StandardCharsets.UTF_8));
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(JWT_SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return unsigned + "." + base64(mac.doFinal(unsigned.getBytes(StandardCharsets.UTF_8)));
    }

    private Map<String, Object> membershipClaims(TenantMembership membership) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("active_tenant_id", membership.getTenant().getId().toString());
        claims.put("tenant_access_mode", "TENANT_MEMBERSHIP");
        claims.put("tenant_access_ref", membership.getId().toString());
        return claims;
    }

    private String json(Object value) throws Exception {
        return objectMapper.writeValueAsString(value);
    }

    private String base64(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private String bearer(String token) {
        return "Bearer " + token;
    }

    private String subject(String label) {
        return label + "-" + UUID.randomUUID() + "@example.test";
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) {
                throw new IllegalStateException("Timed out waiting for authorization regression transaction");
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(interrupted);
        }
    }
}
