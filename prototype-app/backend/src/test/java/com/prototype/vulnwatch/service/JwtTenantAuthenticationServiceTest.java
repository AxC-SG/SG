package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantSupportGrant;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class JwtTenantAuthenticationServiceTest {

    @Mock
    AppUserRepository userRepository;

    @Mock
    TenantRepository tenantRepository;

    @Mock
    TenantMembershipRepository membershipRepository;
    @Mock
    TenantLifecycleGuardService tenantLifecycleGuardService;
    @Mock
    AppUserGlobalRoleService appUserGlobalRoleService;
    @Mock
    TenantSupportGrantService tenantSupportGrantService;

    @Test
    void platformOwnerJwtWithoutExplicitTenantStaysTenantless() {
        AppUser user = new AppUser();
        user.setId(java.util.UUID.randomUUID());
        user.setExternalSubject("owner@example.com");

        when(userRepository.findByExternalSubjectForUpdate("owner@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "sub",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles",
                "scout-ui");

        AuthenticatedTenantActor actor = service.authenticate(Jwt.withTokenValue("token")
                .header("alg", "HS256")
                .subject("owner@example.com")
                .claim("email", "owner@example.com")
                .claim("roles", List.of("PLATFORM_OWNER"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build());

        assertEquals("owner@example.com", actor.subject());
        assertNull(actor.tenantId());
        assertNull(actor.tenantName());
        assertEquals(Set.of("PLATFORM_OWNER"), actor.roles());
        verify(appUserGlobalRoleService, never()).ensureRole(any(), anyString());
        assertFalse(user.isPlatformOwner());
    }

    @Test
    void keycloakRealmRolePreservesCurrentOwnerWithoutCreatingGrant() {
        AppUser user = new AppUser();
        user.setId(java.util.UUID.randomUUID());
        user.setExternalSubject("kc-owner");

        when(userRepository.findByExternalSubjectForUpdate("kc-owner")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "sub",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles",
                "scout-ui");

        AuthenticatedTenantActor actor = service.authenticate(Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("kc-owner")
                .claim("email", "owner@example.com")
                .claim("realm_access", Map.of("roles", List.of("platform-owner")))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build());

        assertEquals(Set.of("PLATFORM_OWNER"), actor.roles());
        verify(appUserGlobalRoleService, never()).ensureRole(any(), anyString());
        assertFalse(user.isPlatformOwner());
    }

    @Test
    void storedGlobalRoleSupportsPlatformScopeWithoutJwtRole() {
        AppUser user = new AppUser();
        user.setId(java.util.UUID.randomUUID());
        user.setExternalSubject("stored-owner");

        when(userRepository.findByExternalSubjectForUpdate("stored-owner")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "sub",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles",
                "scout-ui");

        AuthenticatedTenantActor actor = service.authenticate(Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("stored-owner")
                .claim("email", "stored-owner@example.com")
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build());

        assertEquals(Set.of("PLATFORM_OWNER"), actor.roles());
        assertNull(actor.tenantId());
    }

    @Test
    void namespacedRolesClaimSupportsPlatformOwnerTokens() {
        AppUser user = new AppUser();
        user.setId(java.util.UUID.randomUUID());
        user.setExternalSubject("owner@example.com");

        when(userRepository.findByExternalSubjectForUpdate("owner@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "email",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "https://hossstore.in/roles",
                "scout-ui");

        AuthenticatedTenantActor actor = service.authenticate(Jwt.withTokenValue("token")
                .header("alg", "RS256")
                .subject("owner-subject-123")
                .claim("email", "owner@example.com")
                .claim("https://hossstore.in/roles", List.of("PLATFORM_OWNER"))
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build());

        assertEquals("owner@example.com", actor.subject());
        assertEquals(Set.of("PLATFORM_OWNER"), actor.roles());
        verify(appUserGlobalRoleService, never()).ensureRole(any(), anyString());
        assertFalse(user.isPlatformOwner());
    }

    @Test
    void platformOwnerActiveTenantContextRequiresGrantAndSwitchesTenant() {
        AppUser user = new AppUser();
        user.setId(UUID.randomUUID());
        user.setExternalSubject("owner@example.com");
        UUID tenantId = UUID.fromString("11111111-1111-1111-1111-111111111111");
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setName("Acme");
        tenant.setSchemaName("tenant_acme");
        UUID grantId = UUID.randomUUID();
        TenantSupportGrant grant = new TenantSupportGrant();
        grant.setId(grantId);
        grant.setTenant(tenant);
        grant.setAccessMode("WRITE_ENABLED");

        when(userRepository.findByExternalSubjectForUpdate("owner@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenantSupportGrantService.findActiveGrant("owner@example.com", tenantId)).thenReturn(Optional.of(grant));

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "sub",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles",
                "scout-ui");

        AuthenticatedTenantActor actor = service.authenticate(Jwt.withTokenValue("token")
                        .header("alg", "HS256")
                        .subject("owner@example.com")
                        .claim("email", "owner@example.com")
                        .claim("roles", List.of("PLATFORM_OWNER"))
                        .claim("active_tenant_id", tenantId.toString())
                        .claim("tenant_access_mode", "SUPPORT_WRITE_ENABLED")
                        .claim("tenant_access_ref", grantId.toString())
                        .issuedAt(Instant.now())
                        .expiresAt(Instant.now().plusSeconds(3600))
                        .build(),
                "/api/ingestion/nvd-sync");

        assertEquals(tenantId, actor.tenantId());
        assertEquals("Acme", actor.tenantName());
        assertEquals(TenantAccessMode.SUPPORT_WRITE_ENABLED, actor.accessMode());
    }

    @Test
    void platformOwnerTenantIdClaimWithoutGrantIsDenied() {
        AppUser user = new AppUser();
        user.setId(UUID.randomUUID());
        user.setExternalSubject("owner@example.com");
        UUID tenantId = UUID.fromString("22222222-2222-2222-2222-222222222222");
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setName("Beta");
        tenant.setSchemaName("tenant_beta");

        when(userRepository.findByExternalSubjectForUpdate("owner@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of("PLATFORM_OWNER"));

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "sub",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles",
                "scout-ui");

        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "HS256")
                .subject("owner@example.com")
                .claim("email", "owner@example.com")
                .claim("roles", List.of("PLATFORM_OWNER"))
                .claim("tenant_id", tenantId.toString())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        assertThrows(ResponseStatusException.class, () -> service.authenticate(jwt));
    }

    @ParameterizedTest
    @ValueSource(strings = {"PLATFORM_OWNER", "platform-owner", "platform owner", "ROLE_ROLE_PLATFORM_OWNER"})
    void staleOwnerRoleCannotCreateCurrentOwnerGrant(String role) {
        AppUser user = registeredUser("former-owner", Set.of());
        Jwt jwt = token(user).claim("roles", List.of(role)).build();

        assertThrows(ResponseStatusException.class, () -> authenticationService("roles").authenticate(jwt));

        verify(appUserGlobalRoleService, never()).ensureRole(any(), anyString());
        assertFalse(user.isPlatformOwner());
    }

    @Test
    void staleNamespacedOwnerRoleCannotCreateCurrentOwnerGrant() {
        AppUser user = registeredUser("former-namespaced-owner", Set.of());
        Jwt jwt = token(user).claim("https://identity.example/roles", List.of("ROLE_ROLE_PLATFORM_OWNER")).build();

        assertThrows(ResponseStatusException.class, () -> authenticationService("roles").authenticate(jwt));

        verify(appUserGlobalRoleService, never()).ensureRole(any(), anyString());
        assertFalse(user.isPlatformOwner());
    }

    @Test
    void staleKeycloakRealmAndClientOwnerRolesCannotCreateCurrentOwnerGrant() {
        AppUser user = registeredUser("former-keycloak-owner", Set.of());
        Jwt realm = token(user).claim("realm_access", Map.of("roles", List.of("ROLE_ROLE_PLATFORM_OWNER"))).build();
        Jwt client = token(user).claim("resource_access", Map.of(
                "scout-ui", Map.of("roles", List.of("platform-owner")))).build();

        assertThrows(ResponseStatusException.class, () -> authenticationService("roles").authenticate(realm));
        assertThrows(ResponseStatusException.class, () -> authenticationService("roles").authenticate(client));

        verify(appUserGlobalRoleService, never()).ensureRole(any(), anyString());
        assertFalse(user.isPlatformOwner());
    }

    @ParameterizedTest
    @ValueSource(strings = {"PLATFORM_OWNER", "ROLE_ROLE_PLATFORM_OWNER", "CREATOR", "SERVICE_ACCOUNT", "OPERATOR", "unknown", ""})
    void invalidStoredMembershipCannotSupplyAuthenticatedAuthorities(String role) {
        AppUser user = registeredUser("corrupt-membership", Set.of());
        TenantMembership membership = membership(user, role);
        Jwt jwt = token(user).claim("roles", List.of("SECURITY_ANALYST"))
                .claim("tenant_id", membership.getTenant().getId().toString()).build();

        assertThrows(ResponseStatusException.class, () -> authenticationService("roles").authenticate(jwt));

        verify(appUserGlobalRoleService, never()).ensureRole(any(), anyString());
        assertFalse(user.isPlatformOwner());
    }

    @Test
    void oldTenantAdminClaimUsesCurrentDemotedMembership() {
        AppUser user = registeredUser("demoted-admin", Set.of());
        TenantMembership membership = membership(user, "READ_ONLY_AUDITOR");
        Jwt jwt = token(user).claim("roles", List.of("TENANT_ADMIN"))
                .claim("tenant_id", membership.getTenant().getId().toString()).build();

        AuthenticatedTenantActor actor = authenticationService("roles").authenticate(jwt);

        assertEquals(Set.of("READ_ONLY_AUDITOR"), actor.roles());
        assertEquals(TenantAccessMode.TENANT_MEMBERSHIP, actor.accessMode());
    }

    @Test
    void currentOwnerCanKeepExplicitTenantMembershipSelected() {
        AppUser user = registeredUser("member-owner", Set.of("PLATFORM_OWNER"));
        TenantMembership membership = membership(user, "TENANT_ADMIN");
        Jwt jwt = token(user).claim("roles", List.of("ROLE_ROLE_PLATFORM_OWNER", "TENANT_ADMIN"))
                .claim("active_tenant_id", membership.getTenant().getId().toString())
                .claim("tenant_access_mode", "TENANT_MEMBERSHIP")
                .claim("tenant_access_ref", membership.getId().toString()).build();

        AuthenticatedTenantActor actor = authenticationService("roles").authenticate(jwt);

        assertEquals(Set.of("PLATFORM_OWNER", "TENANT_ADMIN"), actor.roles());
        assertEquals(membership.getTenant().getId(), actor.tenantId());
        assertEquals(TenantAccessMode.TENANT_MEMBERSHIP, actor.accessMode());
        verify(appUserGlobalRoleService, never()).ensureRole(any(), anyString());
    }

    @Test
    void disabledCurrentOwnerCannotAuthenticate() {
        AppUser user = new AppUser();
        user.setExternalSubject("disabled-owner");
        user.setStatus("INACTIVE");
        when(userRepository.findByExternalSubjectForUpdate(user.getExternalSubject())).thenReturn(Optional.of(user));

        assertThrows(ResponseStatusException.class, () -> authenticationService("roles").authenticate(
                token(user).claim("roles", List.of("PLATFORM_OWNER")).build()));

        verify(appUserGlobalRoleService, never()).ensureRole(any(), anyString());
    }

    private AppUser registeredUser(String subject, Set<String> currentRoles) {
        AppUser user = new AppUser();
        user.setExternalSubject(subject);
        when(userRepository.findByExternalSubjectForUpdate(subject)).thenReturn(Optional.of(user));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(currentRoles);
        return user;
    }

    private TenantMembership membership(AppUser user, String role) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Authorization fixture");
        tenant.setSchemaName("tenant_auth_fixture");
        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenant);
        membership.setUser(user);
        membership.setRole(role);
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                user.getExternalSubject(), tenant.getId(), "ACTIVE")).thenReturn(Optional.of(membership));
        return membership;
    }

    private Jwt.Builder token(AppUser user) {
        return Jwt.withTokenValue("test-token").header("alg", "HS256")
                .subject(user.getExternalSubject()).issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600));
    }

    private JwtTenantAuthenticationService authenticationService(String roleClaim) {
        return new JwtTenantAuthenticationService(userRepository, tenantRepository, membershipRepository,
                tenantLifecycleGuardService, appUserGlobalRoleService, tenantSupportGrantService,
                "sub", "tenant_id", "active_tenant_id", "tenant_slug", "email", "name", roleClaim, "scout-ui");
    }

    @Test
    void nonPlatformTenantIdClaimRequiresActiveMembership() {
        AppUser user = new AppUser();
        user.setId(UUID.randomUUID());
        user.setExternalSubject("analyst@example.com");
        UUID tenantId = UUID.fromString("33333333-3333-3333-3333-333333333333");
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setName("Gamma");
        tenant.setSchemaName("tenant_gamma");

        when(userRepository.findByExternalSubjectForUpdate("analyst@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(appUserGlobalRoleService.rolesForUser(user.getId())).thenReturn(Set.of());
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "analyst@example.com",
                tenantId,
                "ACTIVE"
        )).thenReturn(Optional.empty());

        JwtTenantAuthenticationService service = new JwtTenantAuthenticationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                tenantSupportGrantService,
                "sub",
                "tenant_id",
                "active_tenant_id",
                "tenant_slug",
                "email",
                "name",
                "roles",
                "scout-ui");

        Jwt jwt = Jwt.withTokenValue("token")
                .header("alg", "HS256")
                .subject("analyst@example.com")
                .claim("email", "analyst@example.com")
                .claim("roles", List.of("SECURITY_ANALYST"))
                .claim("tenant_id", tenantId.toString())
                .issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();

        assertThrows(ResponseStatusException.class, () -> service.authenticate(jwt));
    }
}
