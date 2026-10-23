package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantSupportGrant;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class LocalCredentialAuthServiceTest {

    private static final String SECRET = "phase-1-local-auth-secret-32-bytes";

    @Mock
    private AppUserRepository userRepository;

    @Mock
    private TenantRepository tenantRepository;

    @Mock
    private TenantMembershipRepository membershipRepository;

    @Mock
    private TenantSupportGrantService tenantSupportGrantService;
    @Mock
    private TenantLifecycleGuardService tenantLifecycleGuardService;
    @Mock
    private AppUserGlobalRoleService appUserGlobalRoleService;
    @Mock
    private AuditEventService auditEventService;
    @Mock
    private TenantWorkRunner tenantWorkRunner;

    @Test
    void platformOwnerLoginReturnsPlatformScopeToken() {
        AppUser existingUser = new AppUser();
        existingUser.setExternalSubject("owner@example.com");
        existingUser.setEmail("owner@example.com");
        existingUser.setPasswordHash(BCrypt.hashpw("password-123", BCrypt.gensalt(10)));
        existingUser.setPlatformOwner(true);

        when(userRepository.findByEmailIgnoreCaseForUpdate("owner@example.com")).thenReturn(Optional.of(existingUser));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                tenantWorkRunner,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.login("OWNER@example.com", "password-123");
        Jwt jwt = decode(response.token());

        assertEquals("owner@example.com", jwt.getSubject());
        assertEquals("PLATFORM_OWNER", jwt.getClaimAsStringList("roles").get(0));
        assertNull(jwt.getClaimAsString("active_tenant_id"));
        assertTrue(existingUser.isPlatformOwner());
        verify(userRepository).save(existingUser);
        verify(appUserGlobalRoleService, never()).ensureRole(any(), anyString());
    }

    @Test
    void tenantOwnerLoginReturnsSingleTenantContext() {
        AppUser user = new AppUser();
        user.setExternalSubject("tenant.owner@example.com");
        user.setEmail("tenant.owner@example.com");
        user.setPasswordHash(BCrypt.hashpw("password-123", BCrypt.gensalt(10)));

        Tenant tenant = tenant("Example Co");
        TenantMembership membership = membership(user, tenant, "TENANT_ADMIN");

        when(userRepository.findByEmailIgnoreCaseForUpdate("tenant.owner@example.com")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(membershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc("tenant.owner@example.com", "ACTIVE"))
                .thenReturn(List.of(membership));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "tenant.owner@example.com", tenant.getId(), "ACTIVE")).thenReturn(Optional.of(membership));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                tenantWorkRunner,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.login("tenant.owner@example.com", "password-123");
        Jwt jwt = decode(response.token());

        assertEquals("tenant.owner@example.com", jwt.getSubject());
        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        assertEquals("TENANT_ADMIN", jwt.getClaimAsStringList("roles").get(0));
    }

    @Test
    void passwordSetupWorksExactlyOnce() {
        AppUser user = new AppUser();
        user.setExternalSubject("tenant.owner@example.com");
        user.setEmail("tenant.owner@example.com");
        user.setPasswordSetupTokenHash(hashToken("setup-token-123"));
        user.setPasswordSetupTokenExpiresAt(Instant.now().plusSeconds(3600));

        Tenant tenant = tenant("Example Co");
        TenantMembership membership = membership(user, tenant, "TENANT_ADMIN");

        when(userRepository.findByPasswordSetupTokenHashForUpdate(hashToken("setup-token-123"))).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(membershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc("tenant.owner@example.com", "ACTIVE"))
                .thenReturn(List.of(membership));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "tenant.owner@example.com", tenant.getId(), "ACTIVE")).thenReturn(Optional.of(membership));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                tenantWorkRunner,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.setupPassword("setup-token-123", "password-123");
        Jwt jwt = decode(response.token());

        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        assertTrue(BCrypt.checkpw("password-123", user.getPasswordHash()));
        assertNull(user.getPasswordSetupTokenHash());
        assertNull(user.getPasswordSetupTokenExpiresAt());

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.setupPassword("setup-token-123", "password-456")
        );
        assertEquals(400, error.getStatusCode().value());
    }

    @Test
    void platformOwnerPasswordSetupReturnsPlatformScopeToken() {
        AppUser user = new AppUser();
        user.setExternalSubject("owner@example.com");
        user.setEmail("owner@example.com");
        user.setPlatformOwner(true);
        user.setPasswordSetupTokenHash(hashToken("setup-token-123"));
        user.setPasswordSetupTokenExpiresAt(Instant.now().plusSeconds(3600));

        when(userRepository.findByPasswordSetupTokenHashForUpdate(hashToken("setup-token-123"))).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                tenantWorkRunner,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.setupPassword("setup-token-123", "password-123");
        Jwt jwt = decode(response.token());

        assertEquals("owner@example.com", jwt.getSubject());
        assertNull(jwt.getClaimAsString("active_tenant_id"));
        assertEquals("PLATFORM_OWNER", jwt.getClaimAsStringList("roles").get(0));
        assertTrue(BCrypt.checkpw("password-123", user.getPasswordHash()));
        verify(auditEventService).recordExplicitActor(
                null,
                "owner@example.com",
                "PLATFORM_OWNER",
                "platform.user.setup_completed",
                "app_user",
                user.getId().toString(),
                "{\"mode\":\"self_service\"}",
                "SUCCESS"
        );
        verify(appUserGlobalRoleService, never()).ensureRole(any(), anyString());
    }

    @Test
    void platformOwnerWithoutPasswordHashCannotUseRemovedSharedLocalhostFallback() {
        AppUser user = new AppUser();
        user.setExternalSubject("owner@example.com");
        user.setEmail("owner@example.com");
        user.setPlatformOwner(true);

        when(userRepository.findByEmailIgnoreCaseForUpdate("owner@example.com")).thenReturn(Optional.of(user));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                tenantWorkRunner,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        assertThrows(ResponseStatusException.class, () -> service.login("owner@example.com", "password-123"));
    }

    @Test
    void switchTenantContextRequiresActiveGrantAndIssuesTenantBoundToken() {
        AppUser platformOwner = new AppUser();
        platformOwner.setExternalSubject("owner@example.com");
        platformOwner.setEmail("owner@example.com");
        platformOwner.setPlatformOwner(true);
        Tenant tenant = tenant("Customer A");

        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.of(platformOwner));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        TenantSupportGrant grant = new TenantSupportGrant();
        grant.setId(UUID.randomUUID());
        grant.setTenant(tenant);
        grant.setAccessMode("WRITE_ENABLED");
        when(tenantSupportGrantService.findActiveGrant("owner@example.com", tenant.getId()))
                .thenReturn(Optional.of(grant));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                tenantWorkRunner,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.switchTenantContext("owner@example.com", tenant.getId());
        Jwt jwt = decode(response.token());

        assertEquals("SUPPORT_WRITE_ENABLED", jwt.getClaimAsString("tenant_access_mode"));
        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        assertEquals("PLATFORM_OWNER", jwt.getClaimAsStringList("roles").get(0));
    }

    @Test
    void switchTenantContextUsesExplicitTenantMembershipForInternalPlaygroundAccess() {
        AppUser platformOwner = new AppUser();
        platformOwner.setExternalSubject("owner@example.com");
        platformOwner.setEmail("owner@example.com");
        platformOwner.setPlatformOwner(true);
        Tenant tenant = tenant("SG Internal");
        tenant.setClassification("INTERNAL");
        tenant.setSlug(TenantAccessResolutionService.PLAYGROUND_SLUG);
        TenantMembership membership = membership(platformOwner, tenant, "TENANT_ADMIN");
        membership.setProvenance("MANUAL");

        when(userRepository.findByExternalSubject("owner@example.com")).thenReturn(Optional.of(platformOwner));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "owner@example.com",
                tenant.getId(),
                "ACTIVE"
        )).thenReturn(Optional.of(membership));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                tenantWorkRunner,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.switchTenantContext("owner@example.com", tenant.getId());
        Jwt jwt = decode(response.token());

        ArgumentCaptor<Runnable> scopedAudit = ArgumentCaptor.forClass(Runnable.class);
        verify(tenantWorkRunner).runScoped(eq(tenant), scopedAudit.capture());
        verifyNoInteractions(auditEventService);
        scopedAudit.getValue().run();

        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        assertTrue(jwt.getClaimAsStringList("roles").contains("PLATFORM_OWNER"));
        assertTrue(jwt.getClaimAsStringList("roles").contains("TENANT_ADMIN"));
        verify(auditEventService).recordExplicitActor(
                eq(tenant.getId()),
                eq("owner@example.com"),
                eq("PLATFORM_OWNER"),
                eq("tenant.context.entered"),
                eq("tenant_access"),
                eq(membership.getId().toString()),
                eq("{\"mode\":\"TENANT_MEMBERSHIP\"}"),
                eq("SUCCESS"));
        verifyNoInteractions(tenantSupportGrantService);
    }

    @Test
    void clearTenantContextIssuesFreshPlatformScopeToken() {
        AppUser platformOwner = new AppUser();
        platformOwner.setExternalSubject("owner@example.com");
        platformOwner.setEmail("owner@example.com");
        platformOwner.setPlatformOwner(true);
        when(userRepository.findByExternalSubject("owner@example.com")).thenAnswer(invocation -> {
            assertTrue(TenantContext.isPlatformContext());
            assertNull(TenantContext.getCurrentTenantId());
            return Optional.of(platformOwner);
        });
        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                tenantWorkRunner,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        UUID activeTenantId = UUID.randomUUID();
        TenantContext.setCurrentTenantId(activeTenantId);
        TenantContext.setCurrentSchemaName("tenant_default");
        try {
            AuthTokenResponse response = service.clearTenantContext("owner@example.com");
            Jwt jwt = decode(response.token());

            assertNull(jwt.getClaimAsString("active_tenant_id"));
            assertEquals("PLATFORM_OWNER", jwt.getClaimAsStringList("roles").get(0));
            assertEquals(activeTenantId, TenantContext.getCurrentTenantId());
            assertEquals("tenant_default", TenantContext.getCurrentSchemaName());

            ArgumentCaptor<Runnable> scopedAudit = ArgumentCaptor.forClass(Runnable.class);
            verify(tenantWorkRunner).runScoped(eq(activeTenantId), scopedAudit.capture());
            verifyNoInteractions(auditEventService);
            scopedAudit.getValue().run();
            verify(auditEventService).recordExplicitActor(
                    activeTenantId,
                    "owner@example.com",
                    "PLATFORM_OWNER",
                    "tenant.context.exited",
                    "app_user",
                    platformOwner.getId().toString(),
                    null,
                    "SUCCESS");
        } finally {
            TenantContext.clear();
        }
    }

    @Test
    void ordinaryUserCannotSwitchOrClearPlatformOwnerTenantContext() {
        AppUser ordinaryUser = new AppUser();
        ordinaryUser.setExternalSubject("analyst@example.com");
        ordinaryUser.setEmail("analyst@example.com");
        when(userRepository.findByExternalSubject("analyst@example.com")).thenReturn(Optional.of(ordinaryUser));
        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                tenantWorkRunner,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );
        UUID selectedTenantId = UUID.randomUUID();
        TenantContext.setCurrentTenantId(selectedTenantId);
        TenantContext.setCurrentSchemaName("tenant_default");
        try {
            ResponseStatusException switchError = assertThrows(ResponseStatusException.class,
                    () -> service.switchTenantContext("analyst@example.com", UUID.randomUUID()));
            assertEquals(org.springframework.http.HttpStatus.FORBIDDEN, switchError.getStatusCode());
            assertEquals(selectedTenantId, TenantContext.getCurrentTenantId());

            ResponseStatusException clearError = assertThrows(ResponseStatusException.class,
                    () -> service.clearTenantContext("analyst@example.com"));
            assertEquals(org.springframework.http.HttpStatus.FORBIDDEN, clearError.getStatusCode());
            assertEquals(selectedTenantId, TenantContext.getCurrentTenantId());
            assertEquals("tenant_default", TenantContext.getCurrentSchemaName());
            verifyNoInteractions(tenantRepository, membershipRepository, tenantSupportGrantService,
                    tenantWorkRunner, auditEventService);
        } finally {
            TenantContext.clear();
        }
    }

    @Test
    void localhostSharedTenantAdminLoginBootstrapsDefaultWorkspaceMembership() {
        String configuredPasswordHash = BCrypt.hashpw("LocalDevTenant123!", BCrypt.gensalt(10));
        Tenant tenant = tenant("SG Internal");
        tenant.setClassification("INTERNAL");
        AppUser user = new AppUser();
        user.setExternalSubject("tenant.admin@localhost");
        user.setEmail("tenant.admin@localhost");

        when(tenantRepository.findBySchemaName("tenant_default")).thenReturn(Optional.of(tenant));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(userRepository.findByEmailIgnoreCaseForUpdate("tenant.admin@localhost")).thenReturn(Optional.empty());
        when(userRepository.findByExternalSubjectForUpdate("tenant.admin@localhost")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        AtomicReference<TenantMembership> savedMembership = new AtomicReference<>();
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "tenant.admin@localhost",
                tenant.getId(),
                "ACTIVE"
        )).thenAnswer(invocation -> Optional.ofNullable(savedMembership.get()));
        when(membershipRepository.save(any(TenantMembership.class))).thenAnswer(invocation -> {
            TenantMembership saved = invocation.getArgument(0);
            if (saved.getId() == null) saved.setId(UUID.randomUUID());
            savedMembership.set(saved);
            return saved;
        });

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                tenantWorkRunner,
                false,
                true,
                "tenant.admin@localhost",
                configuredPasswordHash,
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.login("tenant.admin@localhost", "LocalDevTenant123!");
        Jwt jwt = decode(response.token());

        assertEquals("tenant.admin@localhost", jwt.getSubject());
        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        assertEquals("TENANT_ADMIN", jwt.getClaimAsStringList("roles").get(0));
        assertTrue(BCrypt.checkpw("LocalDevTenant123!", user.getPasswordHash()));
        verify(membershipRepository).save(any(TenantMembership.class));
    }

    @Test
    void realTenantAdminLoginWinsOverSharedLocalhostFallback() {
        AppUser user = new AppUser();
        user.setExternalSubject("tenant.admin@localhost");
        user.setEmail("tenant.admin@localhost");
        user.setPasswordHash(BCrypt.hashpw("gm-test-password", BCrypt.gensalt(10)));

        Tenant tenant = tenant("GM Test");
        TenantMembership membership = membership(user, tenant, "TENANT_ADMIN");

        when(userRepository.findByEmailIgnoreCaseForUpdate("tenant.admin@localhost")).thenReturn(Optional.of(user));
        when(userRepository.save(any(AppUser.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(membershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc("tenant.admin@localhost", "ACTIVE"))
                .thenReturn(List.of(membership));
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "tenant.admin@localhost", tenant.getId(), "ACTIVE")).thenReturn(Optional.of(membership));

        LocalCredentialAuthService service = new LocalCredentialAuthService(
                userRepository,
                tenantRepository,
                membershipRepository,
                authTokenService(),
                tenantSupportGrantService,
                tenantLifecycleGuardService,
                appUserGlobalRoleService,
                auditEventService,
                tenantWorkRunner,
                false,
                true,
                "",
                "",
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        AuthTokenResponse response = service.login("tenant.admin@localhost", "gm-test-password");
        Jwt jwt = decode(response.token());

        assertEquals(tenant.getId().toString(), jwt.getClaimAsString("active_tenant_id"));
        verify(tenantRepository).findById(tenant.getId());
    }

    @Test
    void disabledSubjectAliasCannotBeReactivatedBySharedLocalhostLogin() {
        String email = "tenant.admin@localhost";
        AppUser user = new AppUser();
        user.setExternalSubject(email);
        user.setEmail("previous-email@example.test");
        user.setStatus("INACTIVE");
        Tenant tenant = tenant("SG Internal");
        tenant.setClassification("INTERNAL");
        when(userRepository.findByEmailIgnoreCaseForUpdate(email)).thenReturn(Optional.empty());
        when(userRepository.findByExternalSubjectForUpdate(email)).thenReturn(Optional.of(user));
        when(tenantRepository.findBySchemaName("tenant_default")).thenReturn(Optional.of(tenant));
        LocalCredentialAuthService service = new LocalCredentialAuthService(userRepository, tenantRepository,
                membershipRepository, authTokenService(), tenantSupportGrantService, tenantLifecycleGuardService,
                appUserGlobalRoleService, auditEventService, tenantWorkRunner, false, true, email,
                BCrypt.hashpw("local-password", BCrypt.gensalt(10)), "http://localhost:5173");

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service.login(email, "local-password"));

        assertEquals(401, error.getStatusCode().value());
        assertEquals("INACTIVE", user.getStatus());
        verify(userRepository, never()).save(any());
        verifyNoInteractions(membershipRepository);
    }

    private AuthTokenService authTokenService() {
        return new AuthTokenService(SECRET, 60, "active_tenant_id");
    }

    private Jwt decode(String token) {
        return NimbusJwtDecoder
                .withSecretKey(new SecretKeySpec(SECRET.getBytes(StandardCharsets.UTF_8), "HmacSHA256"))
                .build()
                .decode(token);
    }

    private Tenant tenant(String name) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        return tenant;
    }

    private TenantMembership membership(AppUser user, Tenant tenant, String role) {
        TenantMembership membership = new TenantMembership();
        membership.setId(UUID.randomUUID());
        membership.setTenant(tenant);
        membership.setUser(user);
        membership.setRole(role);
        membership.setStatus("ACTIVE");
        return membership;
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}
