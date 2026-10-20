package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verifyNoInteractions;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.AuditEvent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.dto.PlatformUserResponse;
import com.prototype.vulnwatch.dto.PlatformUserSetupLinkResponse;
import com.prototype.vulnwatch.repo.AuditEventRepository;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.ServiceAccountRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.repo.TenantUserInviteRepository;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class IdentityAdministrationServiceTest {

    @Mock
    private AppUserRepository userRepository;
    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private TenantMembershipRepository membershipRepository;
    @Mock
    private TenantUserInviteRepository tenantUserInviteRepository;
    @Mock
    private ServiceAccountRepository serviceAccountRepository;
    @Mock
    private AuditEventRepository auditEventRepository;
    @Mock
    private TenantQuotaService tenantQuotaService;
    @Mock
    private TenantSchemaExecutionService tenantSchemaExecutionService;
    @Mock
    private AppUserGlobalRoleService appUserGlobalRoleService;
    @Mock
    private LocalCredentialAuthService localCredentialAuthService;

    @Test
    void addMemberRejectsActiveMembershipInAnotherTenant() {
        UUID requestedTenantId = UUID.randomUUID();
        UUID existingTenantId = UUID.randomUUID();
        Tenant requestedTenant = tenant(requestedTenantId, "Requested");
        Tenant existingTenant = tenant(existingTenantId, "Existing");
        AppUser user = user("customer@example.com", false);

        when(tenantRepository.findById(requestedTenantId)).thenReturn(Optional.of(requestedTenant));
        when(userRepository.findByExternalSubject("customer@example.com")).thenReturn(Optional.of(user));
        when(userRepository.findByIdForUpdate(user.getId())).thenReturn(Optional.of(user));
        when(membershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc("customer@example.com", "ACTIVE"))
                .thenReturn(List.of(activeMembership(existingTenant, user)));

        IdentityAdministrationService service = service();

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.addMember(requestedTenantId, "customer@example.com", "customer@example.com", "Customer", "TENANT_ADMIN")
        );

        assertEquals(409, error.getStatusCode().value());
        assertEquals("This user already has active access to another tenant", error.getReason());
    }

    @Test
    void issuePlatformUserSetupLinkReturnsOneTimeExchangeUrl() {
        AppUser user = user("owner-subject", true);
        user.setEmail("owner@example.com");

        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));
        when(localCredentialAuthService.issuePasswordSetupToken("owner-subject")).thenReturn("setup-token-123");

        IdentityAdministrationService service = service();
        PlatformUserSetupLinkResponse response = service.issuePlatformUserSetupLink(user.getId());

        assertEquals(user.getId(), response.userId());
        assertEquals("owner@example.com", response.email());
        assertTrue(response.setupUrl().contains("/setup#token=setup-token-123"));
        assertTrue(response.setupUrl().contains("email=owner%40example.com"));
    }

    @Test
    void listPlatformUsersIncludesActivationState() {
        AppUser user = user("owner-subject", true);
        user.setEmail("owner@example.com");
        user.setPasswordSetAt(Instant.parse("2026-07-11T08:00:00Z"));
        user.setPasswordSetupTokenHash("token-hash");
        user.setPasswordSetupTokenExpiresAt(Instant.now().plusSeconds(3600));
        AuditEvent issued = new AuditEvent();
        issued.setAction("platform.user.setup_issued");
        issued.setTargetType("app_user");
        issued.setTargetId(user.getId().toString());
        AuditEvent completed = new AuditEvent();
        completed.setAction("platform.user.setup_completed");
        completed.setTargetType("app_user");
        completed.setTargetId(user.getId().toString());

        when(userRepository.findAll()).thenReturn(List.of(user));
        when(auditEventRepository.findByTargetTypeAndTargetIdInAndActionInOrderByOccurredAtDesc(
                "app_user",
                List.of(user.getId().toString()),
                List.of("platform.user.setup_issued", "platform.user.setup_completed")
        )).thenReturn(List.of(issued, completed));
        when(appUserGlobalRoleService.rolesByUserIds(List.of(user.getId()))).thenReturn(java.util.Map.of(user.getId(), java.util.Set.of("PLATFORM_OWNER")));

        IdentityAdministrationService service = service();
        PlatformUserResponse response = service.listPlatformUsers().get(0);

        assertTrue(response.passwordSet());
        assertTrue(response.setupPending());
        assertEquals(user.getPasswordSetAt(), response.passwordSetAt());
        assertEquals(issued.getOccurredAt(), response.lastSetupIssuedAt());
        assertEquals(completed.getOccurredAt(), response.lastSetupCompletedAt());
    }

    @Test
    void listPlatformUsersIncludesStoredOwnersWithCompatibilityFlagUnset() {
        AppUser storedOwner = user("stored-owner@example.com", false);
        AppUser compatibilityOwner = user("compatibility-owner@example.com", true);
        AppUser ordinaryUser = user("ordinary@example.com", false);
        List<AppUser> allUsers = List.of(storedOwner, compatibilityOwner, ordinaryUser);
        when(userRepository.findAll()).thenReturn(allUsers);
        when(appUserGlobalRoleService.rolesByUserIds(allUsers.stream().map(AppUser::getId).toList()))
                .thenReturn(Map.of(storedOwner.getId(), Set.of("PLATFORM_OWNER"),
                        compatibilityOwner.getId(), Set.of("PLATFORM_OWNER"),
                        ordinaryUser.getId(), Set.of("SECURITY_ANALYST")));

        List<PlatformUserResponse> response = service().listPlatformUsers();

        assertEquals(Set.of(storedOwner.getId(), compatibilityOwner.getId()),
                response.stream().map(PlatformUserResponse::userId).collect(java.util.stream.Collectors.toSet()));
        assertEquals(List.of("PLATFORM_OWNER"), response.stream()
                .filter(user -> storedOwner.getId().equals(user.userId())).findFirst().orElseThrow().globalRoles());
        assertFalse(storedOwner.isPlatformOwner());
    }

    @Test
    void storedOwnerCanReceiveSetupLinkWithoutCompatibilityFlagMutation() {
        AppUser storedOwner = user("stored-owner@example.com", false);
        when(userRepository.findById(storedOwner.getId())).thenReturn(Optional.of(storedOwner));
        when(appUserGlobalRoleService.rolesForUser(storedOwner.getId())).thenReturn(Set.of("PLATFORM_OWNER"));
        when(localCredentialAuthService.issuePasswordSetupToken(storedOwner.getExternalSubject()))
                .thenReturn("stored-owner-setup-token");

        PlatformUserSetupLinkResponse response = service().issuePlatformUserSetupLink(storedOwner.getId());

        assertEquals(storedOwner.getId(), response.userId());
        assertTrue(response.setupUrl().contains("/setup#token=stored-owner-setup-token"));
        assertFalse(storedOwner.isPlatformOwner());
    }

    @Test
    void storedOwnerCannotBeProvisionedAsOrdinaryTenantOwner() {
        AppUser storedOwner = user("stored-owner@example.com", false);
        when(userRepository.findByExternalSubject(storedOwner.getExternalSubject())).thenReturn(Optional.of(storedOwner));
        when(appUserGlobalRoleService.rolesForUser(storedOwner.getId())).thenReturn(Set.of("PLATFORM_OWNER"));

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service().assertOwnerCredentialProvisioningAllowed(storedOwner.getEmail()));

        assertEquals(409, error.getStatusCode().value());
        assertEquals("Platform-owner identities cannot be assigned as tenant owners", error.getReason());
        assertFalse(storedOwner.isPlatformOwner());
        verifyNoInteractions(membershipRepository);
    }

    @Test
    void storedOwnerCannotBeAddedThroughOrdinaryTenantMembershipPath() {
        AppUser storedOwner = user("stored-owner@example.com", false);
        when(appUserGlobalRoleService.rolesForUser(storedOwner.getId())).thenReturn(Set.of("PLATFORM_OWNER"));

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> service().assertEligibleForTenantMembership(storedOwner, UUID.randomUUID()));

        assertEquals(409, error.getStatusCode().value());
        assertEquals("Platform-owner identities cannot be added to tenant memberships", error.getReason());
        assertFalse(storedOwner.isPlatformOwner());
        verifyNoInteractions(membershipRepository);
    }

    private IdentityAdministrationService service() {
        return new IdentityAdministrationService(
                userRepository,
                tenantRepository,
                membershipRepository,
                tenantUserInviteRepository,
                serviceAccountRepository,
                auditEventRepository,
                tenantQuotaService,
                tenantSchemaExecutionService,
                appUserGlobalRoleService,
                localCredentialAuthService,
                "http://localhost:5173"
        );
    }

    private Tenant tenant(UUID id, String name) {
        Tenant tenant = new Tenant();
        tenant.setId(id);
        tenant.setName(name);
        tenant.setStatus("ACTIVE");
        return tenant;
    }

    private AppUser user(String subject, boolean platformOwner) {
        AppUser user = new AppUser();
        user.setId(UUID.randomUUID());
        user.setExternalSubject(subject);
        user.setEmail(subject);
        user.setPlatformOwner(platformOwner);
        return user;
    }

    private TenantMembership activeMembership(Tenant tenant, AppUser user) {
        TenantMembership membership = new TenantMembership();
        membership.setTenant(tenant);
        membership.setUser(user);
        membership.setRole("TENANT_ADMIN");
        membership.setStatus("ACTIVE");
        return membership;
    }
}
