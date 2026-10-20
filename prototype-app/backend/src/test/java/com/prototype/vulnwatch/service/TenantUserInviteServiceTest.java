package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantUserInvite;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.TenantInviteValidationResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class TenantUserInviteServiceTest {

    @Mock
    private IdentityAdministrationService identityAdministrationService;
    @Mock
    private TenantInviteEmailService tenantInviteEmailService;
    @Mock
    private LocalCredentialAuthService localCredentialAuthService;
    @Mock
    private AppUserRepository appUserRepository;
    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private AuditEventService auditEventService;
    @Mock
    private TenantWorkRunner tenantWorkRunner;

    @Test
    void createInviteRejectsUserWithAnotherActiveTenantMembership() {
        UUID requestedTenantId = UUID.randomUUID();
        when(tenantRepository.findById(requestedTenantId)).thenReturn(Optional.of(tenant(requestedTenantId, "Requested")));
        doThrow(new ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,
                "This user already has active access to another tenant"))
                .when(identityAdministrationService)
                .loadOrCreateEligibleLockedUser(
                        eq(requestedTenantId),
                        eq("customer@example.com"),
                        eq("customer@example.com"),
                        eq("Customer"));

        TenantUserInviteService service = new TenantUserInviteService(
                identityAdministrationService,
                tenantInviteEmailService,
                localCredentialAuthService,
                appUserRepository,
                tenantRepository,
                auditEventService,
                tenantWorkRunner
        );

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.createInvite(requestedTenantId, "customer@example.com", "Customer", "TENANT_ADMIN", "inviter@example.com")
        );

        assertEquals(409, error.getStatusCode().value());
        assertEquals("This user already has active access to another tenant", error.getReason());
    }

    @Test
    void acceptInviteRecordsAcceptedUserAsExplicitAuditActor() {
        UUID tenantId = UUID.randomUUID();
        UUID inviteId = UUID.randomUUID();
        UUID membershipId = UUID.randomUUID();
        Tenant tenant = tenant(tenantId, "Requested");
        TenantUserInvite invite = new TenantUserInvite();
        invite.setId(inviteId);
        invite.setToken("invite-token");
        invite.setTenant(tenant);
        invite.setExternalSubject("customer@example.com");
        invite.setEmail("customer@example.com");
        invite.setDisplayName("Customer");
        invite.setRole("TENANT_ADMIN");
        invite.setStatus("SENT");
        invite.setExpiresAt(Instant.now().plusSeconds(3600));
        TenantMembership membership = new TenantMembership();
        membership.setId(membershipId);
        membership.setRole("TENANT_ADMIN");

        when(identityAdministrationService.findInviteTenantId("invite-token")).thenReturn(tenantId);
        when(identityAdministrationService.findInviteByTokenForUpdate("invite-token")).thenReturn(invite);
        when(identityAdministrationService.activateInvitedMembership(
                tenantId,
                "customer@example.com",
                "customer@example.com",
                "Customer",
                "TENANT_ADMIN",
                null))
                .thenReturn(membership);
        when(identityAdministrationService.saveInvite(any(TenantUserInvite.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(localCredentialAuthService.issuePasswordSetupToken("customer@example.com")).thenReturn("setup-token");
        when(tenantWorkRunner.runScoped(
                eq(tenantId),
                org.mockito.ArgumentMatchers.<java.util.function.Supplier<TenantInviteValidationResponse>>any()))
                .thenAnswer(invocation -> invocation.getArgument(1, java.util.function.Supplier.class).get());

        TenantUserInviteService service = new TenantUserInviteService(
                identityAdministrationService,
                tenantInviteEmailService,
                localCredentialAuthService,
                appUserRepository,
                tenantRepository,
                auditEventService,
                tenantWorkRunner
        );

        service.acceptInvite("invite-token");

        verify(auditEventService).recordExplicitActor(
                eq(tenantId),
                eq("customer@example.com"),
                eq("TENANT_ADMIN"),
                eq("member.invite.accepted"),
                eq("tenant_user_invite"),
                eq(inviteId.toString()),
                eq("{\"tenantId\":\"" + tenantId + "\",\"membershipId\":\"" + membershipId + "\"}"),
                eq("SUCCESS"));
    }

    private Tenant tenant(UUID id, String name) {
        Tenant tenant = new Tenant();
        tenant.setId(id);
        tenant.setName(name);
        tenant.setStatus("ACTIVE");
        return tenant;
    }

}
