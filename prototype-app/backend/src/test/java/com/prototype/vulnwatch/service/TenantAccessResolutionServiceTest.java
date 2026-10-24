package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantSupportGrant;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class TenantAccessResolutionServiceTest {
    @Mock TenantRepository tenantRepository;
    @Mock TenantMembershipRepository membershipRepository;
    @Mock TenantSupportGrantService supportGrantService;
    @Mock TenantLifecycleGuardService lifecycleGuardService;

    private TenantAccessResolutionService service;

    @BeforeEach
    void setUp() {
        service = new TenantAccessResolutionService(
                tenantRepository, membershipRepository, supportGrantService, lifecycleGuardService);
    }

    @Test
    void automaticOwnerPlaygroundMembershipDoesNotAuthorizeTenantAccess() {
        Tenant tenant = tenant("default-workspace");
        TenantMembership membership = membership(tenant, "TENANT_ADMIN", "PLAYGROUND_BOOTSTRAP");
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "owner@example.com", tenant.getId(), "ACTIVE")).thenReturn(Optional.of(membership));

        assertThrows(ResponseStatusException.class,() -> service.resolve("owner@example.com",tenant.getId()));
    }

    @Test
    void activeOrdinaryMembershipResolvesAsTenantMembership() {
        Tenant tenant = tenant("customer-a");
        TenantMembership membership = membership(tenant, "SECURITY_ANALYST", "TENANT_INVITE");
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "owner@example.com", tenant.getId(), "ACTIVE")).thenReturn(Optional.of(membership));

        assertEquals(TenantAccessMode.TENANT_MEMBERSHIP,
                service.resolve("owner@example.com", tenant.getId()).mode());
    }

    @Test
    void acceptedSupportGrantResolvesReadAndWriteModesWithReferenceAndExpiry() {
        Tenant tenant = tenant("customer-a");
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "owner@example.com", tenant.getId(), "ACTIVE")).thenReturn(Optional.empty());
        TenantSupportGrant grant = grant(tenant, "WRITE_ENABLED");
        when(supportGrantService.findActiveGrant("owner@example.com", tenant.getId())).thenReturn(Optional.of(grant));

        TenantAccessResolution result = service.resolve("owner@example.com", tenant.getId());

        assertEquals(TenantAccessMode.SUPPORT_WRITE_ENABLED, result.mode());
        assertEquals(grant.getId(), result.referenceId());
        assertEquals(grant.getExpiresAt(), result.expiresAt());

        grant.setAccessMode("READ_ONLY");
        assertEquals(TenantAccessMode.SUPPORT_READ_ONLY,
                service.resolve("owner@example.com", tenant.getId()).mode());
    }

    @Test
    void missingAccessAndMismatchedTokenReferenceAreRejected() {
        Tenant tenant = tenant("customer-a");
        when(tenantRepository.findById(tenant.getId())).thenReturn(Optional.of(tenant));
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "owner@example.com", tenant.getId(), "ACTIVE")).thenReturn(Optional.empty());
        when(supportGrantService.findActiveGrant("owner@example.com", tenant.getId())).thenReturn(Optional.empty());
        assertEquals(403, assertThrows(ResponseStatusException.class,
                () -> service.resolve("owner@example.com", tenant.getId())).getStatusCode().value());

        TenantMembership membership = membership(tenant, "TENANT_ADMIN", "MANUAL");
        when(membershipRepository.findFirstByUserExternalSubjectAndTenantIdAndStatus(
                "owner@example.com", tenant.getId(), "ACTIVE")).thenReturn(Optional.of(membership));
        assertEquals(403, assertThrows(ResponseStatusException.class,
                () -> service.revalidate("owner@example.com", tenant.getId(),
                        TenantAccessMode.TENANT_MEMBERSHIP, UUID.randomUUID())).getStatusCode().value());
    }

    @Test
    void unknownOrDeletedTenantIsRejectedWithoutRevealingExistence() {
        UUID tenantId = UUID.randomUUID();
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.empty());

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.resolve("owner@example.com", tenantId));

        assertEquals(403, error.getStatusCode().value());
    }

    private Tenant tenant(String slug) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(slug);
        tenant.setSlug(slug);
        tenant.setStatus("ACTIVE");
        return tenant;
    }

    private TenantMembership membership(Tenant tenant, String role, String provenance) {
        AppUser user = new AppUser();
        user.setExternalSubject("owner@example.com");
        TenantMembership membership = new TenantMembership();
        membership.setId(UUID.randomUUID());
        membership.setTenant(tenant);
        membership.setUser(user);
        membership.setStatus("ACTIVE");
        membership.setRole(role);
        membership.setProvenance(provenance);
        return membership;
    }

    private TenantSupportGrant grant(Tenant tenant, String mode) {
        TenantSupportGrant grant = new TenantSupportGrant();
        grant.setId(UUID.randomUUID());
        grant.setTenant(tenant);
        grant.setAccessMode(mode);
        grant.setStatus("ACCEPTED");
        grant.setExpiresAt(Instant.now().plusSeconds(3600));
        return grant;
    }
}
