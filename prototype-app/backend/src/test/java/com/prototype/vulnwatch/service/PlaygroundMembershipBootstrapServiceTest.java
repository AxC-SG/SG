package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.config.PlaygroundMembershipProperties;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class PlaygroundMembershipBootstrapServiceTest {

    @AfterEach
    void tearDown() {
        TenantContext.clear();
    }

    @Test
    void revokesAndAuditsAutomaticOwnerMembershipInsideTenantScope() {
        PlaygroundMembershipProperties properties = new PlaygroundMembershipProperties();
        properties.setEnabled(true);
        properties.setSubjects(List.of("owner-subject"));

        Tenant playground = new Tenant();
        playground.setId(UUID.randomUUID());
        playground.setName("Default Workspace");
        playground.setSlug(TenantAccessResolutionService.PLAYGROUND_SLUG);
        playground.setSchemaName("tenant_default");
        playground.setStatus("ACTIVE");

        AppUser owner = new AppUser();
        owner.setId(UUID.randomUUID());
        owner.setExternalSubject("owner-subject");
        owner.setStatus("ACTIVE");

        TenantRepository tenantRepository = mock(TenantRepository.class);
        AppUserRepository userRepository = mock(AppUserRepository.class);
        TenantMembershipRepository membershipRepository = mock(TenantMembershipRepository.class);
        AppUserGlobalRoleService globalRoleService = mock(AppUserGlobalRoleService.class);
        AuditEventService auditEventService = mock(AuditEventService.class);
        TenantWorkRunner tenantWorkRunner = mock(TenantWorkRunner.class);

        TenantMembership automatic=new TenantMembership();automatic.setId(UUID.randomUUID());automatic.setTenant(playground);
        automatic.setUser(owner);automatic.setRole("TENANT_ADMIN");automatic.setStatus("ACTIVE");automatic.setProvenance("PLAYGROUND_BOOTSTRAP");
        when(membershipRepository.save(any(TenantMembership.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(membershipRepository.findByProvenance(TenantAccessResolutionService.PLAYGROUND_PROVENANCE)).thenReturn(List.of(automatic));

        doAnswer(invocation -> {
            Tenant tenant = invocation.getArgument(0);
            Runnable work = invocation.getArgument(1);
            TenantContext.Snapshot previous = TenantContext.capture();
            try {
                TenantContext.setCurrentTenantId(tenant.getId());
                TenantContext.setCurrentSchemaName(tenant.getSchemaName());
                work.run();
                return null;
            } finally {
                TenantContext.restore(previous);
            }
        }).when(tenantWorkRunner).runScoped(any(Tenant.class), any(Runnable.class));

        AtomicReference<UUID> auditTenantContext = new AtomicReference<>();
        doAnswer(invocation -> {
            auditTenantContext.set(TenantContext.getCurrentTenantId());
            return null;
        }).when(auditEventService).recordExplicitActor(
                any(), any(), any(), any(), any(), any(), any(), any());

        PlaygroundMembershipBootstrapService service = new PlaygroundMembershipBootstrapService(
                properties,
                tenantRepository,
                userRepository,
                membershipRepository,
                globalRoleService,
                auditEventService,
                tenantWorkRunner);

        service.reconcile();

        assertThat(automatic.getStatus()).isEqualTo("SUSPENDED");
        assertThat(auditTenantContext.get()).isEqualTo(playground.getId());
        verify(tenantWorkRunner).runScoped(any(Tenant.class), any(Runnable.class));
        assertThat(TenantContext.getCurrentTenantId()).isNull();
    }
}
