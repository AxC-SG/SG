package com.prototype.vulnwatch.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class DemoTenantPurgeServiceTest {

    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private AppUserRepository appUserRepository;
    @Mock
    private JdbcTemplate resetJdbcTemplate;
    @Mock
    private AuditEventService auditEventService;
    @Mock
    private TenantLifecycleGuardService tenantLifecycleGuardService;
    @Mock
    private TenantSchemaService tenantSchemaService;
    @Mock
    private DemoTenantPurgePlanner demoTenantPurgePlanner;

    private DemoTenantPurgeService service;

    @BeforeEach
    void setUp() {
        service = new DemoTenantPurgeService(
                tenantRepository,
                appUserRepository,
                resetJdbcTemplate,
                auditEventService,
                tenantLifecycleGuardService,
                tenantSchemaService,
                demoTenantPurgePlanner
        );
    }

    @Test
    void processExpiredTenantBlocksAccessButRetainsTenantData() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Demo");
        tenant.setSlug("demo");
        tenant.setSchemaName("tenant_demo");
        tenant.setPlanCode("demo");
        tenant.setStatus("ACTIVE");
        tenant.setDemoExpiresAt(Instant.parse("2026-05-20T00:00:00Z"));

        Instant now = Instant.parse("2026-05-21T00:00:00Z");
        when(tenantRepository.findByIdForUpdate(tenant.getId())).thenReturn(Optional.of(tenant));
        when(demoTenantPurgePlanner.isEligibleForAutomaticPurge(eq(tenant), any())).thenReturn(true);

        service.processExpiredTenant(tenant.getId(), now);
        service.processExpiredTenant(tenant.getId(), now.plusSeconds(3600));

        assertEquals("EXPIRED", tenant.getStatus());
        assertEquals(now, tenant.getExpiredAt());
        assertEquals(now, tenant.getSuspendedAt());
        verify(tenantRepository).save(tenant);
        verifyNoInteractions(tenantSchemaService);
        verifyNoInteractions(resetJdbcTemplate, appUserRepository);
        verify(auditEventService).record("demo.tenant.expired", "tenant", tenant.getId().toString(), null);
    }

    @Test
    void processExpiredTenantSkipsSchemaDropForNonDemoTenant() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);

        when(tenantRepository.findByIdForUpdate(tenantId)).thenReturn(Optional.of(tenant));
        when(demoTenantPurgePlanner.isEligibleForAutomaticPurge(eq(tenant), any())).thenReturn(false);

        service.processExpiredTenant(tenantId, Instant.now());

        verify(tenantSchemaService, never()).dropTenantSchema(any(String.class));
    }

    @Test
    void manualDeletionIsContainedBeforeReadingOrMutatingAnyTenant() {
        ResponseStatusException ex = assertThrows(ResponseStatusException.class,
                () -> service.deleteTenant(UUID.randomUUID(), Instant.now()));

        assertEquals(503, ex.getStatusCode().value());
        verifyNoInteractions(tenantRepository, appUserRepository, resetJdbcTemplate,
                auditEventService, tenantSchemaService, demoTenantPurgePlanner);
    }
}
