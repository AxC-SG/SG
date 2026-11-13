package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.TenantQuotaUpdateRequest;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.AbstractPlatformTransactionManager;
import org.springframework.transaction.support.DefaultTransactionStatus;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@ExtendWith(MockitoExtension.class)
class TenantServiceTest {

    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private TenantSchemaService tenantSchemaService;

    private TenantService tenantService;
    private final RecordingTransactionManager transactions = new RecordingTransactionManager();

    @BeforeEach
    void setUp() {
        TenantContext.clear();
        tenantService = new TenantService(tenantRepository, tenantSchemaService, transactions);
    }

    @AfterEach
    void clearContext() {
        TenantContext.clear();
    }

    /** Records each transaction's definition and opens real synchronization so isActualTransactionActive() is true. */
    private static final class RecordingTransactionManager extends AbstractPlatformTransactionManager {
        private final List<TransactionDefinition> begun = new ArrayList<>();

        @Override
        protected Object doGetTransaction() {
            return new Object();
        }

        @Override
        protected void doBegin(Object transaction, TransactionDefinition definition) {
            begun.add(definition);
        }

        @Override
        protected void doCommit(DefaultTransactionStatus status) {
        }

        @Override
        protected void doRollback(DefaultTransactionStatus status) {
        }
    }

    @Test
    void updateQuotasPersistsTenantSpecificIngestionAdmissionLimits() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenantRepository.save(tenant)).thenReturn(tenant);

        Tenant updated = tenantService.updateQuotas(
                tenantId,
                new TenantQuotaUpdateRequest(15, 30, 150, 75000, 40, 120, 8, 2)
        );

        assertEquals(15, updated.getMaxConnectorCount());
        assertEquals(30, updated.getMaxServiceAccountCount());
        assertEquals(150, updated.getMaxDailySbomUploads());
        assertEquals(75000, updated.getMaxExportRows());
        assertEquals(40, updated.getMaxDailyExposureRefreshes());
        assertEquals(120, updated.getSbomRateLimitWindowSeconds());
        assertEquals(8, updated.getMaxSbomJobsPerRateLimitWindow());
        assertEquals(2, updated.getMaxActiveSbomJobs());
        verify(tenantRepository).save(tenant);
    }

    @Test
    void tenantCreationKeepsDemoDataOptionalAndRecordsExplicitOptIn() {
        when(tenantSchemaService.deriveSchemaName(org.mockito.ArgumentMatchers.anyString()))
                .thenAnswer(invocation -> "tenant_" + invocation.getArgument(0));
        when(tenantRepository.save(org.mockito.ArgumentMatchers.any(Tenant.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        Tenant withoutDemoData = tenantService.createTenant("Plain Tenant", "plain", null, null);
        Tenant withDemoData = tenantService.createTenant("Kanra", "kanra", null, null, true);

        assertEquals(false, DemoDatasetProvisioningService.isRequested(withoutDemoData));
        assertEquals("NOT_REQUESTED", DemoDatasetProvisioningService.status(withoutDemoData));
        assertEquals(true, DemoDatasetProvisioningService.isRequested(withDemoData));
        assertEquals("REQUESTED", DemoDatasetProvisioningService.status(withDemoData));
    }

    @Test
    void updateQuotasAllowsNullAdmissionOverridesToFallBackToDefaults() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenantRepository.save(tenant)).thenReturn(tenant);

        Tenant updated = tenantService.updateQuotas(
                tenantId,
                new TenantQuotaUpdateRequest(15, 30, 150, 75000, 40, null, null, null)
        );

        assertNull(updated.getSbomRateLimitWindowSeconds());
        assertNull(updated.getMaxSbomJobsPerRateLimitWindow());
        assertNull(updated.getMaxActiveSbomJobs());
    }

    @Test
    void updateQuotasRejectsNegativeValues() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> tenantService.updateQuotas(
                        tenantId,
                        new TenantQuotaUpdateRequest(15, 30, 150, 75000, 40, -1, 8, 2)
                )
        );

        assertEquals("sbomRateLimitWindowSeconds must be >= 0", ex.getMessage());
    }

    @Test
    void extendDemoExpiryReactivatesRetainedExpiredTenant() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setStatus("EXPIRED");
        tenant.setSchemaName("tenant_demo");
        tenant.setDemoSource("demo-request:test");
        tenant.setDemoExpiresAt(Instant.parse("2026-07-01T00:00:00Z"));
        tenant.setExpiredAt(Instant.parse("2026-07-01T00:01:00Z"));
        tenant.setSuspendedAt(Instant.parse("2026-07-01T00:01:00Z"));
        Instant extendedUntil = Instant.parse("2099-08-31T23:59:59Z");
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenantSchemaService.schemaExists("tenant_demo")).thenReturn(true);
        when(tenantRepository.save(tenant)).thenReturn(tenant);

        Tenant updated = tenantService.extendDemoExpiry(tenantId, extendedUntil);

        assertEquals("ACTIVE", updated.getStatus());
        assertEquals(extendedUntil, updated.getDemoExpiresAt());
        assertNull(updated.getExpiredAt());
        assertNull(updated.getSuspendedAt());
        verify(tenantRepository).save(tenant);
    }

    @Test
    void extendDemoExpiryRejectsTenantWhoseSchemaWasDeleted() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setStatus("EXPIRED");
        tenant.setSchemaName("tenant_deleted_demo");
        tenant.setDemoExpiresAt(Instant.parse("2026-07-01T00:00:00Z"));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenantSchemaService.schemaExists("tenant_deleted_demo")).thenReturn(false);

        IllegalStateException ex = assertThrows(
                IllegalStateException.class,
                () -> tenantService.extendDemoExpiry(tenantId, Instant.parse("2099-08-31T23:59:59Z"))
        );

        assertEquals("Tenant schema is not provisioned: tenant_deleted_demo", ex.getMessage());
    }

    @Test
    void restoringSuspendedExpiredDemoRequiresExtensionFirst() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setStatus("SUSPENDED");
        tenant.setDemoExpiresAt(Instant.parse("2020-01-01T00:00:00Z"));
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

        IllegalArgumentException ex = assertThrows(
                IllegalArgumentException.class,
                () -> tenantService.updateStatus(tenantId, "ACTIVE")
        );

        assertEquals("Extend the demo expiration before restoring tenant access", ex.getMessage());
    }

    @Test
    void updateStatusTemporarilyBlocksTenantWithoutDeletingIt() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setStatus("ACTIVE");
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));
        when(tenantRepository.save(tenant)).thenReturn(tenant);

        Tenant updated = tenantService.updateStatus(tenantId, "SUSPENDED");

        assertEquals("SUSPENDED", updated.getStatus());
        assertNull(updated.getDeletedAt());
        assertNull(updated.getPurgeStartedAt());
        verify(tenantRepository).save(tenant);
    }

    @Test
    void backgroundRoutingRejectsSuspensionAndUnresolvedCustomerPlacement() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setClassification("CUSTOMER");
        when(tenantRepository.findById(tenantId)).thenReturn(Optional.of(tenant));

        tenant.setSchemaName("tenant_customer");
        tenant.setStatus("SUSPENDED");
        assertThrows(ResponseStatusException.class, () -> tenantService.resolveActiveTenantForBackgroundWork(tenantId));

        tenant.setStatus("ACTIVE");
        tenant.setSchemaName(null);
        assertThrows(ResponseStatusException.class, () -> tenantService.resolveActiveTenantForBackgroundWork(tenantId));

        tenant.setSchemaName(TenantService.DEFAULT_TENANT_SCHEMA);
        assertThrows(ResponseStatusException.class, () -> tenantService.resolveActiveTenantForBackgroundWork(tenantId));

        tenant.setSchemaName("tenant_customer");
        assertSame(tenant, tenantService.resolveActiveTenantForBackgroundWork(tenantId));
    }

    @Test
    void listActiveTenantsFiltersInactiveAndDeletedTenants() {
        Tenant active = new Tenant();
        active.setName("Active");
        active.setStatus("ACTIVE");
        Tenant suspended = new Tenant();
        suspended.setName("Suspended");
        suspended.setStatus("SUSPENDED");
        Tenant expired = new Tenant();
        expired.setName("Expired");
        expired.setStatus("ACTIVE");
        expired.setExpiredAt(Instant.now());
        Tenant purging = new Tenant();
        purging.setName("Purging");
        purging.setStatus("ACTIVE");
        purging.setPurgeStartedAt(Instant.now());
        Tenant deleted = new Tenant();
        deleted.setName("Deleted");
        deleted.setStatus("ACTIVE");
        deleted.setDeletedAt(Instant.now());
        when(tenantRepository.findAllByOrderByCreatedAtAsc())
                .thenReturn(List.of(active, suspended, expired, purging, deleted));

        List<Tenant> tenants = tenantService.listActiveTenants();

        assertEquals(List.of(active), tenants);
    }

    @Test
    void listActiveTenantsOpensItsReadOnlyTransactionInsidePlatformScope() {
        UUID callerTenant = UUID.randomUUID();
        TenantContext.setCurrentTenantId(callerTenant);
        TenantContext.setCurrentSchemaName("tenant_customer");
        List<Boolean> platformAtRead = new ArrayList<>();
        List<Boolean> transactionAtRead = new ArrayList<>();
        when(tenantRepository.findAllByOrderByCreatedAtAsc()).thenAnswer(invocation -> {
            platformAtRead.add(TenantContext.isPlatformContext());
            transactionAtRead.add(TransactionSynchronizationManager.isActualTransactionActive());
            return List.of();
        });

        tenantService.listActiveTenants();

        assertEquals(List.of(true), platformAtRead);
        assertEquals(List.of(true), transactionAtRead);
        assertEquals(1, transactions.begun.size());
        assertTrue(transactions.begun.get(0).isReadOnly());
        assertFalse(TenantContext.isPlatformContext());
        assertEquals(callerTenant, TenantContext.getCurrentTenantId());
        assertEquals("tenant_customer", TenantContext.getCurrentSchemaName());
    }

    @Test
    void listActiveTenantsRestoresCallerContextWhenTheReadFails() {
        UUID callerTenant = UUID.randomUUID();
        TenantContext.setCurrentTenantId(callerTenant);
        when(tenantRepository.findAllByOrderByCreatedAtAsc()).thenThrow(new IllegalStateException("database unavailable"));

        assertThrows(IllegalStateException.class, () -> tenantService.listActiveTenants());

        assertFalse(TenantContext.isPlatformContext());
        assertEquals(callerTenant, TenantContext.getCurrentTenantId());
    }

    @Test
    void listActiveTenantsJoinsACallerTransactionOpenedInPlatformScope() {
        Tenant active = new Tenant();
        active.setStatus("ACTIVE");
        when(tenantRepository.findAllByOrderByCreatedAtAsc()).thenReturn(List.of(active));

        List<Tenant> tenants = TenantContext.runAsPlatform(() ->
                new TransactionTemplate(transactions).execute(status -> tenantService.listActiveTenants()));

        assertEquals(List.of(active), tenants);
        assertEquals(1, transactions.begun.size());
    }

    @Test
    void listActiveTenantsRejectsACallerTransactionOutsidePlatformScope() {
        TenantContext.setCurrentTenantId(UUID.randomUUID());

        IllegalStateException rejected = assertThrows(IllegalStateException.class, () ->
                new TransactionTemplate(transactions).execute(status -> tenantService.listActiveTenants()));

        assertTrue(rejected.getMessage().contains("platform scope"));
        verifyNoInteractions(tenantRepository);
    }

    @Test
    void resolvesOnlyReservedInternalSchema() {
        Tenant internal=new Tenant();internal.setClassification("INTERNAL");internal.setSchemaName("tenant_default");
        when(tenantRepository.findBySchemaName("tenant_default")).thenReturn(Optional.of(internal));
        assertSame(internal,tenantService.getDefaultTenant());
    }
    @Test
    void neverFallsBackToCustomerTenant() {
        when(tenantRepository.findBySchemaName("tenant_default")).thenReturn(Optional.empty());
        assertThrows(ResponseStatusException.class,tenantService::getDefaultTenant);
        org.mockito.Mockito.verify(tenantRepository,org.mockito.Mockito.never()).findAllByOrderByCreatedAtAsc();
    }
    @Test
    void rejectsMisclassifiedReservedSchema() {
        when(tenantRepository.findBySchemaName("tenant_default")).thenReturn(Optional.of(new Tenant()));
        assertThrows(ResponseStatusException.class,tenantService::getDefaultTenant);
    }
}
