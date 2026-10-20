package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.transaction.support.TransactionSynchronizationManager;

@ExtendWith(MockitoExtension.class)
class TenantSchemaExecutionServiceTest {

    @Mock
    private TenantService tenantService;

    @Mock
    private TenantSchemaService tenantSchemaService;

    private TenantSchemaExecutionService service;

    @BeforeEach
    void setUp() {
        TenantContext.clear();
        service = new TenantSchemaExecutionService(tenantService, tenantSchemaService);
    }

    @AfterEach
    void tearDown() {
        TransactionSynchronizationManager.setActualTransactionActive(false);
        TenantContext.clear();
    }

    @Test
    void runWithTenantEnsuresProvisionedSchemaBeforeExecutingSupplier() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setSchemaName("tenant_acme");

        when(tenantSchemaService.schemaNameForTenant(tenant)).thenReturn("tenant_acme");

        String result = service.run(tenant, () -> {
            assertThat(TenantContext.getCurrentTenantId()).isEqualTo(tenantId);
            assertThat(TenantContext.getCurrentSchemaName()).isEqualTo("tenant_acme");
            return "ok";
        });

        assertThat(result).isEqualTo("ok");
        verify(tenantSchemaService).schemaNameForTenant(tenant);
        verify(tenantSchemaService).assertSchemaReady("tenant_acme");
        verify(tenantService, never()).resolveTenantUuid(tenantId);
    }

    @Test
    void runWithTenantIdResolvesAndEnsuresSchemaBeforeExecutingSupplier() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setSchemaName("tenant_acme");

        when(tenantService.resolveTenantUuid(tenantId)).thenReturn(tenant);
        when(tenantSchemaService.schemaNameForTenant(tenant)).thenReturn("tenant_acme");

        String result = service.run(tenantId, () -> {
            assertThat(TenantContext.getCurrentTenantId()).isEqualTo(tenantId);
            assertThat(TenantContext.getCurrentSchemaName()).isEqualTo("tenant_acme");
            return "ok";
        });

        assertThat(result).isEqualTo("ok");
        verify(tenantService).resolveTenantUuid(tenantId);
        verify(tenantSchemaService).schemaNameForTenant(tenant);
        verify(tenantSchemaService).assertSchemaReady("tenant_acme");
    }

    @Test
    void runRestoresOuterPlatformContext() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setSchemaName("tenant_acme");

        when(tenantSchemaService.schemaNameForTenant(tenant)).thenReturn("tenant_acme");

        TenantContext.runAsPlatform(() -> {
            assertThat(TenantContext.isPlatformContext()).isTrue();
            service.run(tenant, () -> {
                assertThat(TenantContext.getCurrentTenantId()).isEqualTo(tenantId);
                assertThat(TenantContext.isPlatformContext()).isFalse();
            });
            assertThat(TenantContext.getCurrentTenantId()).isNull();
            assertThat(TenantContext.getCurrentSchemaName()).isNull();
            assertThat(TenantContext.isPlatformContext()).isTrue();
        });

        assertThat(TenantContext.isPlatformContext()).isFalse();
    }

    @Test
    void guardAllowsSameTenantInsideActiveTransaction() {
        UUID tenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(tenantId);
        tenant.setSchemaName("tenant_acme");

        when(tenantSchemaService.schemaNameForTenant(tenant)).thenReturn("tenant_acme");

        TenantContext.setCurrentTenantId(tenantId);
        TenantContext.setCurrentSchemaName("tenant_acme");
        TransactionSynchronizationManager.setActualTransactionActive(true);

        String result = service.run(tenant, () -> "ok");

        assertThat(result).isEqualTo("ok");
    }

    @Test
    void guardFailsDifferentTenantInsideActiveTransactionByDefault() {
        UUID currentTenantId = UUID.randomUUID();
        UUID requestedTenantId = UUID.randomUUID();
        Tenant tenant = new Tenant();
        tenant.setId(requestedTenantId);
        tenant.setSchemaName("tenant_beta");

        when(tenantSchemaService.schemaNameForTenant(tenant)).thenReturn("tenant_beta");

        TenantContext.setCurrentTenantId(currentTenantId);
        TenantContext.setCurrentSchemaName("tenant_acme");
        TransactionSynchronizationManager.setActualTransactionActive(true);

        assertThatThrownBy(() -> service.run(tenant, () -> "should not run"))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Tenant context switch requested inside an active transaction");
    }
    @ParameterizedTest
    @ValueSource(strings = {"WARN", "unknown", ""})
    void invalidOrPermissiveGuardConfigurationFailsExplicitly(String mode) {
        assertThatThrownBy(() -> new TenantSchemaExecutionService(tenantService, tenantSchemaService, mode))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("must be FAIL");
    }

    @Test
    void exceptionRestoresPreviousTenantContext() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setSchemaName("tenant_beta");
        when(tenantSchemaService.schemaNameForTenant(tenant)).thenReturn("tenant_beta");
        TenantContext.runAsPlatform(() -> {
            assertThatThrownBy(() -> service.run(tenant, () -> { throw new IllegalStateException("work failed"); }))
                    .hasMessage("work failed");
            assertThat(TenantContext.isPlatformContext()).isTrue();
            assertThat(TenantContext.getCurrentTenantId()).isNull();
        });
    }

}
