package com.prototype.vulnwatch.service;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TenantBootstrapServiceTest {

    @Mock
    private TenantRepository tenantRepository;
    @Mock
    private TenantSchemaService tenantSchemaService;

    private TenantBootstrapService service;

    @BeforeEach
    void setUp() {
        service = new TenantBootstrapService(tenantRepository, tenantSchemaService);
    }

    @Test
    void startupRequiresExplicitReservedIdentityRatherThanRepairingCustomerMappings() {
        when(tenantRepository.findBySchemaName("tenant_default")).thenReturn(Optional.empty());
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,service::ensureBootstrapTenant);
        org.mockito.Mockito.verify(tenantRepository,org.mockito.Mockito.never()).save(any());
    }

    @Test
    void readinessFailureDoesNotEscapeStartupOrPreventLaterTenants() {
        Tenant defaultTenant = tenant("Default Workspace", "default-workspace", "tenant_default", "ACTIVE");
        defaultTenant.setClassification("INTERNAL");
        Tenant broken = tenant("Broken", "broken", "tenant_broken", "ACTIVE");
        Tenant healthy = tenant("Healthy", "healthy", "tenant_healthy", "ACTIVE");
        when(tenantSchemaService.normalizeSchemaName(anyString())).thenAnswer(invocation -> invocation.getArgument(0));
        when(tenantRepository.findBySchemaName("tenant_default"))
                .thenReturn(Optional.of(defaultTenant));
        when(tenantRepository.findAll()).thenReturn(List.of(defaultTenant, broken, healthy));
        org.mockito.Mockito.doAnswer(invocation -> {
            if ("tenant_broken".equals(invocation.getArgument(0))) {
                throw new IllegalStateException("drifted");
            }
            return null;
        }).when(tenantSchemaService).assertSchemaReady(anyString());

        service.ensureBootstrapTenant();

        verify(tenantSchemaService).assertSchemaReady("tenant_healthy");
    }

    private Tenant tenant(String name, String slug, String schema, String status) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName(name);
        tenant.setSlug(slug);
        tenant.setSchemaName(schema);
        tenant.setStatus(status);
        return tenant;
    }
}
