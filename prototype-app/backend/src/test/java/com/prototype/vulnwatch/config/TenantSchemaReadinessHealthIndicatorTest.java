package com.prototype.vulnwatch.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.migration.PackagedMigrationCatalog;
import com.prototype.vulnwatch.service.TenantSchemaStatusService;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.health.Status;

class TenantSchemaReadinessHealthIndicatorTest {

    @Test
    void tenantIncompatibilityIsVisibleWithoutDisablingHealthyTenants() {
        TenantSchemaStatusService service = org.mockito.Mockito.mock(TenantSchemaStatusService.class);
        PackagedMigrationCatalog catalog = new PackagedMigrationCatalog();
        when(service.readinessFailures(catalog.tenantTarget())).thenReturn(1L);

        var health = new TenantSchemaReadinessHealthIndicator(service, catalog).health();

        assertEquals(Status.UP, health.getStatus());
        assertEquals(1L,health.getDetails().get("unreadyTenantCount"));
        assertEquals(catalog.tenantTarget(), health.getDetails().get("packagedTenantTarget"));
    }

    @Test
    void controlPlaneFailureMakesReadinessDown() {
        TenantSchemaStatusService service = org.mockito.Mockito.mock(TenantSchemaStatusService.class);
        PackagedMigrationCatalog catalog = new PackagedMigrationCatalog();
        when(service.readinessFailures(catalog.tenantTarget())).thenThrow(new IllegalStateException("unavailable"));

        assertEquals(Status.DOWN, new TenantSchemaReadinessHealthIndicator(service, catalog).health().getStatus());
    }
}
