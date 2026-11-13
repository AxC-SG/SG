package com.prototype.vulnwatch.service.ownership;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantWorkRunner;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** The scheduled ownership callbacks follow the runtime role like every other background job. */
class OwnershipMaintenanceJobTest {

    private final TenantService tenants = mock(TenantService.class);
    private final OwnershipEffectiveCacheService cache = mock(OwnershipEffectiveCacheService.class);

    private OwnershipMaintenanceJob job(String role) {
        return new OwnershipMaintenanceJob(tenants, mock(TenantWorkRunner.class), mock(OwnershipClaimService.class),
                mock(OwnershipResolutionService.class), mock(InventorySubjectAdapter.class),
                mock(OwnershipAuthorityService.class), cache, BackgroundTaskExecutionPolicy.forRole(role), 500, 20);
    }

    @ParameterizedTest
    @ValueSource(strings = {"api", "schema-migrator"})
    void apiAndMigratorNodesSkipBothScheduledCallbacks(String role) {
        when(cache.enabled()).thenReturn(true);
        OwnershipMaintenanceJob job = job(role);

        job.run();
        job.reconcileCache();

        verify(tenants, never()).listActiveTenants();
    }

    @ParameterizedTest
    @ValueSource(strings = {"worker", "all"})
    void workerNodesRunBothScheduledCallbacks(String role) {
        when(cache.enabled()).thenReturn(true);
        when(tenants.listActiveTenants()).thenReturn(List.of());
        OwnershipMaintenanceJob job = job(role);

        job.run();
        job.reconcileCache();

        verify(tenants, times(2)).listActiveTenants();
    }
}
