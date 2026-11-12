package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantWorkRunner;
import java.util.List;
import java.util.function.IntSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Keeps stored direct results current without user action (plan §12.2): expires past-expiry claims and drains the
 * re-resolution queue. Each batch is its own tenant-scoped transaction; a run does a bounded number of batches per
 * tenant so one busy tenant cannot starve the rest. One tenant's failure is logged and does not stop the others.
 * Like the other background jobs, the scheduled entry points do nothing on {@code api} and {@code schema-migrator}
 * nodes ({@link BackgroundTaskExecutionPolicy}).
 */
@Component
public class OwnershipMaintenanceJob {

    private static final Logger LOG = LoggerFactory.getLogger(OwnershipMaintenanceJob.class);

    private final TenantService tenants;
    private final TenantWorkRunner runner;
    private final OwnershipClaimService claims;
    private final OwnershipResolutionService resolution;
    private final InventorySubjectAdapter inventory;
    private final OwnershipAuthorityService authority;
    private final OwnershipEffectiveCacheService cache;
    private final BackgroundTaskExecutionPolicy backgroundTasks;
    private final int batchSize;
    private final int maxBatchesPerTenant;

    public OwnershipMaintenanceJob(TenantService tenants, TenantWorkRunner runner, OwnershipClaimService claims,
                                   OwnershipResolutionService resolution, InventorySubjectAdapter inventory,
                                   OwnershipAuthorityService authority, OwnershipEffectiveCacheService cache,
                                   BackgroundTaskExecutionPolicy backgroundTasks,
                                   @Value("${app.ownership.maintenance.batch-size:500}") int batchSize,
                                   @Value("${app.ownership.maintenance.max-batches-per-tenant:20}") int maxBatchesPerTenant) {
        this.tenants = tenants;
        this.runner = runner;
        this.claims = claims;
        this.resolution = resolution;
        this.inventory = inventory;
        this.authority = authority;
        this.cache = cache;
        this.backgroundTasks = backgroundTasks;
        this.batchSize = batchSize;
        this.maxBatchesPerTenant = maxBatchesPerTenant;
    }

    @Scheduled(zone = "UTC", cron = "${app.ownership.maintenance.cron:0 * * * * *}")
    public void run() {
        if (!backgroundTasks.allowsBackgroundTask("ownership.maintenance")) return;
        List<Tenant> active = TenantContext.runAsPlatform(tenants::listActiveTenants);
        for (Tenant tenant : active) {
            try {
                runForTenant(tenant);
            } catch (RuntimeException ex) {
                LOG.warn("Ownership maintenance failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
            }
        }
    }

    /**
     * One tenant's pass: expiry first, so queued subjects resolve against current claim states; then, once the CORE
     * domain has left LEGACY, the populate step links unlinked assets and findings to subjects (plan §15.2); then, when
     * the effective cache is on, it expands queued changes into invalidations and refreshes invalidated rows.
     */
    public void runForTenant(Tenant tenant) {
        drain(tenant, () -> claims.expireDue(batchSize));
        drain(tenant, () -> resolution.drainQueue(batchSize, "system"));
        boolean populating = runner.runScoped(tenant,
                () -> authority.stateFor(OwnershipAuthorityService.Domain.CORE) != OwnershipAuthorityService.State.LEGACY);
        if (populating) drain(tenant, () -> inventory.linkBatch(batchSize));
        if (cache.enabled()) {
            drain(tenant, () -> cache.expandBatch(cacheBatchSize()), cacheBatchSize());
            drain(tenant, () -> cache.refreshBatch(cacheBatchSize()), cacheBatchSize());
        }
    }

    /**
     * Hourly reconciliation (plan §12.4): queues active subjects that have no cache row, e.g. subjects that existed
     * before the cache was enabled. The per-minute pass then builds their rows.
     */
    @Scheduled(zone = "UTC", cron = "${app.ownership.effective-cache.reconcile-cron:0 7 * * * *}")
    public void reconcileCache() {
        if (!cache.enabled()) return;
        if (!backgroundTasks.allowsBackgroundTask("ownership.effective-cache-reconcile")) return;
        for (Tenant tenant : TenantContext.runAsPlatform(tenants::listActiveTenants)) {
            try {
                drain(tenant, () -> cache.reconcileMissing(cacheBatchSize()), cacheBatchSize());
            } catch (RuntimeException ex) {
                LOG.warn("Ownership cache reconciliation failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
            }
        }
    }

    /** Cache batches are cheap single statements; plan §7.5 caps each at 10,000 subjects. */
    private int cacheBatchSize() {
        return Math.min(10_000, batchSize * 10);
    }

    private void drain(Tenant tenant, IntSupplier batch) {
        drain(tenant, batch, batchSize);
    }

    private void drain(Tenant tenant, IntSupplier batch, int fullBatch) {
        for (int i = 0; i < maxBatchesPerTenant; i++) {
            Integer done = runner.runScoped(tenant, batch::getAsInt);
            if (done == null || done < fullBatch) return;
        }
    }
}
