package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Periodically computes the corrected-vs-legacy entitlement decision for every active tenant and
 * every known entitlement key, so SHADOW coverage does not depend on a feature actually being
 * exercised. Runs on a single instance (guarded by the background-task policy) and emits at most one
 * structured log line per tenant/key per run, which keeps mismatch logging bounded — per-request
 * evaluation only increments the counter and never logs.
 */
@Service
public class EntitlementShadowSweepService {

    private static final Logger LOG = LoggerFactory.getLogger(EntitlementShadowSweepService.class);

    private final TenantEntitlementService tenantEntitlementService;
    private final TenantService tenantService;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public EntitlementShadowSweepService(
            TenantEntitlementService tenantEntitlementService,
            TenantService tenantService) {
        this.tenantEntitlementService = tenantEntitlementService;
        this.tenantService = tenantService;
    }

    @Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    @Scheduled(zone = "UTC", cron = "${app.entitlements.shadow-sweep-cron:0 */30 * * * *}")
    public void sweep() {
        // Nothing to shadow in LEGACY mode.
        if (!tenantEntitlementService.shadowSweepEnabled()) {
            return;
        }
        // Single-instance guard: only the leader runs the sweep, so replicas do not duplicate logs.
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("entitlement.shadow-sweep")) {
            return;
        }
        TenantContext.runAsPlatform(() -> {
            List<Tenant> tenants = tenantService.listActiveTenants();
            int tenantsWithMismatches = 0;
            for (Tenant tenant : tenants) {
                try {
                    List<TenantEntitlementService.ShadowMismatch> mismatches =
                            tenantEntitlementService.detectShadowMismatches(tenant);
                    if (!mismatches.isEmpty()) {
                        tenantsWithMismatches++;
                    }
                    for (TenantEntitlementService.ShadowMismatch mismatch : mismatches) {
                        tenantEntitlementService.incrementMismatchCounter(
                                mismatch.key(), mismatch.source(), mismatch.correctedEnabled());
                        LOG.info("entitlement shadow mismatch tenant={} key={} legacy=true corrected={} source={}",
                                tenant.getId(), mismatch.key(), mismatch.correctedEnabled(), mismatch.source());
                    }
                } catch (Exception ex) {
                    LOG.warn("Entitlement shadow sweep failed for tenant {}: {}",
                            tenant.getId(), ex.getMessage(), ex);
                }
            }
            LOG.info("Entitlement shadow sweep complete: {} active tenants, {} with mismatches",
                    tenants.size(), tenantsWithMismatches);
        });
    }
}
