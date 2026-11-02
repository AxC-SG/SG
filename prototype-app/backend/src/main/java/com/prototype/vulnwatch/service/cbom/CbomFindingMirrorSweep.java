package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Mirrors CBOM findings that predate the CRYPTO finding kind and repairs any drift. Ingest,
 * accept and withdrawal already mirror inline; this only catches what they did not see.
 *
 * <p>Tenant context is established before the transaction opens ({@code syncTenant} is
 * transactional and runs inside {@code run}), as TenantAwareDataSource pins the schema when
 * the connection is acquired.
 */
@Service
public class CbomFindingMirrorSweep {

    private static final Logger LOG = LoggerFactory.getLogger(CbomFindingMirrorSweep.class);

    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final CbomFindingMirrorService mirror;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public CbomFindingMirrorSweep(
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            CbomFindingMirrorService mirror
    ) {
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.mirror = mirror;
    }

    @Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy policy) {
        this.backgroundTaskExecutionPolicy = policy == null ? BackgroundTaskExecutionPolicy.allowAll() : policy;
    }

    @Scheduled(
            fixedDelayString = "${app.cbom.finding-mirror.interval-ms:300000}",
            initialDelayString = "${app.cbom.finding-mirror.initial-delay-ms:60000}")
    public void sweep() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("cbom-finding-mirror.sync")) {
            return;
        }
        TenantContext.runAsPlatform(() -> {
            for (Tenant tenant : tenantService.listActiveTenants()) {
                try {
                    tenantSchemaExecutionService.run(tenant, () -> mirror.syncTenant(tenant));
                } catch (Exception ex) {
                    LOG.warn("Crypto finding mirror failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                }
            }
            return null;
        });
    }
}
