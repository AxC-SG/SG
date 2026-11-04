package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.CbomRiskFindingRepository;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Bounded repair for the CRYPTO finding mirror. CBOM ingest, withdrawal and assessment publish
 * per-finding {@code CBOM_DELTA} entries, so this sweep no longer mirrors every CBOM finding.
 * It runs one bounded drift-detection query per tenant (live finding without a canonical row,
 * or canonical row still OPEN for a finding that is no longer live) and republishes deltas
 * only for those. Repaired rows leave the candidate set, so no cursor is needed.
 *
 * <p>Tenant context is established before the query transaction opens, as TenantAwareDataSource
 * pins the schema when the connection is acquired.
 */
@Service
public class CbomFindingMirrorSweep {

    private static final Logger LOG = LoggerFactory.getLogger(CbomFindingMirrorSweep.class);

    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final CbomRiskFindingRepository cbomFindings;
    private final FindingDeltaQueueService deltaQueue;
    private final CbomOperationsMetrics metrics;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();
    private int repairLimitPerTenant = 500;

    public CbomFindingMirrorSweep(
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            CbomRiskFindingRepository cbomFindings,
            FindingDeltaQueueService deltaQueue,
            CbomOperationsMetrics metrics
    ) {
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.cbomFindings = cbomFindings;
        this.deltaQueue = deltaQueue;
        this.metrics = metrics;
    }

    @Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy policy) {
        this.backgroundTaskExecutionPolicy = policy == null ? BackgroundTaskExecutionPolicy.allowAll() : policy;
    }

    @Value("${app.cbom.finding-mirror.repair-limit-per-tenant:500}")
    public void setRepairLimitPerTenant(int value) {
        this.repairLimitPerTenant = Math.max(1, value);
    }

    @Scheduled(
            fixedDelayString = "${app.cbom.finding-mirror.interval-ms:900000}",
            initialDelayString = "${app.cbom.finding-mirror.initial-delay-ms:60000}")
    public void sweep() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("cbom-finding-mirror.sync")) {
            return;
        }
        try {
            TenantContext.runAsPlatform(() -> {
                for (Tenant tenant : tenantService.listActiveTenants()) {
                    try {
                        repairTenant(tenant);
                    } catch (Exception ex) {
                        metrics.recordRepairFailure();
                        LOG.warn("Crypto finding mirror repair failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                    }
                }
                return null;
            });
        } catch (Exception ex) {
            LOG.warn("Crypto finding mirror repair cycle failed: {}", ex.getMessage(), ex);
        }
    }

    /** Returns the number of drifted findings republished for the tenant. */
    int repairTenant(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> {
            List<UUID> drifted = cbomFindings.findMirrorRepairCandidates(repairLimitPerTenant);
            metrics.recordRepairScan(drifted.size(), drifted.size() >= repairLimitPerTenant);
            if (drifted.isEmpty()) {
                return 0;
            }
            deltaQueue.enqueueCbomDeltas(tenant.getId(), drifted, "cbom-repair");
            return drifted.size();
        });
    }
}
