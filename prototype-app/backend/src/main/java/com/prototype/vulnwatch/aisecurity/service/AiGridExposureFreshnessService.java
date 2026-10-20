package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/** Demotes expired validating evidence without waiting for the next provider discovery run. */
@Service
public class AiGridExposureFreshnessService {
    private static final Logger log = LoggerFactory.getLogger(AiGridExposureFreshnessService.class);
    private final TenantRepository tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    private final NamedParameterJdbcTemplate jdbc;
    private final AiGridCoverageService coverage;
    private final AiGridSystemService systems;
    private final AiGridExposureService exposures;

    public AiGridExposureFreshnessService(TenantRepository tenants, TenantSchemaExecutionService tenantExecution,
                                          TransactionTemplate transactions, NamedParameterJdbcTemplate jdbc,
                                          AiGridCoverageService coverage, AiGridSystemService systems,
                                          AiGridExposureService exposures) {
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
        this.jdbc = jdbc;
        this.coverage = coverage;
        this.systems = systems;
        this.exposures = exposures;
    }

    private com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy backgroundPolicy=com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy.allowAll();
    @org.springframework.beans.factory.annotation.Autowired
    void configureBackgroundPolicy(com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy policy) { backgroundPolicy=policy; }

    @Scheduled(fixedDelayString = "${app.ai-security.grid.exposure-freshness-ms:60000}",
            initialDelayString = "${app.ai-security.grid.exposure-freshness-initial-delay-ms:60000}")
    public void demoteExpiredEvidence() {
        if (!backgroundPolicy.allowsBackgroundTask("demoteExpiredEvidence")) return;
        for (Tenant tenant : tenants.findAll()) {
            try {
                tenantExecution.run(tenant, () -> transactions.execute(status -> {
                    Integer stale = jdbc.queryForObject("""
                            select count(*) from ai_grid_exposure_paths p where p.state='VALIDATED_EXPOSURE'
                              and exists (select 1 from ai_grid_exposure_observations o
                                   where o.exposure_path_id=p.id and o.coverage_epoch_id=p.last_complete_epoch_id
                                     and o.temporal_valid_until is not null and o.temporal_valid_until<now())
                            """, Map.of(), Integer.class);
                    AiGridCoverageService.CurrentState current = coverage.currentState();
                    if (stale != null && stale > 0 && current != null) {
                        UUID epochId = coverage.refreshCurrent(tenant, current.triggerRunId());
                        systems.deriveForCurrentEpoch(tenant, epochId, current.triggerRunId());
                        exposures.correlateCurrentEpoch(tenant, epochId, current.triggerRunId());
                    }
                    return null;
                }));
            } catch (RuntimeException error) {
                log.warn("R2 exposure freshness reconciliation failed for tenant {}; the next sweep will retry",
                        tenant.getId(), error);
            }
        }
    }
}
