package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Campaign;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.CampaignRepository;
import io.micrometer.core.instrument.MeterRegistry;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Keeps CVE campaign membership current (Phase 0B §4.3). Every 15 minutes on worker nodes it adds findings that joined
 * a CVE campaign's scope after launch (new findings, non-members that reopened) and finishes campaigns still
 * MATERIALIZING after the create bound. It never removes a member and never touches CLOSED or CANCELLED campaigns.
 *
 * <p>Per tenant it processes at most {@value #CAMPAIGNS_PER_TENANT} campaigns, least recently reconciled first, each in
 * its own tenant-scoped transaction opened after the tenant context ({@code run(tenant, () -> tx.execute(...))}). The
 * campaign row is locked {@code FOR UPDATE SKIP LOCKED}, so overlapping worker nodes split the work, and the watermark
 * moves in the same transaction as its batch. Three consecutive failures record a {@code RECONCILE_FAILED} activity and
 * increment {@value #FAILURE_METRIC}.
 */
@Component
public class CampaignMembershipReconciler {

    static final int CAMPAIGNS_PER_TENANT = 20;
    static final int FAILURE_THRESHOLD = 3;
    static final String FAILURE_METRIC = "campaign.reconciliation.failures";
    private static final Logger LOG = LoggerFactory.getLogger(CampaignMembershipReconciler.class);

    private final TenantService tenants;
    private final TenantSchemaExecutionService scoped;
    private final CampaignLedger ledger;
    private final CampaignService campaigns;
    private final CampaignRepository campaignRepository;
    private final JdbcTemplate jdbc;
    private final BackgroundTaskExecutionPolicy backgroundTasks;
    private final MeterRegistry metrics;
    private final TransactionTemplate tx;

    public CampaignMembershipReconciler(TenantService tenants, TenantSchemaExecutionService scoped, CampaignLedger ledger,
                                        CampaignService campaigns, CampaignRepository campaignRepository, JdbcTemplate jdbc,
                                        BackgroundTaskExecutionPolicy backgroundTasks, MeterRegistry metrics,
                                        PlatformTransactionManager transactions) {
        this.tenants = tenants;
        this.scoped = scoped;
        this.ledger = ledger;
        this.campaigns = campaigns;
        this.campaignRepository = campaignRepository;
        this.jdbc = jdbc;
        this.backgroundTasks = backgroundTasks;
        this.metrics = metrics;
        this.tx = new TransactionTemplate(transactions);
        this.tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Scheduled(zone = "UTC", cron = "${app.campaigns.reconciler.cron:0 */15 * * * *}")
    public void run() {
        if (!backgroundTasks.allowsBackgroundTask("campaign.reconciler")) return;
        List<Tenant> active = TenantContext.runAsPlatform(tenants::listActiveTenants);
        for (Tenant tenant : active) {
            try {
                runForTenant(tenant);
            } catch (RuntimeException ex) {
                LOG.warn("Campaign reconciliation failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
            }
        }
    }

    /** One tenant's pass; returns the members added. */
    public int runForTenant(Tenant tenant) {
        List<UUID> due = scoped.run(tenant, () -> tx.execute(status -> jdbc.queryForList("""
                SELECT id FROM campaigns
                 WHERE status NOT IN ('CLOSED','CANCELLED', 'DRAFT')
                   AND ((scope_kind = 'CVE' AND status IN ('ACTIVE','PAUSED','BLOCKED','IN_REVIEW')) OR membership_state = 'MATERIALIZING')
                 ORDER BY reconciled_at NULLS FIRST, id LIMIT ?
                """, UUID.class, CAMPAIGNS_PER_TENANT)));
        int added = 0;
        for (UUID campaignId : due) added += reconcile(tenant, campaignId);
        return added;
    }

    /** Reconciles one campaign; a failure is recorded on the campaign and never thrown. */
    public int reconcile(Tenant tenant, UUID campaignId) {
        try {
            Integer added = scoped.run(tenant, () -> tx.execute(status -> {
                List<Map<String, Object>> rows = jdbc.queryForList("""
                        SELECT include_excepted, membership_state FROM campaigns
                         WHERE id = ? AND status NOT IN ('CLOSED','CANCELLED') FOR UPDATE SKIP LOCKED
                        """, campaignId);
                if (rows.isEmpty()) return 0;
                boolean includeExcepted = Boolean.TRUE.equals(rows.get(0).get("include_excepted"));
                boolean materializing = "MATERIALIZING".equals(rows.get(0).get("membership_state"));
                CampaignLedger.ReconcileResult result = ledger.reconcileBatch(campaignId, includeExcepted, CampaignLedger.RECONCILE_BATCH);
                boolean completes = materializing && result.caughtUp();
                jdbc.update("""
                        UPDATE campaigns SET reconciled_at = now(), last_reconcile_added = ?, last_reconcile_error = NULL, reconcile_failures = 0,
                               membership_state = CASE WHEN ? THEN 'COMPLETE' ELSE membership_state END
                         WHERE id = ?
                        """, result.added(), completes, campaignId);
                if (completes) {
                    Campaign campaign = campaignRepository.findById(campaignId).orElseThrow();
                    campaigns.recordActivity(campaign, "system", "MATERIALIZED", "Every in-scope member has been added to the campaign.");
                    campaigns.deliverLaunchNotifications(campaign, "system");
                }
                return result.added();
            }));
            return added == null ? 0 : added;
        } catch (RuntimeException failure) {
            recordFailure(tenant, campaignId, failure);
            return 0;
        }
    }

    private void recordFailure(Tenant tenant, UUID campaignId, RuntimeException failure) {
        LOG.warn("Campaign {} reconciliation failed: {}", campaignId, failure.getMessage(), failure);
        String message = failure.getMessage() == null ? failure.getClass().getSimpleName() : failure.getMessage();
        String error = message.length() > 1000 ? message.substring(0, 1000) : message;
        scoped.run(tenant, () -> tx.executeWithoutResult(status -> {
            List<Integer> failures = jdbc.queryForList("""
                    UPDATE campaigns SET reconciled_at = now(), last_reconcile_error = ?, reconcile_failures = reconcile_failures + 1
                     WHERE id = ? RETURNING reconcile_failures
                    """, Integer.class, error, campaignId);
            if (!failures.isEmpty() && failures.get(0) == FAILURE_THRESHOLD) {
                campaignRepository.findById(campaignId).ifPresent(campaign -> campaigns.recordActivity(campaign, "system", "RECONCILE_FAILED",
                        "Membership reconciliation failed " + FAILURE_THRESHOLD + " times in a row: " + error));
                metrics.counter(FAILURE_METRIC).increment();
            }
        }));
    }
}
