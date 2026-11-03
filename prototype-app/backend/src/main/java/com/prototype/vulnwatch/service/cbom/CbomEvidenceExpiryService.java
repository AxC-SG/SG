package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.sql.Date;
import java.time.Clock;
import java.time.LocalDate;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Evidence expiry (plan Milestone 4). Certificate and key expiry rules depend on the date, so a
 * finding raised when a certificate was merely expiring is stale once it has expired, and one
 * that was valid can enter the warning window without any new CBOM. Daily, per tenant, active
 * CBOMs with a component that crossed the expiry or warning threshold since it was last evaluated
 * are re-evaluated (bounded per run) and reassessed. Stale declared relationships are reported.
 */
@Service
public class CbomEvidenceExpiryService {
    private static final Logger LOG = LoggerFactory.getLogger(CbomEvidenceExpiryService.class);

    public record TenantSweep(UUID tenantId, int reevaluatedArtifacts, int findingsEvaluated, int staleRelationships) { }

    private final JdbcTemplate jdbc;
    private final BomIngestionRecordRepository boms;
    private final CbomIngestionService ingestion;
    private final IngestionJobService jobs;
    private final TenantService tenants;
    private final TenantSchemaExecutionService schemas;
    private final TransactionTemplate transactions;
    private BackgroundTaskExecutionPolicy policy = BackgroundTaskExecutionPolicy.allowAll();
    private Clock clock = Clock.systemUTC();
    private int warningDays = 90;
    private int maxArtifactsPerTenant = 100;

    public CbomEvidenceExpiryService(JdbcTemplate jdbc, BomIngestionRecordRepository boms, CbomIngestionService ingestion,
            IngestionJobService jobs, TenantService tenants, TenantSchemaExecutionService schemas, TransactionTemplate transactions) {
        this.jdbc = jdbc; this.boms = boms; this.ingestion = ingestion; this.jobs = jobs; this.tenants = tenants;
        this.schemas = schemas; this.transactions = transactions;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy value) {
        policy = value == null ? BackgroundTaskExecutionPolicy.allowAll() : value;
    }
    void setClock(Clock value) { clock = value; }
    private CbomRulePackageService rulePackages;

    /** The warning window follows the tenant's certificateExpiryWarningDays; the property is only a fallback. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setRulePackages(CbomRulePackageService value) { rulePackages = value; }

    @Value("${app.cbom.evidence-expiry.warning-days:90}") public void setWarningDays(int value) { warningDays = Math.max(1, value); }
    @Value("${app.cbom.evidence-expiry.max-artifacts-per-tenant:100}") public void setMaxArtifactsPerTenant(int value) { maxArtifactsPerTenant = Math.max(1, value); }

    @Scheduled(cron = "${app.cbom.evidence-expiry.cron:0 40 2 * * *}", zone = "UTC")
    public void scheduledSweep() {
        if (!policy.allowsBackgroundTask("cbom-evidence-expiry.sweep")) return;
        for (Tenant tenant : TenantContext.runAsPlatform(() -> tenants.listActiveTenants())) {
            try { sweep(tenant); }
            catch (RuntimeException failure) { LOG.warn("CBOM evidence expiry failed for tenant {}: {}", tenant.getId(), failure.getMessage()); }
        }
    }

    /** One tenant; establishes tenant context before each transaction. */
    public TenantSweep sweep(Tenant tenant) {
        LocalDate today = LocalDate.now(clock);
        record Plan(List<UUID> due, int stale) { }
        Plan plan = schemas.run(tenant, () -> transactions.execute(tx -> {
            int warningDays = rulePackages == null ? this.warningDays : rulePackages.parameters(tenant).certificateExpiryWarningDays();
            return new Plan(jdbc.queryForList("""
                SELECT DISTINCT c.source_bom_id FROM cbom_components c
                  JOIN bom_ingestion_records b ON b.id = c.source_bom_id AND b.status = 'ACTIVE' AND b.bom_type = 'CBOM'
                 WHERE c.tenant_id = ? AND c.active AND c.not_after IS NOT NULL
                   AND ((c.not_after < ? AND c.updated_at < c.not_after::timestamptz + interval '1 day')
                     OR (c.not_after <= ? AND c.updated_at < (c.not_after - ?)::timestamptz))
                 LIMIT ?
                """, UUID.class, tenant.getId(), Date.valueOf(today), Date.valueOf(today.plusDays(warningDays)), warningDays,
                maxArtifactsPerTenant),
                jdbc.queryForObject("SELECT count(*) FROM cbom_relationships WHERE tenant_id = ? AND valid_until < now()",
                        Integer.class, tenant.getId()));
        }));
        int findings = 0;
        for (UUID bomId : plan.due()) {
            findings += schemas.run(tenant, () -> transactions.execute(tx -> boms.findById(bomId)
                    .map(bom -> ingestion.reevaluate(tenant, bom)).orElse(0)));
            jobs.enqueueCbomAssessmentJob(tenant, bomId, "cbom-evidence-expiry");
        }
        if (!plan.due().isEmpty() || plan.stale() > 0) {
            LOG.info("CBOM evidence expiry for tenant {}: re-evaluated {} artifacts, {} stale relationships",
                    tenant.getId(), plan.due().size(), plan.stale());
        }
        return new TenantSweep(tenant.getId(), plan.due().size(), findings, plan.stale());
    }
}
