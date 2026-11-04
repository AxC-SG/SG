package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.CbomAssessmentRunRepository;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Backfills active CBOM artifacts into assessment runs under the tenant's current effective
 * rule package. Progress is derived entirely from persisted state (assessment runs and
 * CBOM_ASSESSMENT ingestion jobs), so it is durable across restarts and a repeated start
 * resumes where the previous one stopped. Each start enqueues at most {@code limit} artifacts.
 *
 * <p>Assessment does not change canonical finding workflow (status, decision, owner, ticket);
 * it only refreshes explainability evidence through CBOM_DELTA.
 */
@Service
public class CbomAssessmentBackfillService {

    public static final int DEFAULT_LIMIT = 500;
    public static final int MAX_LIMIT = 5000;
    private static final Logger LOG = LoggerFactory.getLogger(CbomAssessmentBackfillService.class);

    private final BomIngestionRecordRepository boms;
    private final CbomAssessmentRunRepository runs;
    private final CbomRulePackageService packages;
    private final IngestionJobService jobs;
    private final TenantSchemaExecutionService schemas;
    private final TransactionTemplate transactions;
    private final TenantService tenants;
    private final AuditEventService audit;
    private final CbomOperationsMetrics metrics;

    public CbomAssessmentBackfillService(BomIngestionRecordRepository boms, CbomAssessmentRunRepository runs,
            CbomRulePackageService packages, IngestionJobService jobs, TenantSchemaExecutionService schemas,
            TransactionTemplate transactions, TenantService tenants, AuditEventService audit,
            CbomOperationsMetrics metrics) {
        this.boms = boms;
        this.runs = runs;
        this.packages = packages;
        this.jobs = jobs;
        this.schemas = schemas;
        this.transactions = transactions;
        this.tenants = tenants;
        this.audit = audit;
        this.metrics = metrics;
    }

    public record BackfillStatus(UUID tenantId, String rulePackage, String rulePackageDigest, String evaluatorVersion,
            int activeArtifacts, int assessed, int queued, int running, int failed, int notStarted,
            boolean complete, Instant observedAt) { }

    public record BackfillStart(int enqueued, BackfillStatus status) { }

    public record PlatformBackfillResult(int tenants, int enqueued, int tenantFailures, List<BackfillStatus> statuses) { }

    /** Snapshot for one tenant. Must not be called inside a transaction. */
    public BackfillStatus status(Tenant tenant) {
        return snapshot(tenant).status();
    }

    /** Enqueues up to {@code limit} artifacts that are neither assessed nor already queued/running. */
    public BackfillStart start(Tenant tenant, String requestedBy, Integer limit) {
        int bounded = limit == null ? DEFAULT_LIMIT : Math.max(1, Math.min(MAX_LIMIT, limit));
        Snapshot before = snapshot(tenant);
        int enqueued = 0;
        for (UUID bomId : before.notStartedOrFailed()) {
            if (enqueued >= bounded) break;
            var accepted = jobs.enqueueCbomAssessmentJob(tenant, bomId, requestedBy == null ? "cbom-backfill" : requestedBy);
            if (accepted != null && !accepted.existingJob()) {
                enqueued++;
            }
        }
        int recorded = enqueued;
        metrics.recordBackfillEnqueued(recorded);
        schemas.run(tenant, () -> {
            audit.record("cbom.assessment.backfill.started", "tenant", tenant.getId().toString(),
                    "{\"enqueued\":" + recorded + ",\"limit\":" + bounded + "}");
            return null;
        });
        return new BackfillStart(enqueued, status(tenant));
    }

    /** Platform-wide start across active tenants. A tenant failure never aborts the others. */
    public PlatformBackfillResult startAllTenants(String requestedBy, Integer limitPerTenant) {
        return TenantContext.runAsPlatform(() -> {
            int enqueued = 0, failures = 0;
            List<BackfillStatus> statuses = new ArrayList<>();
            List<Tenant> active = tenants.listActiveTenants();
            for (Tenant tenant : active) {
                try {
                    BackfillStart started = start(tenant, requestedBy, limitPerTenant);
                    enqueued += started.enqueued();
                    statuses.add(started.status());
                } catch (RuntimeException ex) {
                    failures++;
                    LOG.warn("CBOM assessment backfill failed for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                }
            }
            return new PlatformBackfillResult(active.size(), enqueued, failures, statuses);
        });
    }

    public List<BackfillStatus> statusAllTenants() {
        return TenantContext.runAsPlatform(() -> {
            List<BackfillStatus> statuses = new ArrayList<>();
            for (Tenant tenant : tenants.listActiveTenants()) {
                try {
                    statuses.add(status(tenant));
                } catch (RuntimeException ex) {
                    LOG.warn("CBOM assessment backfill status failed for tenant {}: {}", tenant.getId(), ex.getMessage());
                }
            }
            return statuses;
        });
    }

    private record Snapshot(BackfillStatus status, List<UUID> notStartedOrFailed) { }

    private Snapshot snapshot(Tenant tenant) {
        Set<String> queued = jobs.assetIdentifiersByTypeAndStatus(tenant, IngestionJobService.JOB_TYPE_CBOM_ASSESSMENT, IngestionJobService.STATUS_QUEUED);
        Set<String> running = jobs.assetIdentifiersByTypeAndStatus(tenant, IngestionJobService.JOB_TYPE_CBOM_ASSESSMENT, IngestionJobService.STATUS_RUNNING);
        Set<String> failed = jobs.assetIdentifiersByTypeAndStatus(tenant, IngestionJobService.JOB_TYPE_CBOM_ASSESSMENT, IngestionJobService.STATUS_FAILED);
        return schemas.run(tenant, () -> transactions.execute(tx -> {
            CbomRulePackageService.EffectivePackage pkg = packages.effective(tenant);
            List<UUID> active = boms.findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE).stream()
                    .filter(bom -> bom.getBomType() == BomType.CBOM)
                    .map(BomIngestionRecord::getId)
                    .sorted()
                    .toList();
            Set<UUID> assessed = runs.findAssessedBomIds(tenant.getId(), pkg.digest(), pkg.evaluatorVersion());
            int done = 0, inQueue = 0, inFlight = 0, broken = 0;
            List<UUID> candidates = new ArrayList<>();
            for (UUID bomId : active) {
                String key = bomId.toString();
                if (assessed.contains(bomId)) done++;
                else if (running.contains(key)) inFlight++;
                else if (queued.contains(key)) inQueue++;
                else {
                    if (failed.contains(key)) broken++;
                    candidates.add(bomId);
                }
            }
            int notStarted = candidates.size() - broken;
            BackfillStatus status = new BackfillStatus(tenant.getId(), pkg.id() + "@" + pkg.version(), pkg.digest(),
                    pkg.evaluatorVersion(), active.size(), done, inQueue, inFlight, broken, notStarted,
                    done == active.size(), Instant.now());
            return new Snapshot(status, candidates);
        }));
    }
}
