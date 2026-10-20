package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.RejectedExecutionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class IngestionJobWorkerService {

    private static final Logger LOG = LoggerFactory.getLogger(IngestionJobWorkerService.class);

    private final IngestionJobService ingestionJobService;
    private final IngestionJobExecutionService executionService;
    private final IngestionJobLockService ingestionJobLockService;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TaskExecutor sbomJobExecutor;
    private final TransactionTemplate transactionTemplate;
    private final int pollBatchSize;
    private final int maxConcurrentPerTenant;
    private final long retryDelayMs;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public IngestionJobWorkerService(
            IngestionJobService ingestionJobService,
            IngestionJobExecutionService executionService,
            IngestionJobLockService ingestionJobLockService,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            @Qualifier("sbomJobExecutor") TaskExecutor sbomJobExecutor,
            TransactionTemplate transactionTemplate,
            @org.springframework.beans.factory.annotation.Value("${app.ingestion.jobs.poll-batch-size:10}") int pollBatchSize,
            @org.springframework.beans.factory.annotation.Value("${app.ingestion.jobs.max-concurrent-per-tenant:1}") int maxConcurrentPerTenant,
            @org.springframework.beans.factory.annotation.Value("${app.ingestion.jobs.retry-delay-ms:5000}") long retryDelayMs
    ) {
        this.ingestionJobService = ingestionJobService;
        this.executionService = executionService;
        this.ingestionJobLockService = ingestionJobLockService;
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.sbomJobExecutor = sbomJobExecutor;
        this.transactionTemplate = transactionTemplate;
        this.pollBatchSize = pollBatchSize;
        this.maxConcurrentPerTenant = maxConcurrentPerTenant;
        this.retryDelayMs = retryDelayMs;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    @PostConstruct
    @Scheduled(fixedDelayString="${app.ingestion.jobs.recovery-interval-ms:30000}")
    public void recoverInterruptedJobs() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("ingestion-job-worker.recover-interrupted-jobs")) {
            return;
        }
        // Recovery is best-effort housekeeping. In pre-production, a newly deployed API can be
        // ahead of a tenant schema while the separately operated schema migrator is still running.
        // Never let that expected migration gate prevent the API (and its readiness endpoint) from
        // starting; work for that tenant remains blocked by TenantSchemaExecutionService until it
        // is compatible, and the scheduled poller retries it on subsequent cycles.
        try {
            int recovered = ingestionJobService.recoverInterruptedRunningJobs();
            if (recovered > 0) {
                LOG.warn("Recovered {} interrupted ingestion jobs left RUNNING during the previous process lifetime", recovered);
            }
        } catch (Exception ex) {
            LOG.warn("Skipped interrupted ingestion-job recovery during startup: {}", ex.getMessage(), ex);
        }
    }

    @Scheduled(fixedDelayString = "${app.ingestion.jobs.poll-interval-ms:2000}")
    public void pollJobs() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("ingestion-job-worker.poll-jobs")) {
            return;
        }
        // This method MUST NOT let any exception escape. A periodic @Scheduled task that throws is
        // not rescheduled by Spring's ReschedulingRunnable, so a single transient failure (e.g. a DB
        // connection error after a host sleep/clock-leap exhausts the pool) would silently kill the
        // poller for the rest of the JVM's life and leave every ingestion job stuck in QUEUED. The
        // listActiveTenants() call below touches the database, so it has to be inside the guard too.
        try {
            TenantContext.runAsPlatform(() -> {
                for (Tenant tenant : tenantService.listActiveTenants()) {
                    if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("ingestion-job-worker.claim")) break;
                    try {
                        List<IngestionJobService.ClaimedJobRef> claimed = ingestionJobService.claimPendingJobs(
                                tenant,
                                pollBatchSize,
                                maxConcurrentPerTenant
                        );
                        var allClaimed = new java.util.ArrayList<>(claimed);
                        for (String connector : List.of(IngestionJobService.JOB_TYPE_AWS_DISCOVERY,
                                IngestionJobService.JOB_TYPE_SERVICENOW_CMDB)) {
                            if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("ingestion-job-worker.claim")) break;
                            allClaimed.addAll(ingestionJobService.claimPendingJobsByType(tenant, connector, 1, 1));
                        }
                        for (IngestionJobService.ClaimedJobRef ref : allClaimed) {
                            if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("ingestion-job-worker.dispatch")) {
                                ingestionJobService.retryRejectedClaim(ref, "WORKER_STOPPING",
                                        "Worker stopped before dispatch", Instant.now());
                                continue;
                            }
                            try {
                                sbomJobExecutor.execute(() -> execute(ref.tenantId(), ref.jobId(), ref.claimToken()));
                            } catch (RejectedExecutionException ex) {
                                ingestionJobService.retryRejectedClaim(
                                        ref,
                                        "EXECUTOR_BUSY",
                                        "SBOM job executor is at capacity",
                                        Instant.now().plusMillis(retryDelayMs)
                                );
                            }
                        }
                    } catch (Exception ex) {
                        LOG.warn("Failed polling ingestion jobs for tenant {}: {}", tenant.getId(), ex.getMessage(), ex);
                    }
                }
            });
        } catch (Exception ex) {
            LOG.warn("Ingestion job poll cycle failed before tenant iteration: {}", ex.getMessage(), ex);
        }
    }

    void execute(java.util.UUID tenantId, java.util.UUID jobId) {
        execute(tenantId, jobId, ingestionJobService.loadJob(tenantId, jobId).getClaimToken());
    }

    private void execute(java.util.UUID tenantId, java.util.UUID jobId, java.util.UUID token) {
        try (var ignored = ingestionJobService.openAttempt(tenantId, jobId, token)) {
            executeOwned(tenantId, jobId);
        } catch (com.prototype.vulnwatch.service.IngestionAttemptService.StaleAttemptException stale) {
            LOG.info("Skipped ingestion job {} because its attempt is no longer owned", jobId);
        }
    }

    private void executeOwned(java.util.UUID tenantId, java.util.UUID jobId) {
        Tenant tenant = tenantService.resolveTenantUuid(tenantId);
        IngestionJob job = ingestionJobService.loadJob(tenantId, jobId);
        try {
            // Tenant context first, transaction second: TenantAwareDataSource pins the connection's
            // search_path when the connection is acquired, so the transaction must begin *after* the
            // tenant schema is selected. Opening the transaction first would bind the default schema and
            // run the lock + ingestion against the wrong tenant.
            tenantSchemaExecutionService.run(tenant, () -> {
                if (IngestionJobService.JOB_TYPE_GITHUB_REPOSITORY.equals(job.getJobType())
                        || IngestionJobService.JOB_TYPE_GITHUB_GHCR.equals(job.getJobType())
                        || IngestionJobService.JOB_TYPE_AWS_DISCOVERY.equals(job.getJobType())
                        || IngestionJobService.JOB_TYPE_SERVICENOW_CMDB.equals(job.getJobType())) {
                    executeGithubBatch(tenant, jobId);
                    return null;
                }
                transactionTemplate.executeWithoutResult(status -> {
                    IngestionJob activeJob = ingestionJobService.loadJob(tenantId, jobId);
                    long lockKey = ingestionJobLockService.assetLockKey(tenantId, activeJob.getAssetIdentifier());
                    boolean acquired = ingestionJobLockService.tryAcquireTransactionLock(lockKey);
                    if (!acquired) {
                        ingestionJobService.recordLockRetry(activeJob);
                        ingestionJobService.markQueuedForRetry(
                                tenantId,
                                jobId,
                                "ASSET_LOCK_BUSY",
                                "Another ingestion is in progress for this asset",
                                Instant.now().plusMillis(retryDelayMs)
                        );
                        return;
                    }

                    ingestionJobService.recordStarted(activeJob);
                    IngestionJobExecutionService.ExecutionOutcome outcome;
                    try {
                        outcome = executionService.execute(tenant, activeJob);
                    } catch (IOException ex) {
                        throw new IllegalStateException(ex.getMessage(), ex);
                    }
                    ingestionJobService.markSucceeded(tenantId, jobId, outcome.sbomUpload(), outcome.resultJson());
                });
                return null;
            });
            // Audit/metrics recording resolves the workspace from TenantContext, so it must run inside
            // the tenant scope too — otherwise it throws "Tenant context is required" on the worker thread
            // and a successful job is wrongly flipped to FAILED.
            tenantSchemaExecutionService.run(tenant, () -> {
                try {
                    ingestionJobService.recordCompleted(ingestionJobService.loadJob(tenantId, jobId));
                } catch (RuntimeException reportingFailure) {
                    LOG.warn("Ancillary completion reporting failed for succeeded job {}", jobId);
                }
                return null;
            });
        } catch (Exception ex) {
            String message = ex.getMessage() == null ? "Failed to execute ingestion job" : ex.getMessage();
            tenantSchemaExecutionService.run(tenant, () -> {
                ingestionJobService.markFailed(tenantId, jobId, failureCode(ex), message);
                ingestionJobService.recordFailed(ingestionJobService.loadJob(tenantId, jobId));
                return null;
            });
        }
    }

    private void executeGithubBatch(Tenant tenant, java.util.UUID jobId) {
        // GitHub batches intentionally retain accepted documents when another item fails.
        // A job-wide transaction would either poison their shared transaction on a checked
        // rejection or hold the same asset lock needed by a separate document transaction.
        transactionTemplate.executeWithoutResult(status ->
                ingestionJobService.recordStarted(ingestionJobService.loadJob(tenant.getId(), jobId)));
        IngestionJob activeJob = ingestionJobService.loadJob(tenant.getId(), jobId);
        IngestionJobExecutionService.ExecutionOutcome outcome;
        try {
            outcome = executionService.execute(tenant, activeJob);
        } catch (IOException ex) {
            throw new IllegalStateException(ex.getMessage(), ex);
        }
        // markSucceeded already owns its existing short status transaction. Each document
        // has committed/rolled back under the orchestrator's transaction and asset lock.
        ingestionJobService.markSucceeded(tenant.getId(), jobId, outcome.sbomUpload(), outcome.resultJson());
    }

    private String failureCode(Exception ex) {
        if (ex instanceof IOException) {
            return "INGESTION_IO_FAILURE";
        }
        return "INGESTION_EXECUTION_FAILURE";
    }
}
