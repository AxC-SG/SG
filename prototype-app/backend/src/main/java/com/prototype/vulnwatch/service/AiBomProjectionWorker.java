package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Durable worker for {@code AI_GRID_BOM_PROJECTION} jobs. Mirrors
 * {@code com.prototype.vulnwatch.aisecurity.service.AiGridRuntimeIngestionWorker}'s legacy
 * poll/claim/process/mark shape, with one deliberate difference: {@code recordStarted}/
 * {@code recordCompleted}/{@code recordFailed} write an audit event through
 * {@code RequestActorService.currentActor()}, which resolves the actor's tenant via
 * {@code WorkspaceService.getWorkspace()} -- and that throws {@code 403} without an actual
 * tenant in {@link TenantContext}. A background scheduler tick has no HTTP request to carry
 * one, so this worker sets it explicitly for the duration of each job.
 */
@lombok.extern.slf4j.Slf4j
@Service
public class AiBomProjectionWorker {

    private final IngestionJobService jobs;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final AiBomProjectionService projectionService;
    private final AiBomProjectionSchedulingService schedulingService;
    private final AiBomResourceVulnerabilityCorrelationService vulnerabilityCorrelationService;
    private final boolean enabled;
    private BackgroundTaskExecutionPolicy backgroundPolicy = BackgroundTaskExecutionPolicy.allowAll();

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundPolicy(BackgroundTaskExecutionPolicy policy) {
        backgroundPolicy = java.util.Objects.requireNonNull(policy);
    }

    public AiBomProjectionWorker(
            IngestionJobService jobs,
            TenantService tenants,
            TenantSchemaExecutionService tenantExecution,
            AiBomProjectionService projectionService,
            AiBomProjectionSchedulingService schedulingService,
            AiBomResourceVulnerabilityCorrelationService vulnerabilityCorrelationService,
            @Value("${app.ai-bom.projection.worker-enabled:true}") boolean enabled) {
        this.jobs = jobs;
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.projectionService = projectionService;
        this.schedulingService = schedulingService;
        this.vulnerabilityCorrelationService = vulnerabilityCorrelationService;
        this.enabled = enabled;
    }

    @Scheduled(
            initialDelayString = "${app.ai-bom.projection.initial-delay-ms:5000}",
            fixedDelayString = "${app.ai-bom.projection.poll-interval-ms:5000}")
    public void poll() {
        if (!enabled || !backgroundPolicy.allowsBackgroundTask("ai-bom.projection")) return;
        for (Tenant tenant : tenants.listActiveTenants()) {
            try {
                List<IngestionJobService.ClaimedJobRef> claimed = jobs.claimPendingJobsByType(
                        tenant, IngestionJobService.JOB_TYPE_AI_GRID_BOM_PROJECTION, 5, 5);
                claimed.forEach(ref -> processSafely(tenant, ref));
            } catch (Exception e) {
                log.warn("AI-BOM tenant poll failed tenant={} failure={}", tenant.getId(), e.getClass().getSimpleName());
            }
        }
    }

    /**
     * Lighter-weight than {@link #poll()}: sources waiting on entitlement or queue room don't
     * need second-by-second attention. Reuses the same admission decision ingestion itself
     * runs, so "on entitlement enablement, schedule" and "retain overflow for later scheduling"
     * are one code path re-run, not two mechanisms.
     *
     * <p>Also re-runs declared-resource-to-finding correlation (Milestone 3, part 5.1) on the
     * same tick: the software component a declared resource transitively depends on may not
     * have an open finding yet at upload time, since component-vulnerability correlation is
     * itself asynchronous. Idempotent, so retrying on every tick until the underlying
     * correlation catches up costs nothing beyond a handful of reads.
     */
    @Scheduled(fixedDelayString = "${app.ai-bom.projection.reconcile-interval-ms:60000}")
    public void reconcile() {
        if (!enabled || !backgroundPolicy.allowsBackgroundTask("ai-bom.projection")) return;
        for (Tenant tenant : tenants.listActiveTenants()) {
            try {
                schedulingService.reconcileHeldAndDeferredSources(tenant);
                vulnerabilityCorrelationService.reconcileAllForTenant(tenant);
            } catch (Exception e) {
                log.warn("AI-BOM tenant sweep failed tenant={} failure={}", tenant.getId(), e.getClass().getSimpleName());
            }
        }
    }

    private void processSafely(Tenant tenant, IngestionJobService.ClaimedJobRef ref) {
        try (var ignored = jobs.openAttempt(ref.tenantId(), ref.jobId(), ref.claimToken())) {
            processOwned(tenant, ref);
        } catch (IngestionAttemptService.StaleAttemptException stale) {
            log.info("Skipped expired AI-BOM attempt for job {}", ref.jobId());
        }
    }

    private void processOwned(Tenant tenant, IngestionJobService.ClaimedJobRef ref) {
        tenantExecution.run(tenant, () -> {
            IngestionJob job = jobs.loadJob(ref.tenantId(), ref.jobId());
            jobs.recordStarted(job);
            try {
                IngestionJobService.AiGridBomProjectionJobPayload payload = jobs.readPayload(
                        job, IngestionJobService.AiGridBomProjectionJobPayload.class);
                projectionService.project(tenant, payload.sourceId());
                jobs.markSucceeded(ref.tenantId(), ref.jobId(), null, null);
                job.setCompletedAt(Instant.now());
                try {
                    jobs.recordCompleted(job);
                } catch (RuntimeException reportingFailure) {
                    log.warn("Ancillary completion reporting failed for succeeded job {}", ref.jobId());
                }
            } catch (AiBomProjectionThrottledException throttled) {
                // Not a failure: the work is still valid, just waiting for tomorrow's budget.
                // recordCompleted/recordFailed are both skipped -- the job isn't done.
                jobs.markQueuedForRetry(ref.tenantId(), ref.jobId(), "DAILY_BUDGET_EXCEEDED",
                        throttled.getMessage(), nextUtcMidnight());
            } catch (Exception failure) {
                jobs.markFailed(ref.tenantId(), ref.jobId(), "AI_BOM_PROJECTION_FAILED",
                        "AI-BOM provenance projection could not be processed");
                job.setCompletedAt(Instant.now());
                jobs.recordFailed(job);
            }
        });
    }

    private Instant nextUtcMidnight() {
        return LocalDate.now(ZoneOffset.UTC).plusDays(1).atStartOfDay(ZoneOffset.UTC).toInstant();
    }
}
