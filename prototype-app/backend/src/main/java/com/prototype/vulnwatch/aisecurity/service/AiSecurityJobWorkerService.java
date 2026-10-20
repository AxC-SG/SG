package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.IngestionJobService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.atomic.AtomicInteger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.task.TaskExecutor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class AiSecurityJobWorkerService {

    private static final Logger LOG = LoggerFactory.getLogger(AiSecurityJobWorkerService.class);

    private final IngestionJobService jobs;
    private final TenantService tenants;
    private final TenantSchemaExecutionService tenantExecution;
    private final List<AiSecurityDiscoveryProvider> providers;
    private final Map<String, AiSecurityDiscoveryProvider> providersByJobType;
    private final TaskExecutor executor;
    private final boolean enabled;
    private final int maxConcurrentPerTenant;
    private final AtomicInteger tenantCursor = new AtomicInteger();
    private BackgroundTaskExecutionPolicy backgroundPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public AiSecurityJobWorkerService(
            IngestionJobService jobs,
            TenantService tenants,
            TenantSchemaExecutionService tenantExecution,
            List<AiSecurityDiscoveryProvider> providers,
            @Qualifier("aiSecurityJobExecutor") TaskExecutor executor,
            @Value("${app.ai-security.jobs.enabled:true}") boolean enabled,
            @Value("${app.ai-security.jobs.max-concurrent-per-tenant:1}") int maxConcurrentPerTenant
    ) {
        this.jobs = jobs;
        this.tenants = tenants;
        this.tenantExecution = tenantExecution;
        this.providers = List.copyOf(providers);
        Map<String, AiSecurityDiscoveryProvider> registry = new LinkedHashMap<>();
        for (AiSecurityDiscoveryProvider provider : providers) {
            if (registry.putIfAbsent(provider.jobType(), provider) != null) {
                throw new IllegalStateException("Duplicate AI Security job provider: " + provider.jobType());
            }
        }
        this.providersByJobType = Map.copyOf(registry);
        this.executor = executor;
        this.enabled = enabled;
        this.maxConcurrentPerTenant = Math.max(1, maxConcurrentPerTenant);
    }

    @org.springframework.beans.factory.annotation.Autowired
    void setBackgroundPolicy(BackgroundTaskExecutionPolicy backgroundPolicy) {
        this.backgroundPolicy = backgroundPolicy == null ? BackgroundTaskExecutionPolicy.allowAll() : backgroundPolicy;
    }

    @Scheduled(fixedDelayString = "${app.ai-security.jobs.poll-interval-ms:3000}")
    public void poll() {
        if (!enabled || !backgroundPolicy.allowsBackgroundTask("ai-security-job-worker.poll")) {
            return;
        }
        try {
            TenantContext.runAsPlatform(() -> {
                List<Tenant> active = new ArrayList<>(tenants.listActiveTenants());
                if (active.isEmpty()) {
                    return null;
                }
                Collections.rotate(active, -(Math.floorMod(tenantCursor.getAndIncrement(), active.size())));
                for (Tenant tenant : active) {
                    for (AiSecurityDiscoveryProvider provider : providers) {
                        try {
                            List<IngestionJobService.ClaimedJobRef> claimed = jobs.claimPendingJobsByType(
                                    tenant, provider.jobType(), 1, maxConcurrentPerTenant);
                            for (var ref : claimed) {
                                try {
                                    executor.execute(() -> execute(ref.tenantId(), ref.jobId(), ref.claimToken()));
                                } catch (RejectedExecutionException ex) {
                                    jobs.retryRejectedClaim(
                                            ref, "EXECUTOR_BUSY",
                                            "AI Security worker is at capacity", Instant.now().plusSeconds(5));
                                }
                            }
                        } catch (Exception ex) {
                            LOG.warn("AI Security {} job claim failed for tenant {}: {}",
                                    provider.provider(), tenant.getId(), ex.getMessage());
                        }
                    }
                }
                return null;
            });
        } catch (Exception ex) {
            LOG.warn("AI Security job poll failed: {}", ex.getMessage());
        }
    }

    void execute(java.util.UUID tenantId, java.util.UUID jobId) {
        execute(tenantId, jobId, jobs.loadJob(tenantId, jobId).getClaimToken());
    }

    private void execute(java.util.UUID tenantId, java.util.UUID jobId, java.util.UUID token) {
        try (var ignored = jobs.openAttempt(tenantId, jobId, token)) {
            executeOwned(tenantId, jobId);
        } catch (com.prototype.vulnwatch.service.IngestionAttemptService.StaleAttemptException stale) {
            LOG.info("Skipped ingestion job {} because its attempt is no longer owned", jobId);
        }
    }

    private void executeOwned(java.util.UUID tenantId, java.util.UUID jobId) {
        Tenant tenant = tenants.resolveTenantUuid(tenantId);
        try {
            tenantExecution.run(tenant, () -> {
                IngestionJob job = jobs.loadJob(tenantId, jobId);
                jobs.recordStarted(job);
                AiSecurityDiscoveryProvider provider = providersByJobType.get(job.getJobType());
                if (provider == null) {
                    throw new IllegalArgumentException("Unsupported AI Security job type");
                }
                IngestionJobService.AiSecurityJobPayload payload =
                        jobs.readPayload(job, IngestionJobService.AiSecurityJobPayload.class);
                Object result = provider.discover(tenant, payload.connectorId());
                jobs.markSucceeded(tenantId, jobId, null, jobs.toJson(result));
                try {
                    jobs.recordCompleted(jobs.loadJob(tenantId, jobId));
                } catch (RuntimeException reportingFailure) {
                    LOG.warn("Ancillary completion reporting failed for succeeded job {}", jobId);
                }
                return null;
            });
        } catch (Exception ex) {
            LOG.warn("AI Security job {} failed for tenant {}: {}",
                    jobId, tenantId, ex.getMessage(), ex);
            tenantExecution.run(tenant, () -> {
                IngestionJob failedJob = jobs.loadJob(tenantId, jobId);
                AiSecurityDiscoveryProvider provider = providersByJobType.get(failedJob.getJobType());
                String code = provider == null ? "PROVIDER_UNAVAILABLE" : provider.failureCode(ex);
                String message = provider == null
                        ? "AI Security discovery could not be completed"
                        : provider.safeFailureMessage(code);
                jobs.markFailed(tenantId, jobId, code, message);
                jobs.recordFailed(jobs.loadJob(tenantId, jobId));
                return null;
            });
        }
    }
}
