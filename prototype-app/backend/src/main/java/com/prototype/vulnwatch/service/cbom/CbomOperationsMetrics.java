package com.prototype.vulnwatch.service.cbom;

import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

/**
 * Operational metrics for the CBOM assessment worker and the crypto finding mirror repair.
 * Labels are restricted to low-cardinality values (outcome, reason); tenant identifiers,
 * artifact names and raw values are never used as labels.
 */
@Component
public class CbomOperationsMetrics {

    private final MeterRegistry registry;
    private final AtomicLong oldestQueuedAgeSeconds = new AtomicLong();
    private final AtomicLong queuedJobs = new AtomicLong();
    private final AtomicLong tenantsWithBacklog = new AtomicLong();
    private final DistributionSummary claimsPerTenant;

    public CbomOperationsMetrics(ObjectProvider<MeterRegistry> registryProvider) {
        this.registry = registryProvider.getIfAvailable();
        if (registry != null) {
            registry.gauge("cbom.assessment.queue.oldest_age_seconds", oldestQueuedAgeSeconds);
            registry.gauge("cbom.assessment.queue.depth", queuedJobs);
            registry.gauge("cbom.assessment.tenants_with_backlog", tenantsWithBacklog);
            claimsPerTenant = DistributionSummary.builder("cbom.assessment.claims_per_tenant")
                    .description("CBOM assessment jobs claimed per tenant in one poll cycle (fairness)")
                    .register(registry);
        } else {
            claimsPerTenant = null;
        }
    }

    /** Outcome is one of succeeded, retried, failed. */
    public void recordJobOutcome(String outcome) {
        if (registry != null) registry.counter("cbom.assessment.jobs", "outcome", outcome).increment();
    }

    public void recordDuration(Duration duration) {
        if (registry != null && duration != null && !duration.isNegative()) {
            registry.timer("cbom.assessment.duration").record(duration);
        }
    }

    public void recordExecutorRejection() {
        if (registry != null) registry.counter("cbom.assessment.executor.rejections").increment();
    }

    public void recordClaims(int claimed) {
        if (claimsPerTenant != null) claimsPerTenant.record(claimed);
    }

    /** Published once per poll cycle from per-tenant backlog observations. */
    public void publishBacklog(long queued, long oldestAgeSeconds, long backloggedTenants) {
        queuedJobs.set(queued);
        oldestQueuedAgeSeconds.set(Math.max(0, oldestAgeSeconds));
        tenantsWithBacklog.set(backloggedTenants);
    }

    public void recordRepairScan(int drifted, boolean truncated) {
        if (registry == null) return;
        registry.counter("cbom.mirror.repair.scans").increment();
        registry.counter("cbom.mirror.repair.republished").increment(drifted);
        if (truncated) registry.counter("cbom.mirror.repair.truncated").increment();
    }

    public void recordRepairFailure() {
        if (registry != null) registry.counter("cbom.mirror.repair.failures").increment();
    }

    public void recordBackfillEnqueued(int enqueued) {
        if (registry != null) registry.counter("cbom.assessment.backfill.enqueued").increment(enqueued);
    }

    long oldestQueuedAgeSeconds() { return oldestQueuedAgeSeconds.get(); }
    long tenantsWithBacklog() { return tenantsWithBacklog.get(); }
}
