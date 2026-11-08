package com.prototype.vulnwatch.service;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import java.time.Duration;
import java.time.Instant;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

@Service
public class IngestionJobMetricsService {

    private final MeterRegistry meterRegistry;
    public IngestionJobMetricsService(ObjectProvider<MeterRegistry> meterRegistryProvider) {
        this.meterRegistry = meterRegistryProvider.getIfAvailable();
    }

    public void recordEnqueued(String sourceType) {
        increment("ingestion.jobs.enqueued", sourceType);
    }

    public void recordDeduped(String sourceType) {
        increment("ingestion.jobs.deduped", sourceType);
    }

    public void recordStarted(String sourceType) {
        increment("ingestion.jobs.started", sourceType);
    }

    public void recordEnqueueToStartLatency(String sourceType, Instant requestedAt, Instant startedAt) {
        if (meterRegistry == null || requestedAt == null || startedAt == null || startedAt.isBefore(requestedAt)) {
            return;
        }
        meterRegistry.timer("ingestion.jobs.enqueue_to_start.duration", Tags.of("sourceType", tagValue(sourceType)))
                .record(Duration.between(requestedAt, startedAt));
    }

    public void recordCompleted(String sourceType) {
        increment("ingestion.jobs.completed", sourceType);
    }

    public void recordFailed(String sourceType) {
        increment("ingestion.jobs.failed", sourceType);
    }

    public void recordLockRetry(String sourceType) {
        increment("ingestion.jobs.lock_retries", sourceType);
    }

    public void recordQuotaRejected(String sourceType) {
        increment("ingestion.jobs.quota_rejections", sourceType);
    }

    public void recordRateLimited(String sourceType) {
        increment("ingestion.jobs.rate_limit_rejections", sourceType);
    }

    public void recordAdmissionRejected(String sourceType) {
        increment("ingestion.jobs.admission_rejections", sourceType);
    }

    public void recordExecutionDuration(String sourceType, Instant startedAt, Instant completedAt) {
        if (meterRegistry == null || startedAt == null || completedAt == null || completedAt.isBefore(startedAt)) {
            return;
        }
        meterRegistry.timer("ingestion.jobs.execution.duration", Tags.of("sourceType", tagValue(sourceType)))
                .record(Duration.between(startedAt, completedAt));
    }

    private void increment(String name, String sourceType) {
        if (meterRegistry == null) {
            return;
        }
        meterRegistry.counter(name, "sourceType", tagValue(sourceType)).increment();
    }

    private String tagValue(String value) {
        return value == null || value.isBlank() ? "unknown" : value.trim().toLowerCase();
    }
}
