package com.prototype.vulnwatch.service;

import java.util.concurrent.atomic.LongAdder;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Worker progress signal: counts tenant-scoped background work units and reports them once a
 * minute as one fixed log phrase that CloudWatch metric filters and release verification match.
 *
 * <p>A worker that stays running while every tenant job fails (the 2026-11-15 "V23..V20" range
 * failure) reports {@code failing}; task counts and CPU cannot show that. Only the outermost
 * scoped call on a non-request thread counts, so HTTP traffic and nested calls do not inflate it.
 */
@Component
public class TenantWorkProgress {

    static final String PHRASE = "tenant_work_progress";

    private static final Logger LOG = LoggerFactory.getLogger(TenantWorkProgress.class);
    private static final ThreadLocal<int[]> DEPTH = ThreadLocal.withInitial(() -> new int[1]);

    private final BackgroundTaskExecutionPolicy backgroundTasks;
    private final LongAdder succeeded = new LongAdder();
    private final LongAdder failed = new LongAdder();

    public TenantWorkProgress(BackgroundTaskExecutionPolicy backgroundTasks) {
        this.backgroundTasks = backgroundTasks;
    }

    public <T> T track(Supplier<T> work) {
        int[] depth = DEPTH.get();
        boolean counted = depth[0] == 0 && RequestContextHolder.getRequestAttributes() == null;
        depth[0]++;
        try {
            T result = work.get();
            if (counted) {
                succeeded.increment();
            }
            return result;
        } catch (RuntimeException failure) {
            if (counted) {
                failed.increment();
            }
            throw failure;
        } finally {
            depth[0]--;
        }
    }

    @Scheduled(zone = "UTC", cron = "${app.observability.tenant-work-progress.cron:30 * * * * *}")
    public void report() {
        if (!backgroundTasks.allowsBackgroundTask("tenant-work-progress")) {
            return;
        }
        long ok = succeeded.sumThenReset();
        long failures = failed.sumThenReset();
        LOG.info("{} outcome={} succeeded={} failed={}", PHRASE, outcome(ok, failures), ok, failures);
    }

    /** healthy: all succeeded; degraded: some failed; failing: none succeeded; idle: no work ran. */
    static String outcome(long ok, long failures) {
        if (failures == 0) {
            return ok == 0 ? "idle" : "healthy";
        }
        return ok == 0 ? "failing" : "degraded";
    }
}
