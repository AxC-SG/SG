package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import com.prototype.vulnwatch.service.AuditEventService;
import java.time.Instant;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Queues one unobserved interval at a time; persisted run/ledger rows provide restart continuity. */
@Service
public class NvdBaselineQueueService {
    public record NextWindow(UUID runId, String status, Instant from, Instant to, String message) {}

    private final NvdObservedGapsService gaps;
    private final NvdSyncService nvd;
    private final VulnerabilitySourceFilterConfigService filters;
    private final AuditEventService audit;

    public NvdBaselineQueueService(NvdObservedGapsService gaps, NvdSyncService nvd,
                                   VulnerabilitySourceFilterConfigService filters, AuditEventService audit) {
        this.gaps = gaps;
        this.nvd = nvd;
        this.filters = filters;
        this.audit = audit;
    }

    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional
    public NextWindow queueNext(Instant from, Instant to) {
        String key = NvdSyncService.nvdScopeKey(filters.resolvePlatformNvdFilters());
        var plan = gaps.plan(key, from, to);
        NextWindow result = null;
        for (var partition : plan.partitions()) {
            for (var missing : partition.unobservedIntervals()) {
                var run = nvd.triggerNvdHistoricalWindow(missing.from(), missing.to(), key);
                if ("NVD sync is already in progress".equals(run.message())) {
                    result = new NextWindow(run.runId(), "busy", null, null,
                            "An NVD run is already active; retry after it completes");
                } else {
                    result = new NextWindow(run.runId(), run.status(), missing.from(), missing.to(),
                            "One unobserved NVD interval queued; historical completeness remains unknown");
                }
                break;
            }
            if (result != null) break;
        }
        if (result == null) result = new NextWindow(null, "no_unobserved_interval", null, null,
                "No unobserved interval in this range; historical completeness remains unknown");
        audit.recordPlatformFeedInCurrentTransaction("platform.vulnerability_feed.nvd_baseline_next", "sync_run",
                result.runId() == null ? null : result.runId().toString(),
                "{\"from\":\"" + from + "\",\"to\":\"" + to + "\",\"status\":\"" + result.status() + "\"}");
        return result;
    }
}
