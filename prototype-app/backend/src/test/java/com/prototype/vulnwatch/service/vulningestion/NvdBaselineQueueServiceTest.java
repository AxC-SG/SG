package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.prototype.vulnwatch.dto.NvdBaselinePlanResponse;
import com.prototype.vulnwatch.dto.NvdObservedGapsResponse;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import com.prototype.vulnwatch.service.AuditEventService;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class NvdBaselineQueueServiceTest {
    @Mock NvdObservedGapsService gaps;
    @Mock NvdSyncService nvd;
    @Mock VulnerabilitySourceFilterConfigService filters;
    @Mock AuditEventService audit;

    private final Instant from = Instant.parse("2025-01-01T00:00:00Z");
    private final Instant boundary = Instant.parse("2025-05-01T00:00:00Z");
    private final Instant to = Instant.parse("2025-05-02T00:00:00Z");

    private String scope() {
        var platformFilters = new VulnerabilitySourceFilterConfigService.NvdFilters(null, false, false, null, null);
        when(filters.resolvePlatformNvdFilters()).thenReturn(platformFilters);
        return NvdSyncService.nvdScopeKey(platformFilters);
    }

    @Test void queuesOnlyFirstMissingIntervalInCurrentPlatformScope() {
        String key = scope();
        when(gaps.plan(key, from, to)).thenReturn(new NvdBaselinePlanResponse(key, from, to, List.of(
                new NvdBaselinePlanResponse.Partition(from, boundary, 1, List.of()),
                new NvdBaselinePlanResponse.Partition(boundary, to, 0,
                        List.of(new NvdObservedGapsResponse.Interval(boundary, to)))), "UNKNOWN"));
        UUID runId = UUID.randomUUID();
        when(nvd.triggerNvdHistoricalWindow(boundary, to, key))
                .thenReturn(new SyncTriggerResponse(runId, "queued", "NVD historical window queued"));

        var result = new NvdBaselineQueueService(gaps, nvd, filters, audit).queueNext(from, to);
        assertEquals(runId, result.runId());
        assertEquals(boundary, result.from());
        assertEquals(to, result.to());
        assertTrue(result.message().contains("unknown"));
        verify(nvd).triggerNvdHistoricalWindow(boundary, to, key);
        verify(audit).recordPlatformFeedInCurrentTransaction(
                "platform.vulnerability_feed.nvd_baseline_next", "sync_run", runId.toString(),
                "{\"from\":\"" + from + "\",\"to\":\"" + to + "\",\"status\":\"queued\"}");
    }

    @Test void noObservedGapDoesNotClaimHistoricalCompleteness() {
        String key = scope();
        when(gaps.plan(key, from, to)).thenReturn(new NvdBaselinePlanResponse(key, from, to, List.of(
                new NvdBaselinePlanResponse.Partition(from, to, 2, List.of())), "UNKNOWN"));

        var result = new NvdBaselineQueueService(gaps, nvd, filters, audit).queueNext(from, to);
        assertEquals("no_unobserved_interval", result.status());
        assertNull(result.runId());
        assertTrue(result.message().contains("unknown"));
        verifyNoInteractions(nvd);
    }

    @Test void unrelatedActiveRunDoesNotClaimTheMissingWindowWasQueued() {
        String key = scope();
        when(gaps.plan(key, from, to)).thenReturn(new NvdBaselinePlanResponse(key, from, to, List.of(
                new NvdBaselinePlanResponse.Partition(from, to, 0,
                        List.of(new NvdObservedGapsResponse.Interval(from, to)))), "UNKNOWN"));
        when(nvd.triggerNvdHistoricalWindow(from, to, key)).thenReturn(new SyncTriggerResponse(UUID.randomUUID(),
                "running", "NVD sync is already in progress"));

        var result = new NvdBaselineQueueService(gaps, nvd, filters, audit).queueNext(from, to);
        assertEquals("busy", result.status());
        assertNull(result.from());
        assertNull(result.to());
    }
}
