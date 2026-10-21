package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.prototype.vulnwatch.client.NvdApiClient;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService.NvdFilters;
import com.prototype.vulnwatch.support.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@PostgresIntegrationTest
class NvdContinuityPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB = LocalPostgresTestDatabase.provision("phase3_nvd_continuity");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) { PostgresITSupport.registerDatabaseProperties(registry, DB); }
    @Autowired NvdSyncService nvd;
    @Autowired FeedWatermarkService watermarks;
    @Autowired JdbcTemplate jdbc;
    @MockitoBean NvdApiClient provider;
    @MockitoBean VulnerabilitySourceFilterConfigService filters;
    private final NvdFilters original = new NvdFilters(null, false, false, null, null);
    private final NvdFilters changed = new NvdFilters(null, false, true, null, null);

    @BeforeEach void setup() {
        jdbc.update("delete from platform.feed_sync_watermarks");
        when(filters.resolvePlatformNvdFilters()).thenReturn(original);
        when(provider.fetchPage(anyInt(), any(), any(), any(), any())).thenReturn(new NvdApiClient.NvdPage(List.of(), 0, 0, 0));
    }

    @Test void longOutageIsCoveredByContiguousBoundedIntervalsAndFrozenFilters() {
        Instant completed = Instant.now().minus(Duration.ofDays(250));
        watermarks.complete(key(original), completed);
        when(filters.resolvePlatformNvdFilters()).thenReturn(original, changed);
        List<Instant> starts = new ArrayList<>(), ends = new ArrayList<>();
        when(provider.fetchPage(anyInt(), any(), any(), any(), any())).thenAnswer(call -> {
            starts.add(call.getArgument(1)); ends.add(call.getArgument(2));
            NvdApiClient.NvdQueryFilters sent = call.getArgument(3);
            assertFalse(sent.hasKev());
            return new NvdApiClient.NvdPage(List.of(), 0, 0, 0);
        });
        assertEquals("ok", nvd.syncNvd(24).status());
        assertEquals(3, starts.size());
        assertEquals(completed.minus(Duration.ofHours(1)).toEpochMilli(), starts.get(0).toEpochMilli());
        for (int i = 0; i < starts.size(); i++) {
            assertTrue(Duration.between(starts.get(i), ends.get(i)).compareTo(Duration.ofDays(120)) <= 0);
            if (i > 0) assertEquals(ends.get(i - 1), starts.get(i));
        }
        assertEquals(ends.get(2).toEpochMilli(), watermarks.completedUntil(key(original)).orElseThrow().toEpochMilli());
        assertTrue(watermarks.completedUntil(key(changed)).isEmpty());
        verify(filters).resolvePlatformNvdFilters();
    }

    @Test void failedSecondIntervalDoesNotCertifyGapAndReplayResumesAtLastCompletedBoundary() {
        watermarks.complete(key(original), Instant.now().minus(Duration.ofDays(250)));
        AtomicInteger calls = new AtomicInteger();
        List<Instant> ends = new ArrayList<>();
        when(provider.fetchPage(anyInt(), any(), any(), any(), any())).thenAnswer(call -> {
            ends.add(call.getArgument(2));
            if (calls.incrementAndGet() == 2) throw new IllegalStateException("offline provider interruption");
            return new NvdApiClient.NvdPage(List.of(), 0, 0, 0);
        });
        assertEquals("failed", nvd.syncNvd(24).status());
        Instant checkpoint = watermarks.completedUntil(key(original)).orElseThrow();
        assertEquals(ends.get(0).toEpochMilli(), checkpoint.toEpochMilli());
        assertTrue(checkpoint.isBefore(ends.get(1)));
        List<Instant> replay = new ArrayList<>();
        when(provider.fetchPage(anyInt(), any(), any(), any(), any())).thenAnswer(call -> {
            replay.add(call.getArgument(1));
            return new NvdApiClient.NvdPage(List.of(), 0, 0, 0);
        });
        assertEquals("ok", nvd.syncNvd(24).status());
        assertEquals(checkpoint.minus(Duration.ofHours(1)).toEpochMilli(), replay.get(0).toEpochMilli());
        assertTrue(watermarks.completedUntil(key(original)).orElseThrow().isAfter(checkpoint));
    }

    @Test void filterChangeStartsIndependentHistoryAndEmptyIncompletePageDoesNotAdvanceIt() {
        Instant previous = Instant.now().minus(Duration.ofDays(200));
        watermarks.complete(key(original), previous);
        when(filters.resolvePlatformNvdFilters()).thenReturn(changed);
        when(provider.fetchPage(anyInt(), any(), any(), any(), any())).thenReturn(new NvdApiClient.NvdPage(List.of(), 10, 0, 10));
        assertEquals("failed", nvd.syncNvd(48).status());
        assertTrue(watermarks.completedUntil(key(changed)).isEmpty());
        assertEquals(previous.toEpochMilli(), watermarks.completedUntil(key(original)).orElseThrow().toEpochMilli());
        when(provider.fetchPage(anyInt(), any(), any(), any(), any())).thenAnswer(call -> {
            assertEquals(48, Duration.between(call.getArgument(1), call.getArgument(2)).toHours());
            return new NvdApiClient.NvdPage(List.of(), 0, 0, 0);
        });
        assertEquals("ok", nvd.syncNvd(48).status());
        assertTrue(watermarks.completedUntil(key(changed)).isPresent());
    }

    private static String key(NvdFilters value) {
        return "nvd:" + org.springframework.util.DigestUtils.md5DigestAsHex(value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
}
