package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.NvdApiClient;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.dto.SyncTriggerResponse;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRuleRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.service.IdentityGraphService;
import com.prototype.vulnwatch.service.ObservationIngestionService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import java.time.Instant;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.task.TaskExecutor;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class NvdSyncServiceTest {

    @Mock
    private NvdApiClient nvdApiClient;

    @Mock
    private VulnerabilityRepository vulnerabilityRepository;

    @Mock
    private VulnerabilityRuleRepository vulnerabilityRuleRepository;

    @Mock
    private VulnerabilityTargetRepository vulnerabilityTargetRepository;

    @Mock
    private IdentityGraphService identityGraphService;

    @Mock
    private ObservationIngestionService observationIngestionService;

    @Mock
    private VulnerabilitySourceFilterConfigService vulnerabilitySourceFilterConfigService;

    @Mock
    private TaskExecutor ingestionExecutor;

    @Mock
    private VulnerabilitySyncRunService syncRunService;

    @Mock
    private VulnerabilityIngestionEffectsService effectsService;

    @Mock
    private VulnerabilityIngestionCommonSupport support;

    @Mock
    private FeedWatermarkService feedWatermarks;

    @Mock
    private FeedCoverageLedgerService coverageLedger;

    private NvdSyncService service;

    @BeforeEach
    void setUp() {
        service = new NvdSyncService(
                nvdApiClient,
                vulnerabilityRepository,
                vulnerabilityRuleRepository,
                vulnerabilityTargetRepository,
                identityGraphService,
                observationIngestionService,
                vulnerabilitySourceFilterConfigService,
                (TenantService) null,
                ingestionExecutor,
                syncRunService,
                effectsService,
                support,
                new ObjectMapper(), feedWatermarks, coverageLedger
        );
        ReflectionTestUtils.setField(service, "defaultNvdLookbackHours", 24);
    }

    @Test
    void triggerNvdSyncPersistsAcceptedParametersWithoutExecutorDispatch() {
        SyncRun run=run("NVD");
        when(syncRunService.prepareQueuedRun("NVD",List.of("NVD","NVD_FULL"),Map.of("triggerMode","incremental","lookbackHours",12)))
                .thenReturn(new VulnerabilitySyncRunService.TriggerDecision(run,true));
        assertEquals("queued",service.triggerNvdSync(12).status());
        org.mockito.Mockito.verifyNoInteractions(ingestionExecutor);
        verify(syncRunService,org.mockito.Mockito.never()).markRunningIfQueued(any());
    }

    @Test
    void historicalWindowRejectsInvalidBoundsBeforeQueuing() {
        Instant now = Instant.now();
        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> service.triggerNvdHistoricalWindow(now.minus(Duration.ofDays(121)), now));
        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> service.triggerNvdHistoricalWindow(now, now));
        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> service.triggerNvdHistoricalWindow(now.minus(Duration.ofHours(1)), now.plus(Duration.ofHours(1))));
        verifyNoInteractions(syncRunService);
    }

    @Test
    void queuedHistoricalWindowRecordsOnlyItsScopeAndNeverMovesIncrementalWatermark() {
        UUID runId = UUID.randomUUID();
        Instant from = Instant.parse("2025-01-01T00:00:00Z");
        Instant to = from.plus(Duration.ofDays(30));
        SyncRun run = run("NVD");
        ReflectionTestUtils.setField(run, "id", runId);
        run.setMetadataJson("{\"triggerMode\":\"historical_window\",\"from\":\"" + from + "\",\"to\":\"" + to + "\"}");
        var filters = new VulnerabilitySourceFilterConfigService.NvdFilters(null, false, false, null, null);
        when(support.hasText(any())).thenAnswer(invocation -> {
            String value = invocation.getArgument(0, String.class);
            return value != null && !value.isBlank();
        });
        when(syncRunService.markRunning(runId)).thenReturn(run);
        when(vulnerabilitySourceFilterConfigService.resolvePlatformNvdFilters()).thenReturn(filters);
        when(syncRunService.nvdFiltersMetadata(eq(filters), eq(from), eq(to))).thenReturn(Map.of());
        when(nvdApiClient.fetchPage(eq(0), eq(from), eq(to), any(NvdApiClient.NvdQueryFilters.class), isNull()))
                .thenReturn(new NvdApiClient.NvdPage(List.of(), 0, 0, 0));

        service.executeQueuedNvdSyncAsync(runId);

        verify(coverageLedger).observeNvdInterval(eq(runId), any(), eq(from), eq(to), eq(0), eq(Set.of()));
        verify(syncRunService).completeRun(run, "completed", 0, 0, 0, 0, null);
        org.mockito.Mockito.verify(feedWatermarks, org.mockito.Mockito.never()).complete(any(), any());
    }

    @Test
    void duplicateCvePageFailsHistoricalWindowWithoutCoverageEvidence() {
        UUID runId = UUID.randomUUID();
        Instant from = Instant.parse("2025-01-01T00:00:00Z");
        Instant to = from.plus(Duration.ofDays(1));
        SyncRun run = run("NVD");
        ReflectionTestUtils.setField(run, "id", runId);
        run.setMetadataJson("{\"triggerMode\":\"historical_window\",\"from\":\"" + from + "\",\"to\":\"" + to + "\"}");
        var filters = new VulnerabilitySourceFilterConfigService.NvdFilters(null, false, false, null, null);
        var cve = new NvdApiClient.NvdRecord("CVE-2025-12345", null, null, null, null,
                null, null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, List.of(), null);
        when(support.hasText(any())).thenAnswer(invocation -> {
            String value = invocation.getArgument(0, String.class);
            return value != null && !value.isBlank();
        });
        when(syncRunService.markRunning(runId)).thenReturn(run);
        when(vulnerabilitySourceFilterConfigService.resolvePlatformNvdFilters()).thenReturn(filters);
        when(syncRunService.nvdFiltersMetadata(eq(filters), eq(from), eq(to))).thenReturn(Map.of());
        when(nvdApiClient.fetchPage(eq(0), eq(from), eq(to), any(NvdApiClient.NvdQueryFilters.class), isNull()))
                .thenReturn(new NvdApiClient.NvdPage(List.of(cve, cve), 2, 0, 2));

        service.executeQueuedNvdSyncAsync(runId);

        verify(syncRunService).completeRun(eq(run), eq("failed"), eq(0), eq(0), eq(0), eq(0),
                org.mockito.ArgumentMatchers.contains("duplicate CVE identifier"));
        verifyNoInteractions(coverageLedger, observationIngestionService, feedWatermarks);
    }

    @Test
    void malformedQueuedHistoricalWindowFailsWithoutFetching() {
        UUID runId = UUID.randomUUID();
        SyncRun run = run("NVD");
        run.setMetadataJson("{\"triggerMode\":\"historical_window\",\"from\":\"not-a-date\"}");
        when(support.hasText(any())).thenReturn(true);
        when(syncRunService.markRunning(runId)).thenReturn(run);

        service.executeQueuedNvdSyncAsync(runId);

        verify(syncRunService).completeRun(run, "failed", 0, 0, 0, 0, "Invalid NVD historical window");
        verifyNoInteractions(nvdApiClient, coverageLedger, feedWatermarks);
    }

    @Test
    void executeQueuedNvdSyncUsesQueuedLookbackHours() {
        UUID runId = UUID.randomUUID();
        SyncRun run = run("NVD");
        ReflectionTestUtils.setField(run, "id", runId);
        run.setMetadataJson("{\"lookbackHours\":12}");
        VulnerabilitySourceFilterConfigService.NvdFilters filters =
                new VulnerabilitySourceFilterConfigService.NvdFilters(null, false, false, null, null);
        AtomicReference<Instant> startRef = new AtomicReference<>();
        AtomicReference<Instant> endRef = new AtomicReference<>();

        when(support.hasText(any())).thenAnswer(invocation -> {
            String value = invocation.getArgument(0, String.class);
            return value != null && !value.trim().isEmpty();
        });
        when(syncRunService.markRunning(runId)).thenReturn(run);
        when(vulnerabilitySourceFilterConfigService.resolvePlatformNvdFilters()).thenReturn(filters);
        when(syncRunService.nvdFiltersMetadata(eq(filters), any(), any())).thenReturn(Map.of());
        when(nvdApiClient.fetchPage(eq(0), any(), any(), any(NvdApiClient.NvdQueryFilters.class), isNull()))
                .thenAnswer(invocation -> {
                    startRef.set(invocation.getArgument(1, Instant.class));
                    endRef.set(invocation.getArgument(2, Instant.class));
                    return new NvdApiClient.NvdPage(List.of(), 0, 0, 0);
                });

        service.executeQueuedNvdSyncAsync(runId);

        assertEquals(12L, java.time.Duration.between(startRef.get(), endRef.get()).toHours());
        verify(syncRunService).completeRun(run, "completed", 0, 0, 0, 0, null);
    }

    @Test
    void coverageWriteFailureFailsRunWithoutAdvancingWatermark() {
        UUID runId = UUID.randomUUID();
        SyncRun run = run("NVD");
        ReflectionTestUtils.setField(run, "id", runId);
        var filters = new VulnerabilitySourceFilterConfigService.NvdFilters(null, false, false, null, null);
        when(syncRunService.markRunning(runId)).thenReturn(run);
        when(vulnerabilitySourceFilterConfigService.resolvePlatformNvdFilters()).thenReturn(filters);
        when(syncRunService.nvdFiltersMetadata(eq(filters), any(), any())).thenReturn(Map.of());
        when(nvdApiClient.fetchPage(eq(0), any(), any(), any(NvdApiClient.NvdQueryFilters.class), isNull()))
                .thenReturn(new NvdApiClient.NvdPage(List.of(), 0, 0, 0));
        org.mockito.Mockito.doThrow(new IllegalStateException("database unavailable"))
                .when(coverageLedger).observeNvdInterval(eq(runId), any(), any(), any(), eq(0), eq(Set.of()));

        service.executeQueuedNvdSyncAsync(runId);

        verify(syncRunService).completeRun(eq(run), eq("failed"), eq(0), eq(0), eq(0), eq(0),
                eq("NVD interval coverage evidence could not be recorded"));
        org.mockito.Mockito.verify(feedWatermarks, org.mockito.Mockito.never()).complete(any(), any());
    }

    @Test
    void executeQueuedNvdFullSyncUsesQueuedApiKeyOverride() {
        UUID runId = UUID.randomUUID();
        SyncRun run = run("NVD_FULL");
        ReflectionTestUtils.setField(run, "id", runId);
        var encryption=new com.prototype.vulnwatch.service.CredentialEncryptionService("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        service.configureEncryption(encryption);
        run.setMetadataJson("{\"encryptedApiKeyOverride\":\""+encryption.encrypt("override-key")+"\"}");
        VulnerabilitySourceFilterConfigService.NvdFilters filters =
                new VulnerabilitySourceFilterConfigService.NvdFilters(null, false, false, null, null);
        AtomicReference<String> apiKeyOverrideRef = new AtomicReference<>();

        when(support.hasText(any())).thenAnswer(invocation -> {
            String value = invocation.getArgument(0, String.class);
            return value != null && !value.trim().isEmpty();
        });
        when(syncRunService.markRunning(runId)).thenReturn(run);
        when(nvdApiClient.hasApiKey("override-key")).thenReturn(true);
        when(vulnerabilitySourceFilterConfigService.resolvePlatformNvdFilters()).thenReturn(filters);
        when(syncRunService.nvdFiltersMetadata(eq(filters), isNull(), isNull())).thenReturn(Map.of());
        when(nvdApiClient.fetchPage(eq(0), isNull(), isNull(), any(NvdApiClient.NvdQueryFilters.class), eq("override-key")))
                .thenAnswer(invocation -> {
                    apiKeyOverrideRef.set(invocation.getArgument(4, String.class));
                    return new NvdApiClient.NvdPage(List.of(), 0, 0, 0);
                });

        service.executeQueuedNvdFullSyncAsync(runId);

        assertEquals("override-key", apiKeyOverrideRef.get());
        verify(syncRunService).completeRun(run, "completed", 0, 0, 0, 0, null);
    }

    @Test
    void executeQueuedNvdFullSyncFallsBackToConfiguredApiKeyWhenMetadataIsBlank() {
        UUID runId = UUID.randomUUID();
        SyncRun run = run("NVD_FULL");
        ReflectionTestUtils.setField(run, "id", runId);
        run.setMetadataJson("{\"apiKeyOverride\":\"   \"}");

        when(support.hasText(any())).thenAnswer(invocation -> {
            String value = invocation.getArgument(0, String.class);
            return value != null && !value.trim().isEmpty();
        });
        when(syncRunService.markRunning(runId)).thenReturn(run);
        when(nvdApiClient.hasApiKey(null)).thenReturn(false);

        service.executeQueuedNvdFullSyncAsync(runId);

        verify(syncRunService).completeRun(
                run,
                "failed",
                0,
                0,
                0,
                0,
                "NVD full sync requires an API key from the UI or NVD_API_KEY environment configuration"
        );
    }

    private SyncRun run(String syncType) {
        SyncRun run = new SyncRun();
        run.setSyncType(syncType);
        run.setStatus("queued");
        return run;
    }

    @Test
    void paginationRejectsChangingTotalBetweenPages() {
        NvdSyncService.validateNvdPage(new NvdApiClient.NvdPage(List.of(), 0, 0, 0), 0, null);
        assertThrows(IllegalStateException.class, () -> NvdSyncService.validateNvdPage(
                new NvdApiClient.NvdPage(List.of(), 1, 0, 0), 1, 2));
    }

    @Test
    void paginationRejectsIncompleteAndMisalignedPages() {
        assertThrows(IllegalStateException.class, () -> NvdSyncService.validateNvdPage(
                new NvdApiClient.NvdPage(List.of(), 1, 0, 1), 0, null));
        assertThrows(IllegalStateException.class, () -> NvdSyncService.validateNvdPage(
                new NvdApiClient.NvdPage(List.of(), 1, 1, 0), 0, null));
    }

    @Test
    void paginationCompletionRequiresExactReportedTotal() {
        NvdSyncService.validateNvdCompletion(0, 0);
        NvdSyncService.validateNvdCompletion(4, 4);
        assertThrows(IllegalStateException.class, () -> NvdSyncService.validateNvdCompletion(3, 4));
        assertThrows(IllegalStateException.class, () -> NvdSyncService.validateNvdCompletion(0, null));
    }

    @Test
    void paginationRejectsDuplicateAndInvalidCveIdentitiesAcrossPages() {
        var seen = new HashSet<String>();

        NvdSyncService.validateNvdIdentity("CVE-2025-12345", seen);
        assertEquals(1, seen.size());
        assertThrows(IllegalStateException.class,
                () -> NvdSyncService.validateNvdIdentity("CVE-2025-12345", seen));
        assertThrows(IllegalStateException.class,
                () -> NvdSyncService.validateNvdIdentity("NOT-A-CVE", new HashSet<>()));
        assertThrows(IllegalStateException.class,
                () -> NvdSyncService.validateNvdIdentity(null, new HashSet<>()));
    }
}
