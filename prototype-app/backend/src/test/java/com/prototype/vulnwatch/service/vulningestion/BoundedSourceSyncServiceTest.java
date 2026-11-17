package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.EuvdApiClient;
import com.prototype.vulnwatch.client.JvnApiClient;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.ObservationIngestionService;
import com.prototype.vulnwatch.service.VulnerabilityIntelligenceService;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.core.task.TaskExecutor;
import org.springframework.test.util.ReflectionTestUtils;

class BoundedSourceSyncServiceTest {
    private final ObservationIngestionService observations = mock(ObservationIngestionService.class);
    private final VulnerabilitySyncRunService runs = mock(VulnerabilitySyncRunService.class);
    private final VulnerabilityIngestionEffectsService effects = mock(VulnerabilityIngestionEffectsService.class);
    private final TaskExecutor executor = mock(TaskExecutor.class);
    private final VulnerabilityRepository vulnerabilities = mock(VulnerabilityRepository.class);

    @Test
    void euvdPageCapFailsRatherThanCompleting() {
        EuvdApiClient client = mock(EuvdApiClient.class);
        var service = new EuvdSyncService(client, observations, runs, effects, executor, vulnerabilities);
        ReflectionTestUtils.setField(service, "maxPagesPerSync", 1);
        when(runs.createRunningRun("EUVD")).thenReturn(new SyncRun());
        when(client.perPage()).thenReturn(1);
        when(client.fetchPage(0)).thenReturn(new EuvdApiClient.EuvdPage(
                List.of(new EuvdApiClient.EuvdRecord("EUVD-1", "CVE-2026-1000", "title", null,
                        null, null, null, null, null, null, null, null)), 2, 0, 1));
        when(observations.upsertObservation(any())).thenReturn(
                new VulnerabilityIntelligenceService.ObservationUpsertResult(null, false, false));

        assertEquals("failed", service.syncEuvd().status());
        verify(runs).completeRun(any(), org.mockito.ArgumentMatchers.eq("failed"),
                org.mockito.ArgumentMatchers.eq(1), anyInt(), anyInt(), anyInt(), any());
    }

    @Test
    void jvnPageCapFailsRatherThanCompleting() {
        JvnApiClient client = mock(JvnApiClient.class);
        var service = new JvnSyncService(client, observations, runs, effects, executor, vulnerabilities);
        ReflectionTestUtils.setField(service, "maxPagesPerSync", 1);
        when(runs.createRunningRun("JVN")).thenReturn(new SyncRun());
        when(client.perPage()).thenReturn(1);
        when(client.fetchPage(1)).thenReturn(new JvnApiClient.JvnPage(
                List.of(new JvnApiClient.JvnRecord("JVN-1", "CVE-2026-1000", "title", null,
                        null, null, null, null, null, null, null)), 2, 1, 1));
        when(observations.upsertObservation(any())).thenReturn(
                new VulnerabilityIntelligenceService.ObservationUpsertResult(null, false, false));

        assertEquals("failed", service.syncJvn().status());
        verify(runs).completeRun(any(), org.mockito.ArgumentMatchers.eq("failed"),
                org.mockito.ArgumentMatchers.eq(1), anyInt(), anyInt(), anyInt(), any());
    }

    @Test
    void malformedFirstPagesFailRunsWithoutPublishingEffects() {
        EuvdApiClient euvdClient = mock(EuvdApiClient.class);
        JvnApiClient jvnClient = mock(JvnApiClient.class);
        var euvd = new EuvdSyncService(euvdClient, observations, runs, effects, executor, vulnerabilities);
        var jvn = new JvnSyncService(jvnClient, observations, runs, effects, executor, vulnerabilities);
        when(runs.createRunningRun("EUVD")).thenReturn(new SyncRun());
        when(runs.createRunningRun("JVN")).thenReturn(new SyncRun());
        when(euvdClient.fetchPage(0)).thenThrow(new IllegalArgumentException("Invalid EUVD envelope"));
        when(jvnClient.fetchPage(1)).thenThrow(new IllegalArgumentException("Invalid JVN envelope"));

        assertEquals("failed", euvd.syncEuvd().status());
        assertEquals("failed", jvn.syncJvn().status());
        verify(runs, org.mockito.Mockito.times(2)).completeRun(any(), org.mockito.ArgumentMatchers.eq("failed"),
                org.mockito.ArgumentMatchers.eq(0), anyInt(), anyInt(), anyInt(), any());
        verifyNoInteractions(observations, effects);
    }

    @Test
    void changingReportedTotalsFailBeforeTheSecondPageIsIngested() {
        EuvdApiClient euvdClient = mock(EuvdApiClient.class);
        JvnApiClient jvnClient = mock(JvnApiClient.class);
        var euvd = new EuvdSyncService(euvdClient, observations, runs, effects, executor, vulnerabilities);
        var jvn = new JvnSyncService(jvnClient, observations, runs, effects, executor, vulnerabilities);
        ReflectionTestUtils.setField(euvd, "maxPagesPerSync", 2);
        ReflectionTestUtils.setField(jvn, "maxPagesPerSync", 2);
        when(runs.createRunningRun("EUVD")).thenReturn(new SyncRun());
        when(runs.createRunningRun("JVN")).thenReturn(new SyncRun());
        when(euvdClient.perPage()).thenReturn(1);
        when(jvnClient.perPage()).thenReturn(1);
        var euvdRecord = new EuvdApiClient.EuvdRecord("EUVD-1", "CVE-2026-1000", "title", null,
                null, null, null, null, null, null, null, null);
        var jvnRecord = new JvnApiClient.JvnRecord("JVNDB-2026-1", "CVE-2026-1000", "title", null,
                null, null, null, null, null, null, null);
        when(euvdClient.fetchPage(0)).thenReturn(new EuvdApiClient.EuvdPage(List.of(euvdRecord), 3, 0, 1));
        when(euvdClient.fetchPage(1)).thenReturn(new EuvdApiClient.EuvdPage(List.of(euvdRecord), 2, 1, 1));
        when(jvnClient.fetchPage(1)).thenReturn(new JvnApiClient.JvnPage(List.of(jvnRecord), 3, 1, 1));
        when(jvnClient.fetchPage(2)).thenReturn(new JvnApiClient.JvnPage(List.of(jvnRecord), 2, 2, 1));
        when(observations.upsertObservation(any())).thenReturn(
                new VulnerabilityIntelligenceService.ObservationUpsertResult(null, false, false));

        assertEquals("failed", euvd.syncEuvd().status());
        assertEquals("failed", jvn.syncJvn().status());
        verify(observations, org.mockito.Mockito.times(2)).upsertObservation(any());
        verify(runs, org.mockito.Mockito.times(2)).completeRun(any(), org.mockito.ArgumentMatchers.eq("failed"),
                org.mockito.ArgumentMatchers.eq(1), anyInt(), anyInt(), anyInt(), any());
        verifyNoInteractions(effects);
    }

    @Test
    void repeatedSourceRecordsAcrossPagesFailBeforeTheSecondPageIsIngested() {
        EuvdApiClient euvdClient = mock(EuvdApiClient.class);
        JvnApiClient jvnClient = mock(JvnApiClient.class);
        var euvd = new EuvdSyncService(euvdClient, observations, runs, effects, executor, vulnerabilities);
        var jvn = new JvnSyncService(jvnClient, observations, runs, effects, executor, vulnerabilities);
        ReflectionTestUtils.setField(euvd, "maxPagesPerSync", 2);
        ReflectionTestUtils.setField(jvn, "maxPagesPerSync", 2);
        when(runs.createRunningRun("EUVD")).thenReturn(new SyncRun());
        when(runs.createRunningRun("JVN")).thenReturn(new SyncRun());
        when(euvdClient.perPage()).thenReturn(1);
        when(jvnClient.perPage()).thenReturn(1);
        var euvdRecord = new EuvdApiClient.EuvdRecord("EUVD-1", "CVE-2026-1000", "title", null,
                null, null, null, null, null, null, null, null);
        var jvnRecord = new JvnApiClient.JvnRecord("JVNDB-2026-1", "CVE-2026-1000", "title", null,
                null, null, null, null, null, null, null);
        when(euvdClient.fetchPage(0)).thenReturn(new EuvdApiClient.EuvdPage(List.of(euvdRecord), 2, 0, 1));
        when(euvdClient.fetchPage(1)).thenReturn(new EuvdApiClient.EuvdPage(List.of(euvdRecord), 2, 1, 1));
        when(jvnClient.fetchPage(1)).thenReturn(new JvnApiClient.JvnPage(List.of(jvnRecord), 2, 1, 1));
        when(jvnClient.fetchPage(2)).thenReturn(new JvnApiClient.JvnPage(List.of(jvnRecord), 2, 2, 1));
        when(observations.upsertObservation(any())).thenReturn(
                new VulnerabilityIntelligenceService.ObservationUpsertResult(null, false, false));

        assertEquals("failed", euvd.syncEuvd().status());
        assertEquals("failed", jvn.syncJvn().status());
        verify(observations, org.mockito.Mockito.times(2)).upsertObservation(any());
        verify(runs, org.mockito.Mockito.times(2)).completeRun(any(), org.mockito.ArgumentMatchers.eq("failed"),
                org.mockito.ArgumentMatchers.eq(1), anyInt(), anyInt(), anyInt(), any());
        verifyNoInteractions(effects);
    }

    @Test
    void recordsBeyondReportedTotalFailBeforeStagingThePage() {
        EuvdApiClient client = mock(EuvdApiClient.class);
        var service = new EuvdSyncService(client, observations, runs, effects, executor, vulnerabilities);
        when(runs.createRunningRun("EUVD")).thenReturn(new SyncRun());
        when(client.fetchPage(0)).thenReturn(new EuvdApiClient.EuvdPage(List.of(
                new EuvdApiClient.EuvdRecord("EUVD-1", "CVE-2026-1000", "title", null,
                        null, null, null, null, null, null, null, null),
                new EuvdApiClient.EuvdRecord("EUVD-2", "CVE-2026-1001", "title", null,
                        null, null, null, null, null, null, null, null)), 1, 0, 2));

        assertEquals("failed", service.syncEuvd().status());
        verifyNoInteractions(observations, effects);
    }

    @Test
    void explicitZeroTotalWithRecordsFailsButAbsentTotalCanCompleteShortPage() {
        EuvdApiClient client = mock(EuvdApiClient.class);
        var service = new EuvdSyncService(client, observations, runs, effects, executor, vulnerabilities);
        when(runs.createRunningRun("EUVD")).thenReturn(new SyncRun());
        var record = new EuvdApiClient.EuvdRecord("EUVD-1", "CVE-2026-1000", "title", null,
                null, null, null, null, null, null, null, null);
        when(client.fetchPage(0)).thenReturn(new EuvdApiClient.EuvdPage(List.of(record), 0, 0, 2),
                new EuvdApiClient.EuvdPage(List.of(record), null, 0, 2));
        when(observations.upsertObservation(any())).thenReturn(
                new VulnerabilityIntelligenceService.ObservationUpsertResult(null, false, false));

        assertEquals("failed", service.syncEuvd().status());
        verifyNoInteractions(observations, effects);
        assertEquals("ok", service.syncEuvd().status());
        verify(observations).upsertObservation(any());
        verify(runs).completeRun(any(), org.mockito.ArgumentMatchers.eq("completed"),
                org.mockito.ArgumentMatchers.eq(1), anyInt(), anyInt(), anyInt(), any());
    }

    @Test
    void laterExplicitZeroCannotContradictEarlierUnknownTotalPage() {
        EuvdApiClient client = mock(EuvdApiClient.class);
        var service = new EuvdSyncService(client, observations, runs, effects, executor, vulnerabilities);
        ReflectionTestUtils.setField(service, "maxPagesPerSync", 2);
        when(runs.createRunningRun("EUVD")).thenReturn(new SyncRun());
        when(client.perPage()).thenReturn(1);
        var record = new EuvdApiClient.EuvdRecord("EUVD-1", "CVE-2026-1000", "title", null,
                null, null, null, null, null, null, null, null);
        when(client.fetchPage(0)).thenReturn(new EuvdApiClient.EuvdPage(List.of(record), null, 0, 1));
        when(client.fetchPage(1)).thenReturn(new EuvdApiClient.EuvdPage(List.of(), 0, 1, 1));
        when(observations.upsertObservation(any())).thenReturn(
                new VulnerabilityIntelligenceService.ObservationUpsertResult(null, false, false));

        assertEquals("failed", service.syncEuvd().status());
        verify(observations).upsertObservation(any());
        verify(runs).completeRun(any(), org.mockito.ArgumentMatchers.eq("failed"),
                org.mockito.ArgumentMatchers.eq(1), anyInt(), anyInt(), anyInt(), any());
        verifyNoInteractions(effects);
    }
}
