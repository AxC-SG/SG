package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.task.TaskExecutor;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class CsafSyncServiceTest {
    @Mock VulnerabilitySourceFilterConfigService filterConfig;
    @Mock TenantService tenantService;
    @Mock TaskExecutor executor;
    @Mock VulnerabilitySyncRunService runs;
    @Mock VulnerabilityIngestionEffectsService effects;
    @Mock CsafDiscoveryService discovery;
    @Mock CsafDocumentFetcher fetcher;
    @Mock CsafDocumentIngestor ingestor;
    @Mock VulnerabilityRepository vulnerabilities;

    @Test
    void emptyMicrosoftDiscoveryFailsRunWithoutIngestingOrApplyingEffects() {
        assertEmptyDiscoveryFails(CsafProvider.MICROSOFT);
    }

    @Test
    void emptyRedhatDiscoveryFailsRunWithoutIngestingOrApplyingEffects() {
        assertEmptyDiscoveryFails(CsafProvider.REDHAT);
    }

    @Test
    void allMicrosoftDocumentFetchesFailTheRun() {
        assertAllDocumentFetchesFail(CsafProvider.MICROSOFT);
    }

    @Test
    void allRedhatDocumentFetchesFailTheRun() {
        assertAllDocumentFetchesFail(CsafProvider.REDHAT);
    }

    @Test
    void oneSuccessfulDocumentRetainsPartialSuccessWithFailureCount() {
        SyncRun run = new SyncRun();
        when(runs.createRunningRun("CSAF_REDHAT")).thenReturn(run);
        CsafDistributionSet distributions = new CsafDistributionSet("https://example.test/advisories", "https://example.test/vex");
        when(discovery.discoverDistributions(CsafProvider.REDHAT)).thenReturn(distributions);
        var documents = List.of(new CsafDocumentRef("https://example.test/advisories/one.json", false),
                new CsafDocumentRef("https://example.test/advisories/two.json", false));
        when(discovery.collectDocumentRefs(distributions, CsafProvider.REDHAT)).thenReturn(documents);
        when(fetcher.fetch(documents.get(0).url())).thenReturn(CsafDocumentFetchResult.failure(1, "HTTP_ERROR", "Unavailable"));
        when(fetcher.fetch(documents.get(1).url())).thenReturn(CsafDocumentFetchResult.success("{}", 1));
        when(ingestor.ingestDocument(eq(CsafProvider.REDHAT), any(), eq(documents.get(1).url()), eq(false), any(), any()))
                .thenReturn(new CsafIngestionCounters(0, 0, java.util.Set.of()));
        CsafSyncService service = new CsafSyncService(filterConfig, tenantService, executor, runs, effects,
                discovery, fetcher, ingestor, new ObjectMapper(), vulnerabilities);
        ReflectionTestUtils.setField(service, "csafMaxDocumentsPerSync", 10);

        var result = service.syncRedhatCsaf();

        assertEquals("ok", result.status());
        assertEquals(1, result.fetched());
        verify(runs).completeRun(eq(run), eq("completed"), eq(1), eq(0), eq(0), eq(1), contains("documentsFailed=1"));
    }

    private void assertEmptyDiscoveryFails(CsafProvider provider) {
        SyncRun run = new SyncRun();
        when(runs.createRunningRun(provider == CsafProvider.MICROSOFT ? "CSAF_MICROSOFT" : "CSAF_REDHAT"))
                .thenReturn(run);
        CsafDistributionSet distributions = new CsafDistributionSet("https://example.test/advisories", "https://example.test/vex");
        when(discovery.discoverDistributions(provider)).thenReturn(distributions);
        when(discovery.collectDocumentRefs(distributions, provider)).thenReturn(List.of());
        CsafSyncService service = new CsafSyncService(filterConfig, tenantService, executor, runs, effects,
                discovery, fetcher, ingestor, new ObjectMapper(), vulnerabilities);
        ReflectionTestUtils.setField(service, "csafMaxDocumentsPerSync", 10);

        var result = provider == CsafProvider.MICROSOFT ? service.syncMicrosoftCsaf() : service.syncRedhatCsaf();

        assertEquals("failed", result.status());
        assertEquals(0, result.fetched());
        assertTrue(result.message().contains("no documents"));
        verify(runs).completeRun(eq(run), eq("failed"), eq(0), eq(0), eq(0), eq(0), contains("no documents"));
        verifyNoInteractions(fetcher, ingestor, effects);
    }

    private void assertAllDocumentFetchesFail(CsafProvider provider) {
        SyncRun run = new SyncRun();
        when(runs.createRunningRun(provider == CsafProvider.MICROSOFT ? "CSAF_MICROSOFT" : "CSAF_REDHAT"))
                .thenReturn(run);
        CsafDistributionSet distributions = new CsafDistributionSet("https://example.test/advisories", "https://example.test/vex");
        when(discovery.discoverDistributions(provider)).thenReturn(distributions);
        var documents = List.of(new CsafDocumentRef("https://example.test/advisories/one.json", false),
                new CsafDocumentRef("https://example.test/advisories/two.json", false));
        when(discovery.collectDocumentRefs(distributions, provider)).thenReturn(documents);
        if (provider == CsafProvider.MICROSOFT) {
            when(vulnerabilities.findAllCveExternalIds()).thenReturn(List.of());
        }
        for (CsafDocumentRef document : documents) {
            when(fetcher.fetch(document.url())).thenReturn(CsafDocumentFetchResult.failure(1, "HTTP_ERROR", "Unavailable"));
        }
        CsafSyncService service = new CsafSyncService(filterConfig, tenantService, executor, runs, effects,
                discovery, fetcher, ingestor, new ObjectMapper(), vulnerabilities);
        ReflectionTestUtils.setField(service, "csafMaxDocumentsPerSync", 10);

        var result = provider == CsafProvider.MICROSOFT ? service.syncMicrosoftCsaf() : service.syncRedhatCsaf();

        assertEquals("failed", result.status());
        assertEquals(0, result.fetched());
        assertTrue(result.message().contains("every discovered document"));
        verify(runs).completeRun(eq(run), eq("failed"), eq(0), eq(0), eq(0), eq(2), contains("documentsFailed=2"));
        verifyNoInteractions(ingestor, effects);
    }
}
