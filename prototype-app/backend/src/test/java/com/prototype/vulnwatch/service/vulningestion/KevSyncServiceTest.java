package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.ObservationIngestionService;
import com.prototype.vulnwatch.service.VulnerabilityIntelligenceService;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.task.TaskExecutor;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;

@ExtendWith(MockitoExtension.class)
class KevSyncServiceTest {

    private static final String KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

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
    private OutboundHttpClient outboundHttpClient;

    @Mock
    private OutboundPolicyFactory outboundPolicyFactory;

    @Mock
    private VulnerabilityRepository vulnerabilityRepository;

    private KevSyncService service;

    @BeforeEach
    void setUp() {
        service = new KevSyncService(
                observationIngestionService,
                vulnerabilitySourceFilterConfigService,
                null,
                ingestionExecutor,
                syncRunService,
                effectsService,
                support,
                outboundHttpClient,
                outboundPolicyFactory,
                new ObjectMapper(),
                vulnerabilityRepository
        );
    }

    @Test
    void syncKevSendsBrowserLikeHeadersAndPersistsKevMetadata() throws Exception {
        SyncRun run = new SyncRun();
        run.setSyncType("KEV");
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId("CVE-2026-9999");
        VulnerabilitySourceFilterConfigService.KevFilters filters =
                new VulnerabilitySourceFilterConfigService.KevFilters(null, null, null, null, null, null, false);
        OutboundPolicy policy = new OutboundPolicy("kev", 0L, 1, 0L, 0L, Set.of(), false, true);
        AtomicReference<HttpEntity<?>> requestRef = new AtomicReference<>();

        when(syncRunService.createRunningRun("KEV")).thenReturn(run);
        when(vulnerabilitySourceFilterConfigService.resolvePlatformKevFilters()).thenReturn(filters);
        when(syncRunService.kevFiltersMetadata(filters)).thenReturn(Map.of());
        when(outboundPolicyFactory.forProvider("kev", 0L, null, null)).thenReturn(policy);
        when(observationIngestionService.upsertObservation(any())).thenReturn(
                new VulnerabilityIntelligenceService.ObservationUpsertResult(vulnerability, true, true)
        );
        when(support.parseLocalDateOrNull("2026-06-01")).thenReturn(java.time.LocalDate.parse("2026-06-01"));
        when(support.parseLocalDateOrNull("2026-06-15")).thenReturn(java.time.LocalDate.parse("2026-06-15"));
        doAnswer(invocation -> {
            requestRef.set(invocation.getArgument(2));
            return "{\"vulnerabilities\":[{\"cveID\":\"CVE-2026-9999\",\"vulnerabilityName\":\"Test KEV\",\"dateAdded\":\"2026-06-01\",\"dueDate\":\"2026-06-15\",\"requiredAction\":\"Patch now\"}]}";
        }).when(outboundHttpClient).execute(
                eq(KEV_URL),
                eq(HttpMethod.GET),
                any(HttpEntity.class),
                eq(String.class),
                eq("KEV feed request"),
                eq(policy),
                any(),
                any()
        );

        IngestionResult result = service.syncKev();

        assertEquals("ok", result.status());
        assertEquals(1, result.fetched());
        assertEquals(1, result.inserted());
        HttpEntity<?> request = requestRef.get();
        assertNotNull(request);
        List<String> accept = request.getHeaders().get("Accept");
        assertNotNull(accept);
        assertTrue(accept.stream().anyMatch(value -> value.contains("application/json")));
        assertEquals(
                "Mozilla/5.0 (compatible; VulnWatch/1.0; +https://www.cisa.gov/known-exploited-vulnerabilities-catalog)",
                request.getHeaders().getFirst("User-Agent")
        );
        assertEquals(java.time.LocalDate.parse("2026-06-01"), vulnerability.getKevDateAdded());
        assertEquals(java.time.LocalDate.parse("2026-06-15"), vulnerability.getKevDueDate());
        assertEquals("Patch now", vulnerability.getKevRequiredAction());
        verify(support).saveMetadata(vulnerability,"kev");
        verify(vulnerabilityRepository,never()).save(any());
        verify(effectsService).enqueueCveMetadataDeltas(any());
        verify(syncRunService).completeRun(run, "completed", 1, 1, 0, 0, null);
        verify(syncRunService, never()).completeRun(run, "failed", 1, 1, 0, 0, null);
    }
}
