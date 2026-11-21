package com.prototype.vulnwatch.service.vulningestion;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.prototype.vulnwatch.client.EuvdApiClient;
import com.prototype.vulnwatch.client.JvnApiClient;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.service.IntelligencePublicationService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.server.ResponseStatusException;

@PostgresIntegrationTest
@WithMockUser(roles = "PLATFORM_OWNER")
class FeedResumePostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB = LocalPostgresTestDatabase.provision("feed_resume");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DB);
    }

    @Autowired EuvdSyncService euvd;
    @Autowired JvnSyncService jvn;
    @Autowired GhsaSyncService ghsa;
    @Autowired CsafSyncService csaf;
    @Autowired VulnerabilitySyncRunService runs;
    @Autowired IntelligencePublicationService publication;
    @Autowired FeedWatermarkService watermarks;
    @Autowired JdbcTemplate jdbc;
    @MockitoBean EuvdApiClient euvdApi;
    @MockitoBean JvnApiClient jvnApi;
    @MockitoBean OutboundHttpClient outbound;
    @MockitoBean CsafDiscoveryService discovery;
    @MockitoBean CsafDocumentFetcher fetcher;
    @MockitoBean VulnerabilitySourceFilterConfigService filters;

    @Test
    void euvdResumesTheFrozenUpdatedDateWindow() {
        var scope = new EuvdApiClient.Scan("https://euvd.enisa.europa.eu/api/search", 1, "2026-10-01", "2026-10-31");
        when(euvdApi.scan()).thenReturn(scope);
        when(euvdApi.fetchPage(0, scope)).thenReturn(new EuvdApiClient.EuvdPage(List.of(new EuvdApiClient.EuvdRecord(
                "EUVD-2026-91041", "CVE-2026-91041", "Fixture", null, null, null, null, null, null, null, null, "{}")), 2, 0, 1));
        doThrow(new WorkerStopped()).when(euvdApi).fetchPage(1, scope);
        UUID id = TenantContext.runAsPlatform(() -> euvd.triggerEuvdSync().runId());
        interrupt(id, euvd::executeEuvdSyncAsync);

        doReturn(new EuvdApiClient.EuvdPage(List.of(new EuvdApiClient.EuvdRecord(
                "EUVD-2026-91042", "CVE-2026-91042", "Fixture", null, null, null, null, null, null, null, null, "{}")), 2, 1, 1))
                .when(euvdApi).fetchPage(1, scope);
        execute(id, euvd::executeEuvdSyncAsync);

        assertCompleted(id);
        verify(euvdApi).scan();
        verify(euvdApi).fetchPage(0, scope);
    }

    @Test
    void jvnResumesItsOriginalOffsetAndRejectsAnAlreadyStagedSourceId() {
        var scope = new JvnApiClient.Scan("https://jvndb.jvn.jp/api", 1);
        var record = new JvnApiClient.JvnRecord("JVNDB-2026-91043", "CVE-2026-91043", "Fixture",
                null, null, null, null, null, null, null, "{}");
        when(jvnApi.scan()).thenReturn(scope);
        when(jvnApi.fetchPage(1, scope)).thenReturn(new JvnApiClient.JvnPage(List.of(record), 2, 1, 1));
        doThrow(new WorkerStopped()).when(jvnApi).fetchPage(2, scope);
        UUID id = TenantContext.runAsPlatform(() -> jvn.triggerJvnSync().runId());
        interrupt(id, jvn::executeJvnSyncAsync);

        doReturn(new JvnApiClient.JvnPage(List.of(record), 2, 2, 1)).when(jvnApi).fetchPage(2, scope);
        execute(id, jvn::executeJvnSyncAsync);

        assertEquals("failed", status(id));
        assertEquals(1, observations(id));
        assertEquals(1, committedBatches(id));
        verify(jvnApi).scan();
        verify(jvnApi).fetchPage(1, scope);
    }

    @Test
    void ghsaResumesTheSavedLinkAndAdvancesOnlyItsOriginalFilterWatermark() throws Exception {
        when(filters.resolvePlatformGhsaFilters()).thenReturn(new VulnerabilitySourceFilterConfigService.GhsaFilters("high"));
        var first = new AtomicReference<String>();
        var next = new AtomicReference<String>();
        when(outbound.exchange(anyString(), eq(HttpMethod.GET), any(), eq(String.class), anyString(), any(), any()))
                .thenAnswer(call -> {
                    String requested = call.getArgument(0);
                    if (first.get() == null) {
                        first.set(requested);
                        next.set(requested + "&after=fixture");
                        return ResponseEntity.ok().header(HttpHeaders.LINK, "<" + next.get() + ">; rel=\"next\"")
                                .body(advisory("GHSA-AAAA-BBBB-CCCC", "CVE-2026-91044"));
                    }
                    throw new WorkerStopped();
                });
        UUID id = TenantContext.runAsPlatform(() -> ghsa.triggerGhsaSync().runId());
        interrupt(id, ghsa::executeGhsaSyncAsync);
        String scope = jdbc.queryForObject("select scope->>'coverageKey' from platform.feed_run_checkpoints where run_id=?", String.class, id);
        assertTrue(watermarks.completedUntil(scope).isEmpty());

        when(filters.resolvePlatformGhsaFilters()).thenReturn(new VulnerabilitySourceFilterConfigService.GhsaFilters("low"));
        doReturn(ResponseEntity.ok(advisory("GHSA-DDDD-EEEE-FFFF", "CVE-2026-91045")))
                .when(outbound).exchange(eq(next.get()), eq(HttpMethod.GET), any(), eq(String.class), anyString(), any(), any());
        execute(id, ghsa::executeGhsaSyncAsync);

        assertCompleted(id);
        assertTrue(first.get().contains("severity=high"));
        verify(filters).resolvePlatformGhsaFilters();
        verify(outbound).exchange(eq(first.get()), eq(HttpMethod.GET), any(), eq(String.class), anyString(), any(), any());
        assertTrue(watermarks.completedUntil(scope).isPresent());
    }

    @Test
    void csafResumesTheOriginalManifestAndKeepsFailedDocumentCoverageOutOfPublication() {
        var provider = CsafProvider.REDHAT;
        var roots = new CsafDistributionSet("https://example.test/advisories", "https://example.test/vex");
        var first = new CsafDocumentRef("https://example.test/advisories/one.json", false);
        var second = new CsafDocumentRef("https://example.test/advisories/two.json", false);
        when(discovery.discoverDistributions(provider)).thenReturn(roots);
        when(discovery.collectDocumentRefs(roots, provider)).thenReturn(List.of(first, second), List.of());
        when(fetcher.fetch(first.url(), provider.providerKey())).thenReturn(CsafDocumentFetchResult.success("""
                {"document":{"tracking":{"id":"one"}},"vulnerabilities":[{"cve":"CVE-2026-91046"}]}
                """, 1));
        doThrow(new WorkerStopped()).when(fetcher).fetch(second.url(), provider.providerKey());
        UUID id = TenantContext.runAsPlatform(() -> csaf.triggerRedhatCsafSync().runId());
        interrupt(id, csaf::executeRedhatCsafSyncAsync);

        doReturn(CsafDocumentFetchResult.failure(1, "HTTP_ERROR", "Unavailable"))
                .when(fetcher).fetch(second.url(), provider.providerKey());
        execute(id, csaf::executeRedhatCsafSyncAsync);

        assertEquals("partial", status(id));
        assertEquals(1, observations(id));
        assertEquals(2, committedBatches(id));
        verify(discovery).collectDocumentRefs(roots, provider);
        verify(fetcher).fetch(first.url(), provider.providerKey());
        assertThrows(ResponseStatusException.class,
                () -> TenantContext.runAsPlatform(() -> publication.createCandidate(List.of(id), "test-owner")));
    }

    private void interrupt(UUID id, Consumer<UUID> worker) {
        assertThrows(WorkerStopped.class, () -> execute(id, worker));
        assertEquals(1, committedBatches(id));
        assertEquals(1, observations(id));
        TenantContext.runAsPlatform(() -> {
            jdbc.update("update platform.sync_runs set lease_expires_at=now()-interval '1 second' where id=?", id);
            runs.recoverStaleRuns();
        });
    }

    private void execute(UUID id, Consumer<UUID> worker) {
        TenantContext.runAsPlatform(() -> {
            var claimed = runs.markRunningIfQueued(id).orElseThrow();
            try (var owner = runs.openAttempt(claimed)) { worker.accept(id); }
        });
    }

    private void assertCompleted(UUID id) {
        assertEquals("completed", status(id));
        assertEquals(2, observations(id));
        assertEquals(2, committedBatches(id));
    }

    private String status(UUID id) {
        return jdbc.queryForObject("select status from platform.sync_runs where id=?", String.class, id);
    }

    private int committedBatches(UUID id) {
        return jdbc.queryForObject("select next_batch from platform.feed_run_checkpoints where run_id=?", Integer.class, id);
    }

    private int observations(UUID id) {
        return jdbc.queryForObject("""
                select count(*) from platform.intelligence_staged_records where sync_run_id=? and kind='OBSERVATION'
                """, Integer.class, id);
    }

    private static String advisory(String ghsa, String cve) {
        return """
                [{"ghsa_id":"%s","cve_id":"%s","summary":"Fixture","severity":"high","vulnerabilities":[]}]
                """.formatted(ghsa, cve);
    }

    private static final class WorkerStopped extends Error {}
}
