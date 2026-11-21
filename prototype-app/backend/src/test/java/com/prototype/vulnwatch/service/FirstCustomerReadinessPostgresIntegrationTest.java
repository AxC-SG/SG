package com.prototype.vulnwatch.service;

import static com.prototype.vulnwatch.service.FirstCustomerQualificationMetrics.elapsedMillis;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.NvdApiClient;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.dto.AdvisoryBatchRequest;
import com.prototype.vulnwatch.dto.AdvisoryRequest;
import com.prototype.vulnwatch.service.vulningestion.KevSyncService;
import com.prototype.vulnwatch.service.vulningestion.NvdSyncService;
import com.prototype.vulnwatch.service.vulningestion.VulnerabilityQueuedRunWorkerService;
import com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@PostgresControllerIntegrationTest
@EnabledIfSystemProperty(named = "firstCustomerQualification", matches = "true")
@WithMockUser(roles = "PLATFORM_OWNER")
class FirstCustomerReadinessPostgresIntegrationTest {
    private static final int CVES = Integer.getInteger("firstCustomerCves", FirstCustomerCatalogFixture.CVES);
    private static final String OWNER = "qualification-owner";
    private static final String BASELINE = "CVE-2025-99999";
    private static final boolean RESUME = Boolean.getBoolean("firstCustomerResumeCatalog");
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            FirstCustomerQualificationMetrics.database("first_customer_readiness", RESUME);

    @Autowired private JdbcTemplate jdbc;
    @Autowired private NvdSyncService nvd;
    @Autowired private VulnerabilitySyncRunService runs;
    @Autowired private VulnerabilityQueuedRunWorkerService feedQueue;
    @Autowired private KevSyncService kev;
    @Autowired private VulnerabilityIngestionService advisories;
    @Autowired private IntelligencePublicationService publications;
    @Autowired private IntelligencePublicationProgressService progress;
    @MockitoBean private NvdApiClient provider;
    @MockitoBean private OutboundHttpClient outbound;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.intelligence.targeted-publication.enabled", () -> true);
        registry.add("app.demo-data.seed-tenant-slug", () -> "");
        registry.add("logging.level.com.prototype.vulnwatch.config.TenantAwareDataSource", () -> "ERROR");
        registry.add("spring.datasource.hikari.maximum-pool-size", () -> 10);
    }

    @Test
    void stageBuildAndRecoverAtomicPublicationAtCustomerVolume() throws Exception {
        int version = jdbc.queryForObject("select current_setting('server_version_num')::int", Integer.class);
        assertEquals(16, version / 10_000);
        jdbc.execute("create extension if not exists pg_stat_statements with schema public");
        UUID base = RESUME ? resumeBase() : publishBaseline();
        UUID run = RESUME ? resumeFeed() : stageCatalog();
        UUID candidate = RESUME ? alreadyApprovedCandidate(run, base) : null;
        if (candidate == null) {
            candidate = build(run);
            approve(candidate, base, "full-catalog");
            pauseInsidePublication(candidate, base);
        }
        try (var metrics = metrics("publication_resume")) {
            progress.control(candidate, "RESUME", OWNER);
            long elapsed = publishAndMeasureLock(metrics);
            var result = publications.candidate(candidate);
            assertEquals("PUBLISHED", result.get("status"), result::toString);
            assertEquals(CVES + 1L, catalogCount());
            assertEquals(2L * CVES, count("select count(*) from platform.vulnerability_targets"));
            assertTrue(count("select count(*) from platform.vulnerability_config_expr") >= CVES / 4L);
            assertEquals(2L, count("select generation from platform.intelligence_active_state"));
            metrics.mark("activated", "restart_ms=" + elapsed + " cves=" + CVES
                    + " release_journal_rows=" + count("select count(*) from platform.intelligence_release_changes"));
        }
    }

    private UUID alreadyApprovedCandidate(UUID run, UUID base) {
        var candidates = jdbc.queryForList("""
                select c.id from platform.intelligence_candidates c
                join platform.intelligence_publication_outbox o on o.candidate_id=c.id
                where c.status='PUBLICATION_QUEUED' and c.base_release_id=? and ?=any(c.selected_run_ids)
                    and o.kind='PUBLISH' and o.status='PENDING' and o.idempotency_key='full-catalog'
                """, UUID.class, base, run);
        assertTrue(candidates.size() <= 1);
        return candidates.stream().findFirst().orElse(null);
    }

    private long publishAndMeasureLock(FirstCustomerQualificationMetrics metrics) throws Exception {
        long start = System.nanoTime();
        var pool = Executors.newSingleThreadExecutor();
        try {
            var attempt = pool.submit(publications::poll);
            long lockedAt = 0;
            long lastLocked = 0;
            while (!attempt.isDone()) {
                if (releaseLocked()) {
                    lastLocked = System.nanoTime();
                    if (lockedAt == 0) lockedAt = lastLocked;
                }
                Thread.sleep(200);
            }
            attempt.get();
            metrics.mark("release_lock", "observed_lock_lower_bound_ms="
                    + TimeUnit.NANOSECONDS.toMillis(lastLocked - lockedAt));
            return elapsedMillis(start);
        } finally {
            pool.shutdownNow();
        }
    }

    private UUID publishBaseline() {
        advisories.ingestAdvisories(new AdvisoryBatchRequest(List.of(
                new AdvisoryRequest(BASELINE, "Prior approved catalog", "Qualification fixture",
                        7.5, "HIGH", List.of()))));
        UUID run = jdbc.queryForObject("select id from platform.sync_runs where sync_type='ADVISORY'", UUID.class);
        UUID candidate = build(run);
        approve(candidate, null, "prior-approved-generation");
        publications.poll();
        assertEquals("PUBLISHED", publications.candidate(candidate).get("status"));
        assertEquals(1L, catalogCount());
        return jdbc.queryForObject("select release_id from platform.intelligence_active_state", UUID.class);
    }

    private UUID resumeBase() {
        assertEquals(1L, catalogCount());
        assertEquals(1L, count("select count(*) from platform.vulnerabilities where external_id=?", BASELINE));
        return jdbc.queryForObject("select release_id from platform.intelligence_active_state where generation=1", UUID.class);
    }

    private UUID resumeFeed() {
        UUID run = jdbc.queryForObject("""
                select id from platform.sync_runs where sync_type='NVD_FULL' and status in ('running','queued','completed')
                """, UUID.class);
        int committed = Math.toIntExact(count("""
                select coalesce(max(fetched),0) from platform.nvd_page_checkpoints where run_id=?
                """, run));
        assertTrue(committed >= 10_000 && committed <= CVES);
        assertStaged(run, committed);
        when(provider.hasApiKey(any())).thenReturn(true);
        var first = new AtomicBoolean(true);
        try (var metrics = metrics("nvd_process_replacement")) {
            metrics.mark("previous_checkpoint", "cves=" + committed + " staged_rows=" + stagedRows(run));
            doAnswer(call -> {
                int start = call.getArgument(0);
                if (first.getAndSet(false)) {
                    assertEquals(committed, start);
                    qualifyRoutineKev(run);
                }
                return FirstCustomerCatalogFixture.page(start, CVES);
            }).when(provider).fetchPage(anyInt(), any(), any(), any(), any());
            if (!"completed".equals(runs.requireRun(run).getStatus())) {
                jdbc.update("update platform.sync_runs set lease_expires_at=now()-interval '1 second' where id=?", run);
                runs.recoverStaleRuns();
                executeFeed(run);
            }
            assertCatalogStaged(run);
            metrics.mark("complete", "cves=" + CVES + " staged_rows=" + stagedRows(run));
            return run;
        }
    }

    private UUID stageCatalog() {
        UUID run = nvd.triggerNvdFullSync(null).runId();
        assertNotNull(run);
        when(provider.hasApiKey(any())).thenReturn(true);
        var interrupt = new AtomicBoolean(true);
        int interruption = Math.min(CVES - 1, 100_000) / FirstCustomerCatalogFixture.PAGE_SIZE
                * FirstCustomerCatalogFixture.PAGE_SIZE;
        try (var metrics = metrics("nvd_stage")) {
            doAnswer(call -> {
                int start = call.getArgument(0);
                if ((start == 10_000 || start == 100_000) && (start != interruption || interrupt.get())) {
                    assertStaged(run, start);
                    metrics.mark("checkpoint", "cves=" + start + " staged_rows=" + stagedRows(run));
                }
                if (start == 10_000) qualifyRoutineKev(run);
                if (start == interruption && interrupt.getAndSet(false)) throw new InterruptedFeed();
                return FirstCustomerCatalogFixture.page(start, CVES);
            }).when(provider).fetchPage(anyInt(), any(), any(), any(), any());
            assertThrows(InterruptedFeed.class, () -> executeFeed(run));
            assertStaged(run, interruption);
            long restart = System.nanoTime();
            jdbc.update("update platform.sync_runs set lease_expires_at=now()-interval '1 second' where id=?", run);
            runs.recoverStaleRuns();
            executeFeed(run);
            assertCatalogStaged(run);
            metrics.mark("complete", "cves=" + CVES + " staged_rows=" + stagedRows(run)
                    + " remaining_feed_ms=" + elapsedMillis(restart));
            return run;
        }
    }

    private void qualifyRoutineKev(UUID backfill) throws Exception {
        when(outbound.execute(anyString(), eq(HttpMethod.GET), any(), eq(String.class),
                eq("KEV feed request"), any(), any(), any())).thenReturn("""
                {"count":1,"vulnerabilities":[{"cveID":"CVE-2025-99998","vulnerabilityName":"Routine KEV fixture",
                  "dateAdded":"2025-01-01","dueDate":"2025-01-15","requiredAction":"Apply the update"}]}
                """);
        CompletableFuture.runAsync(() -> {
            long start = System.nanoTime();
            UUID routine = TenantContext.runAsPlatform(() -> kev.triggerKevSync().runId());
            feedQueue.pollQueuedRuns();
            while (elapsedMillis(start) < 10_000) {
                if ("completed".equals(runs.requireRun(routine).getStatus())) {
                    assertEquals("running", runs.requireRun(backfill).getStatus());
                    assertEquals(1L, count("""
                            select count(*) from platform.intelligence_staged_records where sync_run_id=? and kind='OBSERVATION'
                            """, routine));
                    System.out.println("QUALIFICATION routine_feed=KEV admitted_during_nvd=true elapsed_ms="
                            + elapsedMillis(start));
                    return;
                }
                try {
                    Thread.sleep(50);
                } catch (InterruptedException failure) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("Routine feed check interrupted", failure);
                }
            }
            throw new AssertionError("KEV did not complete while the NVD attempt was active");
        }).get(15, TimeUnit.SECONDS);
    }

    private void assertCatalogStaged(UUID run) {
        assertEquals("completed", runs.requireRun(run).getStatus());
        assertStaged(run, CVES);
        assertEquals(CVES, count("""
                select count(distinct id) from platform.nvd_page_checkpoints p
                cross join lateral unnest(p.observed_ids) as manifest(id) where p.run_id=?
                """, run));
        assertEquals(1L, catalogCount());
    }

    private void executeFeed(UUID run) {
        var claim = runs.markRunningIfQueued(run).orElseThrow();
        try (var ownership = runs.openAttempt(claim)) {
            nvd.executeQueuedNvdFullSyncAsync(run);
        }
    }

    private UUID build(UUID run) {
        try (var metrics = metrics("build")) {
            UUID id = (UUID) publications.createCandidate(List.of(run), OWNER).get("id");
            publications.poll();
            var built = publications.candidate(id);
            assertEquals("READY", built.get("status"), built::toString);
            metrics.mark("ready", "candidate=" + id + " candidate_rows="
                    + count("select count(*) from platform.intelligence_candidate_records where candidate_id=?", id));
            return id;
        }
    }

    private void approve(UUID candidate, UUID base, String key) {
        String digest = (String) publications.candidate(candidate).get("digest");
        publications.publish(candidate, digest, base, key, OWNER);
        System.out.println("QUALIFICATION approval=" + candidate + " detail=" + jdbc.queryForObject("""
                select detail::text from platform.intelligence_audit_events
                where candidate_id=? and action='PUBLICATION_QUEUED' order by created_at desc limit 1
                """, String.class, candidate));
    }

    private void pauseInsidePublication(UUID candidate, UUID prior) throws Exception {
        try (var metrics = metrics("publication_interrupted")) {
            var pool = Executors.newSingleThreadExecutor();
            var attempt = pool.submit(publications::poll);
            try {
                long stop = System.nanoTime() + Duration.ofMinutes(30).toNanos();
                long lock = 0;
                long processed = 0;
                while (!attempt.isDone() && System.nanoTime() < stop) {
                    if (lock == 0 && releaseLocked()) lock = System.nanoTime();
                    Map<String, Object> state = progress.get(candidate);
                    if ("APPLYING_RECORDS".equals(state.get("phase"))) {
                        processed = ((Number) state.get("processed")).longValue();
                        if (processed >= 100) break;
                    }
                    Thread.sleep(50);
                }
                assertTrue(processed >= 100, () -> progress.get(candidate).toString());
                assertTrue(releaseLocked(), "Observe publication holding the release lock");
                assertEquals(prior, jdbc.queryForObject("select release_id from platform.intelligence_active_state", UUID.class));
                assertEquals(1L, catalogCount());
                long requested = System.nanoTime();
                progress.control(candidate, "PAUSE", OWNER);
                attempt.get(2, TimeUnit.MINUTES);
                assertEquals("PAUSED", progress.get(candidate).get("status"));
                assertEquals(1L, catalogCount());
                assertEquals(1L, count("select generation from platform.intelligence_active_state"));
                metrics.mark("rolled_back", "discarded_progress_records=" + processed + " pause_ms="
                        + elapsedMillis(requested) + " observed_lock_ms=" + elapsedMillis(lock));
            } finally {
                pool.shutdownNow();
            }
        }
    }

    private boolean releaseLocked() {
        return jdbc.queryForList("""
                select generation from platform.intelligence_active_state where singleton for share skip locked
                """, Long.class).isEmpty();
    }

    private void assertStaged(UUID run, int expected) {
        var counts = jdbc.queryForMap("""
                select count(*) total,count(distinct external_id) distinct_cves
                from platform.intelligence_staged_records where sync_run_id=? and kind='OBSERVATION'
                """, run);
        assertEquals((long) expected, counts.get("total"));
        assertEquals((long) expected, counts.get("distinct_cves"));
    }

    private long stagedRows(UUID run) {
        return count("select count(*) from platform.intelligence_staged_records where sync_run_id=?", run);
    }

    private long catalogCount() {
        return count("select count(*) from platform.vulnerabilities where not intelligence_withdrawn");
    }

    private long count(String sql, Object... args) {
        return jdbc.queryForObject(sql, Long.class, args);
    }

    private FirstCustomerQualificationMetrics metrics(String phase) {
        return new FirstCustomerQualificationMetrics(DATABASE, jdbc, phase);
    }

    private static final class InterruptedFeed extends AssertionError {}
}
