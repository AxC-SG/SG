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
    @Autowired VulnerabilitySyncRunService syncRuns;
    @Autowired FeedWatermarkService watermarks;
    @Autowired FeedCoverageLedgerService coverageLedger;
    @Autowired NvdObservedGapsService observedGaps;
    @Autowired NvdObservedIdComparisonService idComparison;
    @Autowired NvdBaselineQueueService baselineQueue;
    @Autowired JdbcTemplate jdbc;
    @Autowired com.prototype.vulnwatch.repo.VulnerabilityRepository vulnerabilities;
    @Autowired com.prototype.vulnwatch.repo.VulnerabilityRuleRepository rules;
    @MockitoBean NvdApiClient provider;
    @MockitoBean VulnerabilitySourceFilterConfigService filters;
    private final NvdFilters original = new NvdFilters(null, false, false, null, null);
    private final NvdFilters changed = new NvdFilters(null, false, true, null, null);

    @BeforeEach void setup() {
        jdbc.update("delete from platform.nvd_observed_interval_ids");
        jdbc.update("delete from platform.feed_coverage_observations");
        jdbc.update("delete from platform.feed_sync_watermarks");
        when(filters.resolvePlatformNvdFilters()).thenReturn(original);
        when(provider.fetchPage(anyInt(), any(), any(), any(), any())).thenReturn(new NvdApiClient.NvdPage(List.of(), 0, 0, 0));
    }

    @Test void intervalManifestStoresExactIdsAndRejectsIncompleteEvidence() {
        var run = syncRuns.createRunningRun("NVD");
        UUID runId = run.getId();
        Instant from = Instant.parse("2025-03-01T00:00:00Z");
        Instant to = from.plus(Duration.ofDays(1));
        assertThrows(IllegalArgumentException.class, () -> coverageLedger.observeNvdInterval(
                runId, key(original), from, to, 2, Set.of("CVE-2025-1001")));
        assertEquals(0, jdbc.queryForObject("select count(*) from platform.feed_coverage_observations where run_id=?",
                Integer.class, runId));

        coverageLedger.observeNvdInterval(runId, key(original), from, to, 2,
                Set.of("CVE-2025-1001", "CVE-2025-1002"));
        assertEquals(Set.of("CVE-2025-1001", "CVE-2025-1002"), new HashSet<>(jdbc.queryForList(
                "select cve_id from platform.nvd_observed_interval_ids where run_id=?", String.class, runId)));
        assertEquals(2, jdbc.queryForObject("select fetched_records from platform.feed_coverage_observations where run_id=?",
                Integer.class, runId));
        syncRuns.completeRun(run, "completed", 2, 0, 2, 0, null);
    }

    @Test void manifestWriteFailureRollsBackCoverageObservation() {
        var run = syncRuns.createRunningRun("NVD");
        UUID runId = run.getId();
        Instant from = Instant.parse("2025-04-01T00:00:00Z");
        Instant to = from.plus(Duration.ofDays(1));
        jdbc.execute("""
                create function platform.reject_nvd_manifest_test() returns trigger language plpgsql as $$
                begin raise exception 'forced manifest failure'; end $$
                """);
        jdbc.execute("""
                create trigger reject_nvd_manifest_test before insert on platform.nvd_observed_interval_ids
                for each row execute function platform.reject_nvd_manifest_test()
                """);
        try {
            assertThrows(org.springframework.dao.DataAccessException.class, () -> coverageLedger.observeNvdInterval(
                    runId, key(original), from, to, 1, Set.of("CVE-2025-2001")));
        } finally {
            jdbc.execute("drop trigger reject_nvd_manifest_test on platform.nvd_observed_interval_ids");
            jdbc.execute("drop function platform.reject_nvd_manifest_test()");
        }
        assertEquals(0, jdbc.queryForObject("select count(*) from platform.feed_coverage_observations where run_id=?",
                Integer.class, runId));
        syncRuns.completeRun(run, "failed", 0, 0, 0, 0, "forced manifest failure");
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void failedRunIntervalRemainsUnobservedUntilSuccessfulReplay() {
        Instant from = Instant.parse("2025-05-01T00:00:00Z");
        Instant to = from.plus(Duration.ofDays(1));
        var failedRun = syncRuns.createRunningRun("NVD");
        coverageLedger.observeNvdInterval(failedRun.getId(), key(original), from, to, 0, Set.of());
        assertEquals(1, observedGaps.inspect(key(original), from, to).unobservedIntervals().size());
        syncRuns.completeRun(failedRun, "failed", 0, 0, 0, 0, "later interval failed");
        assertEquals(1, observedGaps.inspect(key(original), from, to).unobservedIntervals().size());
        assertTrue(observedGaps.scopes(null).items().stream().noneMatch(item -> item.feedKey().equals(key(original))));

        var replay = syncRuns.createRunningRun("NVD");
        coverageLedger.observeNvdInterval(replay.getId(), key(original), from, to, 0, Set.of());
        syncRuns.completeRun(replay, "completed", 0, 0, 0, 0, null);
        assertTrue(observedGaps.inspect(key(original), from, to).unobservedIntervals().isEmpty());
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void completedReplayComparisonReportsExactBoundedDifferences() {
        Instant from = Instant.parse("2025-06-01T00:00:00Z");
        Instant to = from.plus(Duration.ofDays(1));
        var first = syncRuns.createRunningRun("NVD");
        coverageLedger.observeNvdInterval(first.getId(), key(original), from, to, 2,
                Set.of("CVE-2025-3001", "CVE-2025-3002"));
        syncRuns.completeRun(first, "completed", 2, 0, 2, 0, null);
        var second = syncRuns.createRunningRun("NVD");
        coverageLedger.observeNvdInterval(second.getId(), key(original), from, to, 2,
                Set.of("CVE-2025-3002", "CVE-2025-3003"));
        syncRuns.completeRun(second, "completed", 2, 0, 2, 0, null);

        var result = idComparison.compare(first.getId(), second.getId(), key(original), from, to);
        assertFalse(result.identical());
        assertEquals(1, result.onlyInFirst());
        assertEquals(1, result.onlyInSecond());
        assertEquals(List.of("CVE-2025-3001"), result.onlyInFirstSample());
        assertEquals(List.of("CVE-2025-3003"), result.onlyInSecondSample());
        assertEquals("UNKNOWN", result.historicalCoverageStatus());
        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> idComparison.compare(first.getId(), first.getId(), key(original), from, to));
        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> idComparison.compare(first.getId(), second.getId(), key(changed), from, to));

        var legacy = syncRuns.createRunningRun("NVD");
        jdbc.update("""
                insert into platform.feed_coverage_observations
                  (run_id,source_system,feed_key,interval_start,interval_end,fetched_records)
                values (?,'nvd',?,?,?,0)
                """, legacy.getId(), key(original), java.sql.Timestamp.from(from), java.sql.Timestamp.from(to));
        syncRuns.completeRun(legacy, "completed", 0, 0, 0, 0, null);
        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> idComparison.compare(first.getId(), legacy.getId(), key(original), from, to));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "TENANT_ADMIN")
    void tenantAdminCannotComparePlatformNvdManifests() {
        Instant from = Instant.parse("2025-06-01T00:00:00Z");
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> idComparison.compare(UUID.randomUUID(), UUID.randomUUID(), key(original),
                        from, from.plus(Duration.ofDays(1))));
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
        assertEquals(3, jdbc.queryForObject(
                "select count(*) from platform.feed_coverage_observations where feed_key=? and source_system='nvd'",
                Integer.class, key(original)));
        assertTrue(watermarks.completedUntil(key(changed)).isEmpty());
        verify(filters).resolvePlatformNvdFilters();
    }

    @Test void historicalWindowRetryRecordsEvidenceOnlyAfterCompleteRunWithoutMovingIncrementalWatermark() {
        Instant from = Instant.parse("2025-01-01T00:00:00Z");
        Instant to = from.plus(Duration.ofDays(30));
        when(provider.fetchPage(anyInt(), eq(from), eq(to), any(), any()))
                .thenReturn(new NvdApiClient.NvdPage(List.of(), 10, 0, 10));
        UUID firstRun = nvd.triggerNvdHistoricalWindow(from, to).runId();
        executeClaimed(firstRun);
        assertEquals("failed", jdbc.queryForObject("select status from platform.sync_runs where id=?", String.class, firstRun));
        assertEquals(0, jdbc.queryForObject("select count(*) from platform.feed_coverage_observations where feed_key=?",
                Integer.class, key(original)));
        assertTrue(watermarks.completedUntil(key(original)).isEmpty());

        when(provider.fetchPage(anyInt(), eq(from), eq(to), any(), any()))
                .thenReturn(new NvdApiClient.NvdPage(List.of(), 0, 0, 0));
        UUID retryRun = nvd.triggerNvdHistoricalWindow(from, to).runId();
        executeClaimed(retryRun);
        assertEquals("completed", jdbc.queryForObject("select status from platform.sync_runs where id=?", String.class, retryRun));
        assertEquals(1, jdbc.queryForObject("select count(*) from platform.feed_coverage_observations where feed_key=? and interval_start=? and interval_end=?",
                Integer.class, key(original), java.sql.Timestamp.from(from), java.sql.Timestamp.from(to)));
        assertTrue(watermarks.completedUntil(key(original)).isEmpty());
    }

    @Test void workerReplacementResumesTheCommittedPageWithItsOriginalIntervalAndFilters() {
        UUID runId = nvd.triggerNvdSync(24).runId();
        var initialBounds = new ArrayList<Instant>();
        when(provider.fetchPage(eq(0), any(), any(), any(), any())).thenAnswer(call -> {
            initialBounds.add(call.getArgument(1));
            initialBounds.add(call.getArgument(2));
            return new NvdApiClient.NvdPage(List.of(resumeRecord("CVE-2026-91001")), 2, 0, 1);
        });
        doThrow(new AssertionError("worker stopped")).when(provider).fetchPage(eq(1), any(), any(), any(), any());

        assertThrows(AssertionError.class, () -> executeClaimed(runId));
        assertEquals(1, jdbc.queryForObject("select count(*) from platform.nvd_page_checkpoints where run_id=?",
                Integer.class, runId));
        assertEquals(1, stagedObservations(runId));
        assertTrue(watermarks.completedUntil(key(original)).isEmpty());

        jdbc.update("update platform.sync_runs set lease_expires_at=now()-interval '1 second' where id=?", runId);
        syncRuns.recoverStaleRuns();
        when(filters.resolvePlatformNvdFilters()).thenReturn(changed);
        doAnswer(call -> {
            assertEquals(initialBounds.get(0), call.getArgument(1));
            assertEquals(initialBounds.get(1), call.getArgument(2));
            assertFalse(call.<NvdApiClient.NvdQueryFilters>getArgument(3).hasKev());
            return new NvdApiClient.NvdPage(List.of(resumeRecord("CVE-2026-91002")), 2, 1, 1);
        }).when(provider).fetchPage(eq(1), any(), any(), any(), any());
        executeClaimed(runId);

        verify(provider, times(1)).fetchPage(eq(0), any(), any(), any(), any());
        assertEquals(2, stagedObservations(runId));
        assertEquals(Set.of("CVE-2026-91001", "CVE-2026-91002"), new HashSet<>(jdbc.queryForList("""
                select cve_id from platform.nvd_observed_interval_ids where run_id=?
                """, String.class, runId)));
        assertEquals(initialBounds.get(1), watermarks.completedUntil(key(original)).orElseThrow());
        assertTrue(watermarks.completedUntil(key(changed)).isEmpty());
    }

    @Test void failedCheckpointWriteRollsBackTheStagedPageAndKeepsTheWatermark() {
        Instant prior = Instant.now().minus(Duration.ofDays(1)).truncatedTo(java.time.temporal.ChronoUnit.MILLIS);
        watermarks.complete(key(original), prior);
        UUID runId = nvd.triggerNvdSync(24).runId();
        when(provider.fetchPage(eq(0), any(), any(), any(), any())).thenReturn(new NvdApiClient.NvdPage(
                List.of(resumeRecord("CVE-2026-91003")), 1, 0, 1));
        jdbc.execute("""
                create function platform.reject_nvd_checkpoint_test() returns trigger language plpgsql as $$
                begin raise exception 'forced checkpoint failure'; end $$
                """);
        jdbc.execute("""
                create trigger reject_nvd_checkpoint_test before insert on platform.nvd_page_checkpoints
                for each row execute function platform.reject_nvd_checkpoint_test()
                """);
        try {
            executeClaimed(runId);
            assertEquals("failed", jdbc.queryForObject("select status from platform.sync_runs where id=?",
                    String.class, runId));
            assertEquals(0, stagedObservations(runId));
            assertEquals(0, jdbc.queryForObject("select count(*) from platform.nvd_page_checkpoints where run_id=?",
                    Integer.class, runId));
            assertEquals(prior, watermarks.completedUntil(key(original)).orElseThrow());
        } finally {
            jdbc.execute("drop trigger reject_nvd_checkpoint_test on platform.nvd_page_checkpoints");
            jdbc.execute("drop function platform.reject_nvd_checkpoint_test()");
        }
    }

    private NvdApiClient.NvdRecord resumeRecord(String cveId) {
        return new NvdApiClient.NvdRecord(cveId, cveId, "Fixture", 8.0, "HIGH",
                "Analyzed", null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, List.of(), "{}");
    }

    private int stagedObservations(UUID runId) {
        return jdbc.queryForObject("""
                select count(*) from platform.intelligence_staged_records where sync_run_id=? and kind='OBSERVATION'
                """, Integer.class, runId);
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void baselinePlanPartitionsLongRangeAndLeavesUnobservedTailExplicit() {
        Instant from = Instant.parse("2025-01-01T00:00:00Z");
        Instant boundary = from.plus(Duration.ofDays(120));
        Instant to = boundary.plus(Duration.ofDays(1));
        UUID runId = nvd.triggerNvdHistoricalWindow(from, boundary).runId();
        executeClaimed(runId);

        var plan = observedGaps.plan(key(original), from, to);
        assertEquals("UNKNOWN", plan.historicalCoverageStatus());
        assertEquals(2, plan.partitions().size());
        assertTrue(plan.partitions().get(0).unobservedIntervals().isEmpty());
        assertEquals(boundary, plan.partitions().get(1).unobservedIntervals().get(0).from());
        assertEquals(to, plan.partitions().get(1).unobservedIntervals().get(0).to());
        assertThrows(org.springframework.web.server.ResponseStatusException.class,
                () -> observedGaps.plan(key(original), from, from.plus(Duration.ofDays(366L * 41))));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void baselineQueueResumesAtFirstUnobservedWindowAndNeverCertifiesCompleteness() {
        Instant from = Instant.parse("2025-01-01T00:00:00Z");
        Instant boundary = from.plus(Duration.ofDays(120));
        Instant to = boundary.plus(Duration.ofDays(1));
        executeClaimed(nvd.triggerNvdHistoricalWindow(from, boundary).runId());

        var next = baselineQueue.queueNext(from, to);
        assertEquals("queued", next.status());
        assertEquals(boundary, next.from());
        assertEquals(to, next.to());
        assertEquals(1, jdbc.queryForObject("""
                select count(*) from platform.intelligence_audit_events
                where detail->>'action'='platform.vulnerability_feed.nvd_baseline_next'
                  and detail->>'targetId'=? and detail->'details'->>'status'='queued'
                """, Integer.class, next.runId().toString()));
        executeClaimed(next.runId());

        var observed = baselineQueue.queueNext(from, to);
        assertEquals("no_unobserved_interval", observed.status());
        assertNull(observed.runId());
        assertTrue(observed.message().contains("unknown"));
        assertEquals(2, jdbc.queryForObject(
                "select count(*) from platform.feed_coverage_observations where feed_key=?", Integer.class, key(original)));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void queuedBaselineWindowFailsWithoutCoverageWhenPlatformFilterScopeChanges() {
        Instant from = Instant.parse("2025-01-01T00:00:00Z");
        Instant to = from.plus(Duration.ofDays(1));
        var next = baselineQueue.queueNext(from, to);
        assertEquals("queued", next.status());
        when(filters.resolvePlatformNvdFilters()).thenReturn(changed);

        executeClaimed(next.runId());
        assertEquals("failed", jdbc.queryForObject(
                "select status from platform.sync_runs where id=?", String.class, next.runId()));
        assertEquals(0, jdbc.queryForObject(
                "select count(*) from platform.feed_coverage_observations where feed_key=?", Integer.class, key(original)));
        verifyNoInteractions(provider);
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void repeatedBaselineQueueRequestDoesNotCreateAnotherActiveNvdRun() {
        Instant from = Instant.parse("2025-01-01T00:00:00Z");
        Instant to = from.plus(Duration.ofDays(1));
        var first = baselineQueue.queueNext(from, to);
        assertEquals("queued", first.status());

        var second = baselineQueue.queueNext(from, to);
        assertEquals("busy", second.status());
        assertEquals(first.runId(), second.runId());
        assertNull(second.from());
        assertNull(second.to());
        assertEquals(1, jdbc.queryForObject("select count(*) from platform.sync_runs where id=? and status='queued'",
                Integer.class, first.runId()));

        executeClaimed(first.runId());
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "PLATFORM_OWNER")
    void auditFailureRollsBackNewlyQueuedBaselineRun() {
        Instant from = Instant.parse("2024-07-01T00:00:00Z");
        Instant to = from.plus(Duration.ofDays(1));
        String countSql = """
                select count(*) from platform.sync_runs where status='queued'
                  and metadata_json::jsonb->>'triggerMode'='historical_window'
                  and metadata_json::jsonb->>'from'=? and metadata_json::jsonb->>'to'=?
                """;
        int before = jdbc.queryForObject(countSql, Integer.class, from.toString(), to.toString());
        jdbc.execute("""
                create function platform.reject_baseline_audit_test() returns trigger language plpgsql as $$
                begin
                  if new.detail->>'action'='platform.vulnerability_feed.nvd_baseline_next' then
                    raise exception 'forced baseline audit failure';
                  end if;
                  return new;
                end $$
                """);
        jdbc.execute("""
                create trigger reject_baseline_audit_test before insert on platform.intelligence_audit_events
                for each row execute function platform.reject_baseline_audit_test()
                """);
        try {
            assertThrows(org.springframework.dao.DataAccessException.class,
                    () -> baselineQueue.queueNext(from, to));
        } finally {
            jdbc.execute("drop trigger reject_baseline_audit_test on platform.intelligence_audit_events");
            jdbc.execute("drop function platform.reject_baseline_audit_test()");
        }
        assertEquals(before, jdbc.queryForObject(countSql, Integer.class, from.toString(), to.toString()));
    }

    @Test
    @org.springframework.security.test.context.support.WithMockUser(roles = "TENANT_ADMIN")
    void tenantAdminCannotReadPlatformNvdBaselinePlan() {
        Instant from = Instant.parse("2025-01-01T00:00:00Z");
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> observedGaps.plan(key(original), from, from.plus(Duration.ofDays(1))));
        assertThrows(org.springframework.security.access.AccessDeniedException.class,
                () -> baselineQueue.queueNext(from, from.plus(Duration.ofDays(1))));
    }

    @Test void failedSecondIntervalDoesNotCertifyGapAndReplayResumesAtLastCompletedBoundary() {
        Instant originalCheckpoint=Instant.now().minus(Duration.ofDays(250));
        watermarks.complete(key(original), originalCheckpoint);
        AtomicInteger calls = new AtomicInteger();
        List<Instant> ends = new ArrayList<>();
        when(provider.fetchPage(anyInt(), any(), any(), any(), any())).thenAnswer(call -> {
            ends.add(call.getArgument(2));
            if (calls.incrementAndGet() == 2) throw new IllegalStateException("offline provider interruption");
            return new NvdApiClient.NvdPage(List.of(), 0, 0, 0);
        });
        assertEquals("failed", nvd.syncNvd(24).status());
        Instant checkpoint = watermarks.completedUntil(key(original)).orElseThrow();
        assertEquals(originalCheckpoint.toEpochMilli(), checkpoint.toEpochMilli());
        assertTrue(checkpoint.isBefore(ends.get(1)));
        assertEquals(1, jdbc.queryForObject(
                "select count(*) from platform.feed_coverage_observations where feed_key=?",
                Integer.class, key(original)));
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
        assertEquals(0, jdbc.queryForObject(
                "select count(*) from platform.feed_coverage_observations where feed_key=?",
                Integer.class, key(changed)));
        assertEquals(previous.toEpochMilli(), watermarks.completedUntil(key(original)).orElseThrow().toEpochMilli());
        when(provider.fetchPage(anyInt(), any(), any(), any(), any())).thenAnswer(call -> {
            assertEquals(48, Duration.between(call.getArgument(1), call.getArgument(2)).toHours());
            return new NvdApiClient.NvdPage(List.of(), 0, 0, 0);
        });
        assertEquals("ok", nvd.syncNvd(48).status());
        assertTrue(watermarks.completedUntil(key(changed)).isPresent());
    }

    @Test void optionalTargetRepairStagesAnExplicitRunWithoutChangingApprovedTargets() {
        var vulnerability=new com.prototype.vulnwatch.domain.Vulnerability();
        vulnerability.setExternalId("CVE-2099-89999");vulnerability.setTitle("Approved rule repair fixture");
        vulnerability.setSource(com.prototype.vulnwatch.domain.VulnerabilitySource.NVD);
        vulnerability=vulnerabilities.save(vulnerability);
        var rule=new com.prototype.vulnwatch.domain.VulnerabilityRule();rule.setVulnerability(vulnerability);
        rule.setEcosystem("npm");rule.setPackageName("repair-fixture");rule.setVersionExact("1.0.0");rules.save(rule);
        org.springframework.test.util.ReflectionTestUtils.setField(nvd,"backfillTargetsOnStartup",true);
        try {
            nvd.backfillTargetsFromExistingRulesIfEnabled();
            assertEquals(0,jdbc.queryForObject("select count(*) from platform.vulnerability_targets where vulnerability_id=?",Integer.class,vulnerability.getId()));
            assertTrue(jdbc.queryForObject("select count(*) from platform.intelligence_staged_records s join platform.sync_runs r on r.id=s.sync_run_id where r.sync_type='NVD_TARGET_REPAIR' and r.status='completed' and s.kind='TARGET'",Integer.class)>0);
            assertNull(com.prototype.vulnwatch.service.IntelligenceWriteContext.runId());
        } finally { org.springframework.test.util.ReflectionTestUtils.setField(nvd,"backfillTargetsOnStartup",false); }
    }

    private static String key(NvdFilters value) {
        return "nvd:" + org.springframework.util.DigestUtils.md5DigestAsHex(value.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private void executeClaimed(UUID runId) {
        var claim = syncRuns.markRunningIfQueued(runId).orElseThrow();
        try (var ownership = syncRuns.openAttempt(claim)) {
            nvd.executeQueuedNvdSyncAsync(runId);
        }
    }
}
