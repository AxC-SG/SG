package com.prototype.vulnwatch.service;

import static com.prototype.vulnwatch.service.FirstCustomerInventoryFixture.PROBE_PRODUCT;
import static com.prototype.vulnwatch.service.FirstCustomerInventoryFixture.PROBE_VENDOR;
import static com.prototype.vulnwatch.service.FirstCustomerQualificationMetrics.elapsedMillis;
import static com.prototype.vulnwatch.support.AuthRequest.asAnalyst;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.withTenant;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityConstraintType;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.dto.AdvisoryBatchRequest;
import com.prototype.vulnwatch.dto.AdvisoryRequest;
import com.prototype.vulnwatch.dto.AdvisoryRuleRequest;
import com.prototype.vulnwatch.repo.SyncRunRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.util.IdentityUtil;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

@PostgresControllerIntegrationTest
@EnabledIfSystemProperty(named = "firstCustomerQualification", matches = "true")
@WithMockUser(roles = "PLATFORM_OWNER")
class FirstCustomerInventoryPostgresIntegrationTest {
    private static final int ASSETS = Integer.getInteger("firstCustomerAssets", FirstCustomerInventoryFixture.ASSETS);
    private static final int PRODUCTS = FirstCustomerInventoryFixture.SOFTWARE_PER_ASSET;
    private static final int UNCHANGED_ASSETS = Math.min(25, ASSETS);
    private static final String PROBE = "CVE-2025-88888";
    private static final String PROBE_CPE = "cpe:2.3:a:" + PROBE_VENDOR + ":" + PROBE_PRODUCT + ":*:*:*:*:*:*:*:*";
    private static final String OWNER = "qualification-owner";
    private static final CmdbIngestionService.HostInventorySourceDescriptor SOURCE =
            new CmdbIngestionService.HostInventorySourceDescriptor(
                    "qualification.json", "sccm-jdbc", "sccm", "qualification", null, "application/json", null);
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            FirstCustomerQualificationMetrics.provision(ASSETS == FirstCustomerInventoryFixture.ASSETS
                    ? "first_customer_inventory" : "first_customer_inventory_smoke");

    @Autowired private JdbcTemplate jdbc;
    @Autowired private TenantService tenants;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantSchemaExecutionService schemas;
    @Autowired private SccmInventoryCaptureService captures;
    @Autowired private CmdbIngestionService inventory;
    @Autowired private SyncRunRepository runs;
    @Autowired private FindingDeltaQueueService deltas;
    @Autowired private InventoryRollupWorker rollups;
    @Autowired private TransactionTemplate transactions;
    @Autowired private TenantIntelligenceProcessingService processing;
    @Autowired private VulnerabilityIngestionService advisories;
    @Autowired private IntelligencePublicationService publications;
    @Autowired private IntelligenceReleaseRoutingService routing;
    @Autowired private VulnerabilitySyncRunService feeds;
    @Autowired private EpssRefreshService epss;
    @Autowired private VulnerabilityRepository vulnerabilities;
    @Autowired private IntelligenceStagingService staging;
    @Autowired private CpeDimensionService cpes;
    @Autowired private RiskPolicyService riskPolicies;
    @Autowired private MockMvc mvc;
    @MockitoBean private SccmQueryService provider;
    @MockitoBean private OutboundHttpClient outbound;

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.intelligence.targeted-publication.enabled", () -> true);
        registry.add("app.demo-data.seed-tenant-slug", () -> "");
        registry.add("app.tenancy.allow-header-tenant-selection", () -> true);
        registry.add("logging.level.com.prototype.vulnwatch.config.TenantAwareDataSource", () -> "ERROR");
        registry.add("spring.datasource.hikari.maximum-pool-size", () -> 14);
        registry.add("spring.datasource.hikari.data-source-properties.reWriteBatchedInserts",
                () -> Boolean.getBoolean("firstCustomerRewriteBatches"));
    }

    @Test
    void qualifySccmThroughCorrelationAndTargetedPublication() throws Exception {
        assertEquals(16L, count("select current_setting('server_version_num')::int") / 10_000);
        jdbc.execute("create extension if not exists pg_stat_statements with schema public");
        Tenant primary = tenants.getDefaultTenant();
        Tenant peer = tenants.createTenant("qualification-peer", "Qualification peer", "ENTERPRISE", null);
        migrations.provisionNewTenant(peer);
        peer = tenants.resolveTenantUuid(peer.getId());
        enable(primary);
        enable(peer);
        jdbc.update("""
                insert into platform.software_identities (id,canonical_key,display_name,vendor,product,cpe23,created_at,updated_at)
                values (?,?,?,?,?,?,now(),now())
                """, UUID.randomUUID(), IdentityUtil.canonicalIdentityKey("generic", PROBE_VENDOR, PROBE_PRODUCT),
                PROBE_PRODUCT, PROBE_VENDOR, PROBE_PRODUCT, PROBE_CPE);

        UUID base = publish(build(stageAdvisory("Qualification applicability baseline", List.of(probeRule()))),
                null, "initial");
        settle(primary, peer);
        long revision = revision(primary);
        try (var measurements = metrics("inventory_initial_capture")) {
            capture(primary, ASSETS);
            assertEquals(ASSETS, tenantCount(primary, "select count(*) from assets"));
            assertEquals((long) ASSETS * PRODUCTS, tenantCount(primary, "select count(*) from inventory_components"));
            assertEquals((long) ASSETS * PRODUCTS, tenantCount(primary, "select count(*) from software_instances"));
            assertEquals(revision, revision(primary));
            measurements.mark("normalized", "assets=" + ASSETS + " observations=" + (long) ASSETS * PRODUCTS);
            printBatchStatistics();
        }
        try (var measurements = metrics("inventory_correlation")) {
            settle(primary, peer);
            assertEquals(Math.min(8, ASSETS), openFindings(primary));
            assertEquals(0L, openFindings(peer));
            measurements.mark("settled", "findings=" + openFindings(primary));
        }

        try (var measurements = metrics("inventory_unchanged_rediscovery")) {
            long queue = tenantCount(primary, "select count(*) from finding_delta_queue");
            var findings = findingVersions(primary);
            capture(primary, UNCHANGED_ASSETS);
            assertEquals(queue, tenantCount(primary, "select count(*) from finding_delta_queue"));
            assertEquals(findings, findingVersions(primary));
            assertEquals(revision, revision(primary));
            measurements.mark("replayed", "assets=" + UNCHANGED_ASSETS
                    + " observations=" + (long) UNCHANGED_ASSETS * PRODUCTS + " new_delta_jobs=0"
                    + " freshness_rollups=" + tenantCount(primary, "select count(*) from inventory_rollup_queue"));
        }

        merge(peer, "sccm", FirstCustomerInventoryFixture.host(0, 1));
        settle(primary, peer);
        assertEquals(1L, openFindings(peer));
        assertEquals(Math.min(8, ASSETS), openFindings(primary));

        // An overlapping source supplies one present installation. It has no authority
        // to infer that other installations or findings on that host disappeared.
        merge(primary, "qualification-observer", FirstCustomerInventoryFixture.host(0, 1));
        settle(primary, peer);
        assertEquals(Math.min(8, ASSETS), openFindings(primary));
        assertEquals((long) ASSETS * PRODUCTS, tenantCount(primary, "select count(*) from inventory_components"));

        var initialEvaluation = probeEvaluations(primary);
        assertEquals(java.util.Collections.nCopies(Math.min(8, ASSETS), 0.0), probeScores(primary));
        UUID ranking = exerciseLiveUpdate(primary, peer, build(stageEpss()), base, "ranking", "RANKING", "2.0");
        assertEquals(Math.min(8, ASSETS), openFindings(primary));
        assertEquals(1L, openFindings(peer));
        assertEquals(1L, count("select count(*) from platform.vulnerabilities where external_id=? and epss_score=0.92", PROBE));
        assertEquals(1L, tenantCount(peer, "select count(*) from org_cve_records where epss_score=0.92"));
        assertEquals(initialEvaluation, probeEvaluations(primary));
        assertEquals(java.util.Collections.nCopies(Math.min(8, ASSETS), 10.0), probeScores(primary));

        UUID applicability = exerciseLiveUpdate(primary, peer,
                build(stageAdvisory("Replace the affected version range", List.of(
                        new AdvisoryRuleRequest(PROBE_VENDOR, PROBE_PRODUCT, "0.9", null, null, null, PROBE_CPE)))),
                ranking, "applicability", "APPLICABILITY", "3.0");
        assertEquals(0L, activeApplicability(primary));
        assertEquals(0L, activeApplicability(peer));
        UUID restored = withdraw(primary, peer, applicability, "withdraw-applicability");
        assertEquals(Math.min(8, ASSETS), activeApplicability(primary));
        assertEquals(1L, activeApplicability(peer));

        UUID vex = exerciseLiveUpdate(primary, peer, build(stageVex()), restored, "vex", "APPLICABILITY", "4.0");
        assertEquals(1L, count("select count(*) from platform.vex_assertions where status='NOT_AFFECTED'"));
        assertEquals(0L, activeApplicability(primary));
        assertEquals(0L, activeApplicability(peer));
        restored = withdraw(primary, peer, vex, "withdraw-vex");
        assertEquals(Math.min(8, ASSETS), activeApplicability(primary));
        assertEquals(0L, count("select count(*) from platform.vex_assertions"));

        UUID removal = exerciseLiveUpdate(primary, peer, build(stageAdvisory("Remove reviewed targets", List.of())),
                restored, "remove_targets", "APPLICABILITY", "5.0");
        assertEquals(0L, openFindings(primary));
        assertEquals(0L, openFindings(peer));
        restored = withdraw(primary, peer, removal, "withdraw-target-removal");
        assertEquals(Math.min(8, ASSETS), openFindings(primary));
        assertEquals(1L, openFindings(peer));

        UUID unresolved = publish(build(stageAdvisory("A target without a routable key", List.of(
                new AdvisoryRuleRequest(PROBE_VENDOR, PROBE_PRODUCT, "1.0", null, null, "sha256:" + "a".repeat(64))))),
                restored, "unresolved");
        org.junit.jupiter.api.Assertions.assertNull(routing.mode(unresolved));
        processing.poll();
        var fullEvaluation = processing.status(primary.getId());
        assertEquals("PENDING", fullEvaluation.get("status"));
        org.junit.jupiter.api.Assertions.assertNull(fullEvaluation.get("targeted_revision"));
        org.junit.jupiter.api.Assertions.assertNotNull(fullEvaluation.get("after_component_id"));
        System.out.println("QUALIFICATION fallback=explicit_reevaluation_scheduled");
    }

    private UUID withdraw(Tenant primary, Tenant peer, UUID release, String key) {
        publications.withdraw(release, key, OWNER);
        publications.poll();
        UUID withdrawal = activeRelease();
        assertEquals("APPLICABILITY", routing.mode(withdrawal));
        settle(primary, peer);
        assertEquals(1L, count("select count(*) from platform.vulnerabilities where external_id=? and not intelligence_withdrawn", PROBE));
        return withdrawal;
    }

    private UUID exerciseLiveUpdate(Tenant primary, Tenant peer, UUID candidate, UUID base, String key,
            String mode, String version) throws Exception {
        try (var measurements = metrics("live_" + key)) {
            List<Map<String, String>> burst = new ArrayList<>();
            for (int product = 1; product < 41; product++) {
                burst.add(FirstCustomerInventoryFixture.install(0, product, version));
            }
            merge(primary, "sccm", burst);
            merge(peer, "sccm", burst);
            assertTrue(pending(primary) > 0);
            assertTrue(pending(peer) > 0);
            long revision = revision(primary);
            var executor = Executors.newFixedThreadPool(2);
            var started = new CountDownLatch(2);
            var done = new AtomicBoolean();
            var latencies = new ArrayList<Long>();
            UUID release;
            try {
                var correlation = executor.submit(() -> {
                    started.countDown();
                    do {
                        deltas.processPendingDeltas();
                    } while (!done.get());
                });
                var traffic = executor.submit(() -> {
                    String[] routes = {"/api/dashboard", "/api/inventory/components?page=0&size=25",
                            "/api/vuln-repo/org-cves?page=0&size=25", "/api/findings?page=0&size=25"};
                    for (int i = 0; i < routes.length || !done.get(); i++) {
                        Tenant tenant = (i / routes.length) % 2 == 0 ? primary : peer;
                        long start = System.nanoTime();
                        if (i == 0) started.countDown();
                        mvc.perform(withTenant(asAnalyst(authedGet(routes[i % routes.length])),
                                tenant.getId().toString())).andExpect(status().isOk());
                        latencies.add(elapsedMillis(start));
                        Thread.sleep(75);
                    }
                    return null;
                });
                assertTrue(started.await(10, TimeUnit.SECONDS));
                release = publish(candidate, base, key);
                done.set(true);
                traffic.get(2, TimeUnit.MINUTES);
                correlation.get(2, TimeUnit.MINUTES);
            } finally {
                done.set(true);
                executor.shutdownNow();
            }
            assertEquals(mode, routing.mode(release));
            assertEquals(revision, revision(primary), "Routine inventory must not restart the tenant sweep");
            processing.poll();
            var firstPage = processing.status(primary.getId());
            if ("RANKING".equals(mode)) {
                assertEquals(revision + 1, firstPage.get("targeted_revision"));
            } else {
                assertEquals("COMPLETED", firstPage.get("status"), "The affected scope fits one page");
            }
            settle(primary, peer);
            assertEquals(revision + 1, revision(primary), "Only publication fanout raises the revision");
            assertEquals(0L, terminalFailures(primary));
            assertEquals(0L, terminalFailures(peer));
            latencies.sort(Long::compareTo);
            measurements.mark("settled", "mode=" + mode + " ui_requests=" + latencies.size()
                    + " ui_p95_ms=" + latencies.get((int) Math.ceil(latencies.size() * 0.95) - 1));
            return release;
        }
    }

    private void capture(Tenant tenant, int hostCount) throws Exception {
        var config = new SccmCmdbConfig();
        config.setTenant(tenant);
        UUID run = schemas.run(tenant, () -> {
            var row = new SyncRun();
            row.setTenant(tenant);
            row.setSyncType("SCCM_CMDB");
            row.setRunScope("TENANT_INVENTORY");
            row.setStatus("running");
            return runs.save(row).getId();
        });
        doAnswer(call -> {
            var pages = call.<Consumer<List<Map<String, String>>>>getArgument(1);
            for (int host = 0; host < hostCount; host++) pages.accept(FirstCustomerInventoryFixture.host(host, PRODUCTS));
            return null;
        }).when(provider).forEachInstallPage(eq(config), any());

        schemas.run(tenant, () -> {
            try {
                var result = captures.collectAndIngest(config, run, "sccm", SOURCE, ignored -> {});
                assertEquals(hostCount, result.assetsIngested());
                assertEquals(hostCount * PRODUCTS, result.installRowsProcessed());
                transactions.executeWithoutResult(status -> captures.finish(run));
            } catch (Exception failure) {
                throw new IllegalStateException("SCCM qualification capture failed", failure);
            }
        });
    }

    private void merge(Tenant tenant, String source, List<Map<String, String>> rows) {
        schemas.run(tenant, () -> inventory.ingestRows(tenant, source, rows, List.of(), SOURCE));
    }

    private void enable(Tenant tenant) {
        schemas.run(tenant, () -> {
            jdbc.update("""
                    insert into inventory_correlation_settings(tenant_id,inventory_incremental_correlation_enabled)
                    values (?,true)
                    """, tenant.getId());
            riskPolicies.getOrCreate(tenant);
            jdbc.update("""
                    update risk_policies set findings_score_config=?::jsonb
                    """, """
                    [{"table":"VULNERABILITY","column":"epssScore",
                      "values":[{"operator":">=","value":"0.9","weight":1.0}]}]
                    """);
        });
    }

    private UUID stageAdvisory(String description, List<AdvisoryRuleRequest> rules) {
        advisories.ingestAdvisories(new AdvisoryBatchRequest(List.of(
                new AdvisoryRequest(PROBE, "Qualification probe", description, 8.2, "HIGH", rules))));
        return jdbc.queryForObject("""
                select id from platform.sync_runs where sync_type='ADVISORY'
                order by started_at desc limit 1
                """, UUID.class);
    }

    private UUID stageEpss() {
        when(outbound.exchange(anyString(), any(), any(), eq(String.class), anyString(), any(), any()))
                .thenReturn(ResponseEntity.ok("""
                        {"data":[{"cve":"%s","epss":"0.92"}]}
                        """.formatted(PROBE)));
        UUID id = feeds.prepareQueuedRun("EPSS", List.of("EPSS"), Map.of()).run().getId();
        var claim = feeds.markRunningIfQueued(id).orElseThrow();
        try (var attempt = feeds.openAttempt(claim)) {
            epss.executeQueuedRun(id);
        }
        assertEquals("completed", feeds.requireRun(id).getStatus());
        return id;
    }

    private UUID stageVex() {
        var run = feeds.createRunningRun("CSAF_MICROSOFT");
        try {
            Vulnerability probe = vulnerabilities.findByExternalId(PROBE).orElseThrow();
            var target = new VulnerabilityTarget();
            target.setVulnerability(probe);
            target.setTargetType(VulnerabilityTargetType.CPE);
            target.setNormalizedTargetKey(PROBE_CPE);
            target.setCpe(PROBE_CPE);
            target.setCpeDim(cpes.resolveOrCreate(PROBE_CPE));
            target.setVersionExact("1.0");
            target.setVersionScheme(VersionScheme.UNKNOWN);
            target.setConstraintType(VulnerabilityConstraintType.EXACT);
            target.setSource("microsoft-vex");
            target.setQualifiersJson("""
                    {"vexStatus":"KNOWN_NOT_AFFECTED","vexProvider":"microsoft","vexTrustTier":"HIGH",
                     "vexPublishedAt":"%s","advisoryDocumentId":"qualification-vex"}
                    """.formatted(Instant.now()));
            staging.entity("TARGET", probe, target.getSource(), target);
            feeds.completeRun(run, "completed", 1, 0, 1, 0, null);
            return run.getId();
        } finally {
            IntelligenceWriteContext.endRun(run.getId());
        }
    }

    private static AdvisoryRuleRequest probeRule() {
        return new AdvisoryRuleRequest(PROBE_VENDOR, PROBE_PRODUCT, "1.0", null, null, null, PROBE_CPE);
    }

    private UUID build(UUID run) {
        UUID candidate = (UUID) publications.createCandidate(List.of(run), OWNER).get("id");
        publications.poll();
        var state = publications.candidate(candidate);
        assertEquals("READY", state.get("status"), state::toString);
        return candidate;
    }

    private UUID publish(UUID candidate, UUID base, String key) {
        publications.publish(candidate, (String) publications.candidate(candidate).get("digest"), base, key, OWNER);
        publications.poll();
        var state = publications.candidate(candidate);
        assertEquals("PUBLISHED", state.get("status"), state::toString);
        return activeRelease();
    }

    private UUID activeRelease() {
        return jdbc.queryForObject("select release_id from platform.intelligence_active_state", UUID.class);
    }

    private void settle(Tenant primary, Tenant peer) {
        long deadline = System.nanoTime() + Duration.ofHours(1).toNanos();
        while (System.nanoTime() < deadline) {
            processing.poll();
            deltas.processPendingDeltas();
            rollups.poll();
            if (settled(primary) && settled(peer)) {
                assertEquals(0L, terminalFailures(primary));
                assertEquals(0L, terminalFailures(peer));
                return;
            }
        }
        throw new AssertionError("Timed out draining evaluation, finding deltas and rollups");
    }

    private boolean settled(Tenant tenant) {
        return pending(tenant) == 0
                && tenantCount(tenant, "select count(*) from inventory_rollup_queue") == 0
                && "COMPLETED".equals(processing.status(tenant.getId()).get("status"));
    }

    private long pending(Tenant tenant) {
        return tenantCount(tenant, "select count(*) from finding_delta_queue where status in ('PENDING','PROCESSING')");
    }

    private long terminalFailures(Tenant tenant) {
        return tenantCount(tenant, "select count(*) from finding_delta_queue where status in ('FAILED','DEAD')");
    }

    private long openFindings(Tenant tenant) {
        return schemas.run(tenant, () -> count("""
                select count(*) from findings f join platform.vulnerabilities v on v.id=f.vulnerability_id
                where v.external_id=? and f.status='OPEN' and f.intelligence_eligibility='ELIGIBLE'
                """, PROBE));
    }

    private List<Map<String, Object>> findingVersions(Tenant tenant) {
        return schemas.run(tenant, () -> jdbc.queryForList("select id,status,updated_at from findings order by id"));
    }

    private long activeApplicability(Tenant tenant) {
        return tenantCount(tenant, "select count(*) from component_vulnerability_states where eligible_for_finding");
    }

    private List<Map<String, Object>> probeEvaluations(Tenant tenant) {
        return schemas.run(tenant, () -> jdbc.queryForList("""
                select component_id,last_evaluated_at from component_vulnerability_states order by component_id
                """));
    }

    private List<Double> probeScores(Tenant tenant) {
        return schemas.run(tenant, () -> jdbc.queryForList("select risk_score from findings order by id", Double.class));
    }

    private long revision(Tenant tenant) {
        return count("select required_revision from platform.tenant_intelligence_processing where tenant_id=?", tenant.getId());
    }

    private long tenantCount(Tenant tenant, String sql) {
        return schemas.run(tenant, () -> count(sql));
    }

    private long count(String sql, Object... args) {
        return jdbc.queryForObject(sql, Long.class, args);
    }

    private void printBatchStatistics() {
        jdbc.queryForList("""
                select calls,rows,round(total_exec_time::numeric,1) ms, left(query,500) statement
                from public.pg_stat_statements
                where dbid=(select oid from pg_database where datname=current_database())
                  and (query ilike 'insert into sccm_inventory_capture_rows%'
                       or query ilike 'insert into inventory_components%'
                       or query ilike 'insert into software_instances%')
                order by rows desc
                """).forEach(row -> System.out.println("QUALIFICATION jdbc=" + row));
    }

    private FirstCustomerQualificationMetrics metrics(String phase) {
        return new FirstCustomerQualificationMetrics(DATABASE, jdbc, phase);
    }
}
