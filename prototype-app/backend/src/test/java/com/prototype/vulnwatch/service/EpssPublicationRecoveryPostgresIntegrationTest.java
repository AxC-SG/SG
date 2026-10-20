package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.service.vulningestion.*;
import com.prototype.vulnwatch.support.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.util.ReflectionTestUtils;

@PostgresIntegrationTest
class EpssPublicationRecoveryPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB =
            LocalPostgresTestDatabase.provision("phase3_epss_publication");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DB);
    }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired VulnerabilityRepository vulnerabilities;
    @Autowired VulnerabilitySyncRunService runs;
    @Autowired VulnerabilityQueuedRunWorkerService worker;
    @Autowired EpssRefreshService epss;
    @Autowired JdbcTemplate jdbc;
    @MockitoBean OutboundHttpClient transport;
    @MockitoBean(name="integrationQueueExecutor") org.springframework.core.task.TaskExecutor executor;
    Tenant first, second;
    List<Vulnerability> rows;

    @BeforeEach void setup() {
        TenantContext.clear();
        jdbc.update("delete from platform.sync_runs where sync_type='EPSS'");
        jdbc.update("delete from platform.vulnerabilities");
        first = tenant(); second = tenant();
        rows = new ArrayList<>();
        doAnswer(call -> { ((Runnable) call.getArgument(0)).run(); return null; }).when(executor).execute(any());
        ReflectionTestUtils.setField(epss, "batchSize", 2);
    }
    @AfterEach void clear() { TenantContext.clear(); ReflectionTestUtils.setField(epss, "batchSize", 100); }

    @Test void partialTenantFanoutRetainsStaleEligibilityAndSameScoreReplayRepairsIt() {
        row(1);
        respond(payload());
        scoped.run(second, () -> {
            jdbc.execute("""
                    create function fail_epss_intent() returns trigger language plpgsql as $$
                    begin if new.source_tag='epss-refresh' then raise exception 'injected tenant unavailable'; end if;
                    return new; end $$
                    """);
            jdbc.execute("create trigger fail_epss before insert on finding_delta_queue for each row execute function fail_epss_intent()");
        });
        UUID failed = execute();
        assertEquals("failed", runs.requireRun(failed).getStatus());
        Vulnerability saved = vulnerabilities.findById(rows.get(0).getId()).orElseThrow();
        assertEquals(0.75, saved.getEpssScore());
        assertNull(saved.getEpssUpdatedAt(), "failed publication must remain eligible for replay");
        assertEquals(1, queued(first)); assertEquals(0, queued(second));
        scoped.run(second, () -> jdbc.execute("drop trigger fail_epss on finding_delta_queue"));
        assertEquals("completed", runs.requireRun(execute()).getStatus());
        assertNotNull(vulnerabilities.findById(saved.getId()).orElseThrow().getEpssUpdatedAt());
        assertEquals(1, queued(first)); assertEquals(1, queued(second));
    }

    @Test void failureAfterFanoutBeforeFreshnessCommitReplaysWithoutDuplicatePendingIntent() {
        row(1); respond(payload());
        jdbc.execute("""
                create function platform.fail_epss_completion() returns trigger language plpgsql as $$
                begin if new.epss_updated_at is not null then raise exception 'injected freshness commit loss'; end if;
                return new; end $$
                """);
        jdbc.execute("create trigger fail_epss_completion before update on platform.vulnerabilities "
                + "for each row execute function platform.fail_epss_completion()");
        try {
            assertEquals("failed", runs.requireRun(execute()).getStatus());
            assertNull(vulnerabilities.findById(rows.get(0).getId()).orElseThrow().getEpssUpdatedAt());
            assertEquals(1, queued(first)); assertEquals(1, queued(second));
        } finally { jdbc.execute("drop trigger fail_epss_completion on platform.vulnerabilities"); }
        assertEquals("completed", runs.requireRun(execute()).getStatus());
        assertEquals(1, queued(first)); assertEquals(1, queued(second));
    }

    @Test void keysetTraversalTerminatesAcrossMissingScoresAndFailedPagesThenRecovers() {
        for (int n = 1; n <= 5; n++) row(n);
        AtomicInteger calls = new AtomicInteger();
        when(transport.exchange(anyString(), any(), any(), eq(String.class), anyString(), any(), any()))
                .thenAnswer(call -> switch (calls.incrementAndGet()) {
                    case 1 -> ResponseEntity.ok(payload());
                    case 2 -> throw new IllegalStateException("offline page unavailable");
                    default -> ResponseEntity.ok("{\"data\":[]}");
                });
        var partial = runs.requireRun(execute());
        assertEquals("partial", partial.getStatus());
        assertEquals(5, partial.getRecordsFetched()); assertEquals(2, partial.getRecordsUpdated());
        assertEquals(3, partial.getRecordsFailed()); assertEquals(3, calls.get());
        respond(payload());
        var complete = runs.requireRun(execute());
        assertEquals("completed", complete.getStatus());
        assertEquals(3, complete.getRecordsFetched()); assertEquals(3, complete.getRecordsUpdated());
        assertEquals(5, queued(first)); assertEquals(5, queued(second));
    }

    private UUID execute() {
        UUID id = TenantContext.runAsPlatform(() -> runs.prepareQueuedRun("EPSS", List.of("EPSS"), Map.of()).run().getId());
        worker.pollQueuedRuns(); return id;
    }
    private Tenant tenant() {
        String slug = "epss-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant result = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(result); return tenants.resolveTenantUuid(result.getId());
    }
    private void row(int n) {
        UUID id = new UUID(0, n);
        jdbc.update("""
                insert into platform.vulnerabilities(id,external_id,source,title,severity,in_kev,created_at,updated_at)
                values (?,?,'NVD','Offline EPSS fixture','HIGH',false,now(),now())
                """, id, "CVE-2099-" + (90000 + n));
        rows.add(vulnerabilities.findById(id).orElseThrow());
    }
    private String payload() {
        return "{\"data\":[" + rows.stream().map(row -> "{\"cve\":\"" + row.getExternalId()
                + "\",\"epss\":\"0.75\"}").collect(java.util.stream.Collectors.joining(",")) + "]}";
    }
    private void respond(String payload) {
        when(transport.exchange(anyString(), any(), any(), eq(String.class), anyString(), any(), any()))
                .thenReturn(ResponseEntity.ok(payload));
    }
    private int queued(Tenant tenant) {
        return scoped.run(tenant, () -> jdbc.queryForObject("select count(*) from finding_delta_queue where source_tag='epss-refresh'",
                Integer.class));
    }
}
