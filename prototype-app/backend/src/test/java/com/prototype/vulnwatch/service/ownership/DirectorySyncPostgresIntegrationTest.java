package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.client.ServiceNowDirectoryClient;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.Cursor;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.DirectoryTable;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.FailureKind;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.Page;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.ServiceNowDirectoryException;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyRegistry;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.ownership.DirectoryService.DirectoryUser;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.ServiceNowSourceRequest;
import com.prototype.vulnwatch.service.ownership.ServiceNowDirectorySync.RunResult;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.invocation.InvocationOnMock;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.web.server.ResponseStatusException;

/**
 * Real-PostgreSQL proof for the ServiceNow directory sync (Phase 0B contract §1.3, §1.5, §1.7): baseline load, the
 * incremental cursor, complete-scan deactivation, failed-run no-op, per-page cursor advance, three failures to ERROR,
 * anomaly pause with approval by resume, and sync-now gating. ServiceNow is an in-memory fake behind the mocked client.
 */
@PostgresIntegrationTest
class DirectorySyncPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("ownership_directory_sync");
    private static final DateTimeFormatter SN_TIME = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
        registry.add("app.ownership.servicenow.directory-enabled", () -> "true");
    }

    @Autowired private ServiceNowDirectorySync sync;
    @Autowired private IdentitySourceService sources;
    @Autowired private DirectoryService directory;
    @Autowired private TenantKeyRegistry keys;
    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private JdbcTemplate jdbc;
    @MockitoBean private ServiceNowDirectoryClient client;
    @TestBean private OutboundHostPolicy hostPolicy;

    static OutboundHostPolicy hostPolicy() {
        return OutboundHostPolicy.forTests("servicenow=acme.service-now.com");
    }

    private Tenant tenant;
    private UUID source;
    private UUID manual;
    private FakeServiceNow fake;

    @BeforeEach
    void setUp() {
        String slug = "own-sync-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenantService.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        tenant = tenantService.resolveTenantUuid(created.getId());
        keys.provision(tenant.getId());
        TenantContext.clear();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
        source = sources.create(new ServiceNowSourceRequest("Acme ServiceNow", "https://acme.service-now.com", "BASIC", "svc", "s3cret",
                null, null, null), "admin").id();
        jdbc.update("UPDATE identity_source SET state = 'ENABLED' WHERE id = ?", source);
        manual = directory.manualSource("admin");
        fake = new FakeServiceNow();
        when(client.fetchPage(any(), any(), any(), any(), anyInt())).thenAnswer(fake::page);
    }

    @AfterEach
    void clear() {
        TenantContext.clear();
    }

    @Test
    void aBaselineRunLinksPeopleGroupsMembershipsAndManagersAndRecordsOneRun() {
        DirectoryUser grace = directory.createUser("Grace Hopper", "grace@acme.test", null, null, manual, "admin");
        fake.user(1, "Ada Lovelace", "ada@acme.test", null);
        fake.user(2, "G. Hopper", "GRACE@acme.test", 4);
        fake.user(3, "Bob Byte", "bob@acme.test", 4);
        fake.user(4, "Carol Coder", "carol@acme.test", null); // the manager appears after the people who report to her
        fake.group(10, "Database Team");
        fake.member(20, 10, 1);
        fake.member(21, 10, 99); // a person this source has not seen

        RunResult run = runNow();

        assertThat(run.state()).isEqualTo("APPLIED");
        assertThat(run.complete()).isTrue();
        Map<String, Object> row = jdbc.queryForMap("SELECT kind, state, rows_total, rows_created, rows_rejected, actor FROM identity_import_run WHERE id = ?", run.runId());
        assertThat(row).containsEntry("kind", "PROVIDER_SYNC").containsEntry("state", "APPLIED").containsEntry("rows_total", 7)
                .containsEntry("rows_created", 6).containsEntry("rows_rejected", 1).containsEntry("actor", ServiceNowDirectorySync.SYSTEM_ACTOR);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM identity_import_run WHERE source_id = ?", Integer.class, source)).isEqualTo(1);

        UUID ada = person(1);
        UUID bob = person(3);
        UUID carol = person(4);
        assertThat(person(2)).isEqualTo(grace.id());
        assertThat(directory.user(grace.id()).orElseThrow().displayName()).as("a manual person keeps their name").isEqualTo("Grace Hopper");
        assertThat(directory.user(grace.id()).orElseThrow().managerUserId()).as("and their manager").isNull();
        assertThat(directory.user(bob).orElseThrow().managerUserId()).isEqualTo(carol);
        assertThat(directory.user(ada).orElseThrow().email()).isEqualTo("ada@acme.test");

        UUID group = jdbc.queryForObject("SELECT group_id FROM external_group WHERE source_id = ?", UUID.class, source);
        assertThat(jdbc.queryForMap("SELECT display_name, created_source_id FROM directory_group WHERE id = ?", group))
                .containsEntry("display_name", "Database Team").containsEntry("created_source_id", source);
        assertThat(jdbc.queryForMap("SELECT user_id, status, last_seen_run_id FROM directory_group_member WHERE group_id = ?", group))
                .containsEntry("user_id", ada).containsEntry("status", "ACTIVE").containsEntry("last_seen_run_id", run.runId());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM external_identity WHERE source_id = ? AND last_seen_run_id = ?", Integer.class,
                source, run.runId())).isEqualTo(4);

        assertThat(jdbc.queryForMap("SELECT health, last_success_at IS NOT NULL AS succeeded, sync_cursor FROM identity_source WHERE id = ?", source))
                .containsEntry("health", "HEALTHY").containsEntry("succeeded", true);
        assertThat(cursor()).contains("sys_user", "sys_user_group", "sys_user_grmember", sysId(4)).doesNotContain("acme.test");
        assertThat(jdbc.queryForObject("SELECT details_json::text FROM audit_events WHERE target_id = ? AND action = 'ownership.identity_source.synced'",
                String.class, source.toString())).contains("APPLIED").doesNotContain("acme.test").doesNotContain("Lovelace");

        assertThat(sync.runSource(tenant, source)).as("not due again until the schedule passes").isEmpty();
    }

    @Test
    void anIncrementalRunStartsAtTheCursorUpdatesOnlyThisSourcesPeopleAndNeverDeactivates() {
        DirectoryUser grace = directory.createUser("Grace Hopper", "grace@acme.test", null, null, manual, "admin");
        fake.user(1, "Ada Lovelace", "ada@acme.test", null);
        fake.user(2, "Grace Hopper", "grace@acme.test", null);
        fake.group(10, "Database Team");
        fake.member(20, 10, 1);
        runNow();
        UUID ada = person(1);

        fake.user(1, "Ada King", "ada.king@acme.test", null);
        fake.user(2, "Grace B. Hopper", "grace@acme.test", null);
        fake.remove(DirectoryTable.GROUPS, 10);
        fake.remove(DirectoryTable.MEMBERSHIPS, 20);
        makeDue();
        clearInvocations(client);

        RunResult run = runNow();

        assertThat(run.complete()).isFalse();
        assertThat(run.state()).isEqualTo("APPLIED");
        verify(client, atLeastOnce()).fetchPage(any(), eq(DirectoryTable.USERS), any(), argThat(c -> c != null), anyInt());
        verify(client, never()).fetchPage(any(), eq(DirectoryTable.USERS), any(), isNull(), anyInt());
        DirectoryUser updated = directory.user(ada).orElseThrow();
        assertThat(updated.displayName()).isEqualTo("Ada King");
        assertThat(updated.email()).isEqualTo("ada.king@acme.test");
        assertThat(directory.user(grace.id()).orElseThrow().displayName()).isEqualTo("Grace Hopper");
        assertThat(jdbc.queryForObject("SELECT status FROM external_group WHERE source_id = ?", String.class, source)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM directory_group_member WHERE source_id = ?", String.class, source)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT rows_updated FROM identity_import_run WHERE id = ?", Integer.class, run.runId())).isEqualTo(1);
    }

    @Test
    void aCompleteScanDeactivatesAbsentRowsButNeverPeopleFromAnotherSource() {
        DirectoryUser grace = directory.createUser("Grace Hopper", "grace@acme.test", null, null, manual, "admin");
        fake.user(1, "Ada Lovelace", "ada@acme.test", null);
        fake.user(2, "Grace Hopper", "grace@acme.test", null);
        fake.user(3, "Bob Byte", "bob@acme.test", null);
        fake.group(10, "Database Team");
        fake.member(20, 10, 1);
        runNow();
        UUID ada = person(1);

        fake.remove(DirectoryTable.USERS, 1);
        fake.remove(DirectoryTable.USERS, 2);
        fake.remove(DirectoryTable.GROUPS, 10);
        fake.remove(DirectoryTable.MEMBERSHIPS, 20);
        assertThat(sources.syncNow(source, true, "admin").complete()).isTrue();

        RunResult run = runNow();

        assertThat(run.complete()).isTrue();
        assertThat(run.state()).isEqualTo("APPLIED");
        assertThat(identityStatus(1)).isEqualTo("INACTIVE");
        assertThat(identityStatus(2)).isEqualTo("INACTIVE");
        assertThat(identityStatus(3)).isEqualTo("ACTIVE");
        assertThat(directory.user(ada).orElseThrow().status()).isEqualTo("INACTIVE");
        assertThat(directory.user(grace.id()).orElseThrow().status()).as("a manual person is never deactivated by the sync").isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM external_group WHERE source_id = ?", String.class, source)).isEqualTo("INACTIVE");
        assertThat(jdbc.queryForObject("SELECT g.status FROM directory_group g JOIN external_group e ON e.group_id = g.id WHERE e.source_id = ?",
                String.class, source)).isEqualTo("INACTIVE");
        assertThat(jdbc.queryForObject("SELECT status FROM directory_group_member WHERE source_id = ?", String.class, source)).isEqualTo("REMOVED");
        assertThat(jdbc.queryForObject("SELECT actor FROM identity_import_run WHERE id = ?", String.class, run.runId())).isEqualTo("admin");

        fake.user(1, "Ada Lovelace", "ada@acme.test", null);
        makeDue();
        runNow();
        assertThat(directory.user(ada).orElseThrow().status()).as("an active identity reactivates its person").isEqualTo("ACTIVE");
    }

    @Test
    void aFailedRunChangesNoStatusKeepsTheCursorAtTheLastCommittedPageAndThreeFailuresSetError() {
        fake.pageCap = 2;
        fake.user(1, "Ada Lovelace", "ada@acme.test", null);
        fake.user(2, "Bob Byte", "bob@acme.test", null);
        fake.user(3, "Carol Coder", "carol@acme.test", null);
        fake.failOn(DirectoryTable.USERS, 4); // pass one reads two pages; the apply pass fails on its second page

        RunResult failed = runNow();

        assertThat(failed.state()).isEqualTo("FAILED");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM external_identity WHERE source_id = ?", Integer.class, source)).isEqualTo(2);
        assertThat(cursor()).contains(sysId(2)).doesNotContain(sysId(3));
        Map<String, Object> state = jdbc.queryForMap("SELECT state, health, last_error, last_success_at FROM identity_source WHERE id = ?", source);
        assertThat(state).containsEntry("state", "ENABLED").containsEntry("health", "DEGRADED").containsEntry("last_success_at", null);
        assertThat((String) state.get("last_error")).startsWith("UNAVAILABLE").doesNotContain("acme.test");
        assertThat(jdbc.queryForObject("SELECT error_summary FROM identity_import_run WHERE id = ?", String.class, failed.runId())).startsWith("UNAVAILABLE");

        // A complete scan that fails on a later table deactivates nothing, even for tables it finished.
        fake.failOn(DirectoryTable.USERS, null);
        fake.remove(DirectoryTable.USERS, 1);
        fake.failOn(DirectoryTable.GROUPS, -1);
        sources.syncNow(source, true, "admin");
        assertThat(runNow().state()).isEqualTo("FAILED");
        assertThat(identityStatus(1)).isEqualTo("ACTIVE");
        assertThat(jdbc.queryForObject("SELECT state FROM identity_source WHERE id = ?", String.class, source)).isEqualTo("ENABLED");

        sources.syncNow(source, false, "admin");
        assertThat(runNow().state()).isEqualTo("FAILED");
        assertThat(jdbc.queryForMap("SELECT state, health FROM identity_source WHERE id = ?", source))
                .containsEntry("state", "ERROR").containsEntry("health", "FAILING");
        assertThat(sync.runSource(tenant, source)).isEmpty();
    }

    @Test
    void anAnomalousTableWritesNothingPausesTheSourceAndResumingApprovesIt() {
        for (int i = 1; i <= 120; i++) fake.user(i, "Person " + i, "person" + i + "@acme.test", null);
        fake.group(500, "Database Team");
        RunResult baseline = runNow();
        assertThat(baseline.state()).as("baseline creates stay under the absolute limit").isEqualTo("APPLIED");

        for (int i = 1; i <= 120; i++) fake.remove(DirectoryTable.USERS, i);
        fake.group(500, "Database Platform");
        sources.syncNow(source, true, "admin");

        RunResult held = runNow();

        assertThat(held.state()).isEqualTo("PARTIAL");
        assertThat(held.anomalyTables()).containsExactly("sys_user");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM external_identity WHERE source_id = ? AND status = 'ACTIVE'", Integer.class, source))
                .as("the held table wrote nothing").isEqualTo(120);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM directory_user WHERE status = 'ACTIVE'", Integer.class)).isEqualTo(120);
        assertThat(jdbc.queryForObject("SELECT display_name FROM directory_group", String.class)).as("other tables still apply")
                .isEqualTo("Database Platform");
        Map<String, Object> state = jdbc.queryForMap("SELECT state, last_error FROM identity_source WHERE id = ?", source);
        assertThat(state).containsEntry("state", "PAUSED");
        assertThat((String) state.get("last_error")).contains("ANOMALY_PAUSED").contains("sys_user");
        String key = ServiceNowDirectorySync.anomalyKey(source, "sys_user");
        assertThat(jdbc.queryForMap("SELECT item_type, state, source_kind, details::text AS details FROM ownership_review_item WHERE dedupe_key = ?", key))
                .containsEntry("item_type", "PRODUCER_ANOMALY").containsEntry("state", "OPEN").containsEntry("source_kind", "SERVICENOW");
        assertThat(jdbc.queryForObject("SELECT details::text FROM ownership_review_item WHERE dedupe_key = ?", String.class, key))
                .contains("\"wouldDeactivate\": 120").doesNotContain("acme.test").doesNotContain("Person");
        assertStatus(409, () -> sources.syncNow(source, false, "admin"));
        assertThat(sync.runSource(tenant, source)).as("a paused source does not run").isEmpty();

        sources.resume(source, "admin");
        RunResult approved = runNow();

        assertThat(approved.state()).isEqualTo("APPLIED");
        assertThat(approved.complete()).as("the approved changes came from a complete scan").isTrue();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM external_identity WHERE source_id = ? AND status = 'ACTIVE'", Integer.class, source)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM directory_user WHERE status = 'ACTIVE'", Integer.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT state FROM ownership_review_item WHERE dedupe_key = ?", String.class, key)).isEqualTo("RESOLVED");
        assertThat(jdbc.queryForObject("SELECT state FROM identity_source WHERE id = ?", String.class, source)).isEqualTo("ENABLED");
    }

    @Test
    void syncNowNeedsAnEnabledSourceReusesTheQueuedRunAndTheKillSwitchHoldsIt() {
        jdbc.update("UPDATE identity_source SET state = 'DISABLED' WHERE id = ?", source);
        assertStatus(409, () -> sources.syncNow(source, false, "admin"));
        jdbc.update("UPDATE identity_source SET state = 'ENABLED' WHERE id = ?", source);

        UUID queued = sources.syncNow(source, false, "admin").runId();
        assertThat(sources.syncNow(source, true, "admin").runId()).isEqualTo(queued);
        assertThat(jdbc.queryForObject("SELECT cursor_start::jsonb ->> 'complete' FROM identity_import_run WHERE id = ?", String.class, queued))
                .isEqualTo("true");

        jdbc.update("""
                INSERT INTO platform.ownership_kill_switches (id, source_kind, tenant_id, state, reason, updated_by)
                VALUES (?, 'SERVICENOW', ?, 'PAUSED', 'incident', 'operator')
                """, UUID.randomUUID(), tenant.getId());
        assertStatus(409, () -> sources.syncNow(source, false, "admin"));
        assertThat(sync.runSource(tenant, source)).isEmpty();
        assertThat(jdbc.queryForObject("SELECT state FROM identity_import_run WHERE id = ?", String.class, queued)).isEqualTo("QUEUED");
        verify(client, never()).fetchPage(any(), any(), any(), any(), anyInt());

        jdbc.update("DELETE FROM platform.ownership_kill_switches WHERE tenant_id = ?", tenant.getId());
        assertThat(runNow().runId()).isEqualTo(queued);
    }

    @Test
    void aRunLeftRunningByADeadWorkerIsEndedAsFailedBeforeTheNextClaim() {
        UUID stale = sources.syncNow(source, false, "admin").runId();
        jdbc.update("UPDATE identity_import_run SET state = 'RUNNING', started_at = now() - interval '5 hours', created_at = now() - interval '2 days' WHERE id = ?",
                stale);
        fake.user(1, "Ada Lovelace", "ada@acme.test", null);

        RunResult next = runNow();

        assertThat(next.runId()).isNotEqualTo(stale);
        assertThat(jdbc.queryForMap("SELECT state, error_summary FROM identity_import_run WHERE id = ?", stale))
                .containsEntry("state", "FAILED").containsEntry("error_summary", "STALE_RUN");
        assertThat(next.state()).isEqualTo("APPLIED");
    }

    // ----- helpers ------------------------------------------------------------------------------------------

    private RunResult runNow() {
        Optional<RunResult> run = sync.runSource(tenant, source);
        assertThat(run).as("a run was claimed").isPresent();
        return run.get();
    }

    private void makeDue() {
        jdbc.update("UPDATE identity_import_run SET created_at = created_at - interval '2 days' WHERE source_id = ?", source);
    }

    private UUID person(int sysId) {
        return directory.userIdByExternalId(source, sysId(sysId)).orElseThrow();
    }

    /** Every identity in these tests is linked, so its person identifies it. */
    private String identityStatus(int sysId) {
        return jdbc.queryForObject("SELECT status FROM external_identity WHERE source_id = ? AND user_id = ?", String.class, source, person(sysId));
    }

    private String cursor() {
        return jdbc.queryForObject("SELECT sync_cursor FROM identity_source WHERE id = ?", String.class, source);
    }

    static String sysId(int n) {
        return String.format("%032x", n);
    }

    private static void assertStatus(int status, Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode().value()).isEqualTo(status));
    }

    /** An in-memory ServiceNow with keyset paging, an optional page cap and injected failures. */
    private static final class FakeServiceNow {
        final Map<DirectoryTable, Map<String, Map<String, String>>> rows = new EnumMap<>(DirectoryTable.class);
        final Map<DirectoryTable, Integer> calls = new EnumMap<>(DirectoryTable.class);
        final Map<DirectoryTable, Integer> failOn = new EnumMap<>(DirectoryTable.class);
        int pageCap = 500;
        int clock;

        FakeServiceNow() {
            for (DirectoryTable table : DirectoryTable.values()) rows.put(table, new LinkedHashMap<>());
        }

        void user(int id, String name, String email, Integer manager) {
            Map<String, String> row = new LinkedHashMap<>();
            row.put("sys_id", sysId(id));
            row.put("name", name);
            row.put("email", email);
            row.put("user_name", "user" + id);
            row.put("active", "true");
            row.put("locked_out", "false");
            if (manager != null) row.put("manager", sysId(manager));
            put(DirectoryTable.USERS, row);
        }

        void group(int id, String name) {
            put(DirectoryTable.GROUPS, new LinkedHashMap<>(Map.of("sys_id", sysId(id), "name", name, "active", "true")));
        }

        void member(int id, int group, int user) {
            put(DirectoryTable.MEMBERSHIPS, new LinkedHashMap<>(Map.of("sys_id", sysId(id), "group", sysId(group), "user", sysId(user))));
        }

        void remove(DirectoryTable table, int id) {
            rows.get(table).remove(sysId(id));
        }

        /** Fail the {@code call}-th fetch of {@code table}; -1 fails every fetch, null stops failing. */
        void failOn(DirectoryTable table, Integer call) {
            calls.remove(table);
            if (call == null) failOn.remove(table);
            else failOn.put(table, call);
        }

        private void put(DirectoryTable table, Map<String, String> row) {
            row.put("sys_updated_on", LocalDateTime.of(2026, 11, 1, 0, 0).plusSeconds(++clock).format(SN_TIME));
            rows.get(table).put(row.get("sys_id"), row);
        }

        Page page(InvocationOnMock invocation) {
            DirectoryTable table = invocation.getArgument(1);
            Cursor after = invocation.getArgument(3);
            int size = invocation.getArgument(4);
            int call = calls.merge(table, 1, Integer::sum);
            Integer fail = failOn.get(table);
            if (fail != null && (fail < 0 || fail == call)) {
                throw new ServiceNowDirectoryException(FailureKind.UNAVAILABLE, 503,
                        "ServiceNow did not respond successfully while reading " + table.tableName() + " (HTTP 503)");
            }
            List<Map<String, String>> sorted = new ArrayList<>(rows.get(table).values().stream()
                    .filter(row -> cursorOf(row).isAfter(after))
                    .sorted(Comparator.comparing((Map<String, String> row) -> row.get("sys_updated_on")).thenComparing(row -> row.get("sys_id")))
                    .toList());
            int limit = Math.min(size, pageCap);
            List<Map<String, String>> page = List.copyOf(sorted.subList(0, Math.min(limit, sorted.size())));
            Cursor next = page.isEmpty() ? after : cursorOf(page.get(page.size() - 1));
            return new Page(page, next, sorted.size() <= limit, size);
        }

        private static Cursor cursorOf(Map<String, String> row) {
            return new Cursor(row.get("sys_updated_on"), row.get("sys_id"));
        }
    }
}
