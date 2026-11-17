package com.prototype.vulnwatch.service.ownership;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.Connection;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.Cursor;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.DirectoryTable;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.Page;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient.ServiceNowDirectoryException;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantWorkRunner;
import com.prototype.vulnwatch.service.ownership.DirectoryImportService.ProviderRunCounts;
import com.prototype.vulnwatch.service.ownership.DirectoryImportService.ProviderRunStart;
import com.prototype.vulnwatch.service.ownership.DirectoryService.IdentityObservation;
import com.prototype.vulnwatch.service.ownership.DirectoryService.ObservedGroup;
import com.prototype.vulnwatch.service.ownership.DirectoryService.ObservedIdentity;
import com.prototype.vulnwatch.service.ownership.DirectoryService.RowChange;
import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;

/**
 * The durable ServiceNow directory sync (Phase 0B contract §1.3, §1.5, §1.7). Each worker tick claims at most one
 * run per enabled source: a queued run (enable, resume, sync-now) or a scheduled one. Every run is one
 * {@code identity_import_run} of kind {@code PROVIDER_SYNC}, which is also the job record a crashed worker leaves
 * behind; the next claim ends a stale one as FAILED.
 *
 * <p>Tables are synced in order (people, groups, memberships), so memberships see this run's links. For each table
 * a read-only pass counts the changes the run proposes and applies {@link OwnershipSourcePolicy#anomalous}; a table
 * that trips it writes nothing, raises a {@code PRODUCER_ANOMALY} review item and pauses the source at the end of
 * the run. Resuming is the approval: the next run skips the check for that table. Otherwise a second pass applies
 * the rows, one transaction per row, and stores the table's cursor after each page. Incremental runs start at the
 * stored cursor and never deactivate. Only a complete scan that read every table without an error marks absent
 * rows inactive or removed. A failed, cancelled or partial run changes no status.
 *
 * <p>Every transaction selects the tenant first and opens inside it ({@link TenantWorkRunner}); no transaction is
 * held across an HTTP call. Logs and run summaries carry IDs and failure codes only.
 */
@Component
public class ServiceNowDirectorySync {

    public record RunResult(UUID runId, String state, boolean complete, ProviderRunCounts counts, List<String> anomalyTables) { }

    static final String SYSTEM_ACTOR = "system:servicenow-directory-sync";
    static final Duration COMPLETE_EVERY = Duration.ofDays(7);
    static final int FAILURES_FOR_ERROR = 3;
    static final String REVIEW_ANOMALY = "PRODUCER_ANOMALY";
    private static final Duration STALE_MARGIN = Duration.ofMinutes(30);
    private static final String KIND = IdentitySourceService.KIND;
    private static final Logger LOG = LoggerFactory.getLogger(ServiceNowDirectorySync.class);

    /** Ends a run early: CANCELLED when the source stopped, FAILED when the run ran out of time. */
    private static final class RunStopped extends RuntimeException {
        private final String state;

        RunStopped(String state, String code) {
            super(code, null, false, false);
            this.state = state;
        }
    }

    private record PendingManager(String managerExternalId, boolean countedUnchanged) { }

    private static final class Run {
        final Tenant tenant;
        final UUID sourceId;
        final ProviderRunStart start;
        final Instant deadline;
        final Map<String, Cursor> cursors = new LinkedHashMap<>();
        final List<String> anomalyTables = new ArrayList<>();
        Connection connection;
        Map<String, String> filters = Map.of();
        int total;
        int created;
        int updated;
        int unchanged;
        int rejected;

        Run(Tenant tenant, UUID sourceId, ProviderRunStart start, Instant deadline) {
            this.tenant = tenant;
            this.sourceId = sourceId;
            this.start = start;
            this.deadline = deadline;
        }

        ProviderRunCounts counts() {
            return new ProviderRunCounts(total, created, updated, unchanged, rejected);
        }
    }

    private final TenantService tenants;
    private final TenantWorkRunner runner;
    private final JdbcTemplate jdbc;
    private final DirectoryService directory;
    private final DirectoryImportService runs;
    private final IdentitySourceService sources;
    private final ServiceNowDirectoryClient client;
    private final OwnershipClaimService claims;
    private final OwnershipReviewService reviews;
    private final TenantDataCipher cipher;
    private final AuditEventService audit;
    private final BackgroundTaskExecutionPolicy backgroundTasks;
    private final ObjectMapper json;
    private final GroupTeamMappingService mappings;
    private final boolean enabled;
    private final Duration maxRunDuration;

    public ServiceNowDirectorySync(TenantService tenants, TenantWorkRunner runner, JdbcTemplate jdbc, DirectoryService directory,
                                   DirectoryImportService runs, IdentitySourceService sources, ServiceNowDirectoryClient client,
                                   OwnershipClaimService claims, OwnershipReviewService reviews, TenantDataCipher cipher,
                                   AuditEventService audit, BackgroundTaskExecutionPolicy backgroundTasks, ObjectMapper json,
                                   GroupTeamMappingService mappings,
                                   @Value("${app.ownership.servicenow.directory-enabled:false}") boolean enabled,
                                   @Value("${app.ownership.servicenow.directory-sync.max-run-duration:PT4H}") Duration maxRunDuration) {
        this.mappings = mappings;
        this.tenants = tenants;
        this.runner = runner;
        this.jdbc = jdbc;
        this.directory = directory;
        this.runs = runs;
        this.sources = sources;
        this.client = client;
        this.claims = claims;
        this.reviews = reviews;
        this.cipher = cipher;
        this.audit = audit;
        this.backgroundTasks = backgroundTasks;
        this.json = json;
        this.enabled = enabled;
        this.maxRunDuration = maxRunDuration;
    }

    /** The worker tick, on the same five-minute UTC schedule as the other connector syncs. Does nothing while the switch is off. */
    @Scheduled(zone = "UTC", cron = "${app.ownership.servicenow.directory-sync.cron:0 */5 * * * *}")
    public void runScheduled() {
        if (!enabled) return;
        if (!backgroundTasks.allowsBackgroundTask("ownership.servicenow-directory-sync")) return;
        for (Tenant tenant : TenantContext.runAsPlatform(tenants::listActiveTenants)) {
            try {
                runForTenant(tenant);
            } catch (RuntimeException ex) {
                LOG.warn("ServiceNow directory sync failed for tenant {}: {}", tenant.getId(), ex.getClass().getSimpleName());
            }
        }
    }

    /** Runs each of the tenant's enabled ServiceNow sources that has a queued or due run. */
    public List<RunResult> runForTenant(Tenant tenant) {
        List<UUID> enabledSources = runner.runScoped(tenant, () -> {
            if (!cipher.readiness(tenant.getId()).ready() || claims.sourcePaused(KIND)) return List.<UUID>of();
            return jdbc.queryForList("SELECT id FROM identity_source WHERE kind = ? AND state = 'ENABLED' ORDER BY created_at", UUID.class, KIND);
        });
        List<RunResult> results = new ArrayList<>();
        for (UUID sourceId : enabledSources) {
            try {
                runSource(tenant, sourceId).ifPresent(results::add);
            } catch (RuntimeException ex) {
                LOG.warn("ServiceNow directory sync of source {} failed: {}", sourceId, ex.getClass().getSimpleName());
            }
        }
        return results;
    }

    /** Claims and executes at most one run of {@code sourceId}; empty when nothing is queued or due, or another run holds it. */
    public Optional<RunResult> runSource(Tenant tenant, UUID sourceId) {
        Optional<ProviderRunStart> claimed = runner.runScoped(tenant, () -> {
            if (!enabled || !cipher.readiness(tenant.getId()).ready() || claims.sourcePaused(KIND)) return Optional.<ProviderRunStart>empty();
            List<Map<String, Object>> source = jdbc.queryForList("SELECT state, schedule FROM identity_source WHERE id = ? AND kind = ?", sourceId, KIND);
            if (source.isEmpty() || !"ENABLED".equals(source.get(0).get("state"))) return Optional.<ProviderRunStart>empty();
            return runs.claimProviderRun(sourceId, schedule((String) source.get(0).get("schedule")), COMPLETE_EVERY,
                    maxRunDuration.plus(STALE_MARGIN), SYSTEM_ACTOR);
        });
        return claimed.map(start -> execute(tenant, sourceId, start));
    }

    private RunResult execute(Tenant tenant, UUID sourceId, ProviderRunStart start) {
        Run run = new Run(tenant, sourceId, start, Instant.now().plus(maxRunDuration));
        String state;
        String error = null;
        try {
            IdentitySourceService.SyncSetup setup = runner.runScoped(tenant, () -> sources.syncSetup(sourceId));
            run.connection = setup.connection();
            run.filters = setup.filters();
            run.cursors.putAll(runner.runScoped(tenant, () -> storedCursors(sourceId)));
            for (DirectoryTable table : DirectoryTable.values()) syncTable(run, table);
            if (start.complete()) reconcileAbsent(run);
            state = run.anomalyTables.isEmpty() ? "APPLIED" : "PARTIAL";
        } catch (RunStopped stopped) {
            state = stopped.state;
            error = stopped.getMessage();
        } catch (ServiceNowDirectoryException failure) {
            state = "FAILED";
            error = failure.kind().name() + ": " + failure.getMessage();
        } catch (RuntimeException failure) {
            state = "FAILED";
            error = "SYNC_ERROR: " + failure.getClass().getSimpleName();
            LOG.warn("ServiceNow directory sync run {} failed: {}", start.runId(), failure.getClass().getName());
        }
        finish(run, state, error);
        return new RunResult(start.runId(), state, start.complete(), run.counts(), List.copyOf(run.anomalyTables));
    }

    // ----- tables -------------------------------------------------------------------------------------------

    private void syncTable(Run run, DirectoryTable table) {
        String name = table.tableName();
        Cursor from = run.start.complete() ? null : run.cursors.get(name);
        boolean exempt = run.start.exemptTables().contains(name);
        if (!exempt) {
            Set<UUID> seenActive = new HashSet<>();
            long[] planned = new long[2];
            forEachPage(run, table, from, page -> runner.runScoped(run.tenant, () -> {
                for (Map<String, String> row : page.rows()) {
                    RowChange change = plan(run, table, row, seenActive);
                    if (change == RowChange.CREATED) planned[0]++;
                    else if (change == RowChange.UPDATED) planned[1]++;
                }
            }));
            long active = runner.runScoped(run.tenant, () -> directory.activeSourceRows(run.sourceId, name));
            long absent = run.start.complete() ? Math.max(0, active - seenActive.size()) : 0;
            if (OwnershipSourcePolicy.anomalous(planned[1] + absent, planned[0], active, run.start.baseline())) {
                hold(run, name, planned[0], planned[1], absent, active);
                return;
            }
        }
        Map<UUID, PendingManager> pendingManagers = new LinkedHashMap<>();
        forEachPage(run, table, from, page -> {
            for (Map<String, String> row : page.rows()) apply(run, table, row, pendingManagers);
            Cursor next = page.next();
            if (next != null && next.isAfter(run.cursors.get(name))) {
                run.cursors.put(name, next);
                String cursor = cursorJson(run.cursors);
                runner.runScoped(run.tenant, () -> directory.advanceSyncCursor(run.sourceId, cursor));
            }
        });
        if (table == DirectoryTable.USERS) resolvePendingManagers(run, pendingManagers);
        if (exempt) {
            runner.runScoped(run.tenant, () -> reviews.closeOpen(anomalyKey(run.sourceId, name), "RESOLVED",
                    "Approved by resuming the source", run.start.actor()));
        }
    }

    private void forEachPage(Run run, DirectoryTable table, Cursor from, Consumer<Page> work) {
        Cursor after = from;
        int size = ServiceNowDirectoryClient.DEFAULT_PAGE_SIZE;
        while (true) {
            checkStillRunning(run);
            Page page = client.fetchPage(run.connection, table, run.filters.get(table.tableName()), after, size);
            size = page.pageSize();
            work.accept(page);
            if (page.last() || page.rows().isEmpty()) return;
            after = page.next();
        }
    }

    private void checkStillRunning(Run run) {
        if (Instant.now().isAfter(run.deadline)) throw new RunStopped("FAILED", "RUN_TIMEOUT");
        String stop = runner.runScoped(run.tenant, () -> {
            if (claims.sourcePaused(KIND)) return "KILL_SWITCH";
            List<String> state = jdbc.queryForList("SELECT state FROM identity_source WHERE id = ?", String.class, run.sourceId);
            return state.isEmpty() || !"ENABLED".equals(state.get(0)) ? "SOURCE_NOT_ENABLED" : null;
        });
        if (stop != null) throw new RunStopped("CANCELLED", stop);
    }

    private RowChange plan(Run run, DirectoryTable table, Map<String, String> row, Set<UUID> seenActive) {
        try {
            return switch (table) {
                case USERS -> directory.planIdentity(identity(run.sourceId, row), seenActive);
                case GROUPS -> directory.planGroup(group(run.sourceId, row), seenActive);
                case MEMBERSHIPS -> {
                    if (row.get("group") == null || row.get("user") == null) yield null;
                    yield directory.planMembership(run.sourceId, row.get("group"), row.get("user"), seenActive);
                }
            };
        } catch (ResponseStatusException invalid) {
            if (invalid.getStatusCode().is5xxServerError()) throw invalid;
            return null;
        }
    }

    /** One row in its own transaction, so a row the directory refuses is counted as rejected without undoing the others. */
    private void apply(Run run, DirectoryTable table, Map<String, String> row, Map<UUID, PendingManager> pendingManagers) {
        run.total++;
        RowChange change;
        try {
            change = runner.runScoped(run.tenant, () -> switch (table) {
                case USERS -> applyUser(run, row, pendingManagers);
                case GROUPS -> applyGroup(run, row);
                case MEMBERSHIPS -> applyMembership(run, row);
            });
        } catch (ResponseStatusException invalid) {
            if (invalid.getStatusCode().is5xxServerError()) throw invalid;
            change = null;
        }
        if (change == null) run.rejected++;
        else if (change == RowChange.CREATED) run.created++;
        else if (change == RowChange.UPDATED) run.updated++;
        else run.unchanged++;
    }

    private RowChange applyUser(Run run, Map<String, String> row, Map<UUID, PendingManager> pendingManagers) {
        IdentityObservation observed = directory.observeIdentity(identity(run.sourceId, row), run.start.runId(), run.start.actor());
        RowChange change = observed.change();
        if (observed.userId() == null) return change;
        String managerRef = row.get("manager");
        Optional<UUID> manager = managerRef == null ? Optional.empty() : directory.userIdByExternalId(run.sourceId, managerRef);
        if (managerRef != null && manager.isEmpty()) {
            // The manager may appear later in this run; otherwise the next run that reads this row retries.
            pendingManagers.put(observed.userId(), new PendingManager(managerRef, change == RowChange.UNCHANGED));
            return change;
        }
        boolean managerChanged = directory.setSourceManager(observed.userId(), manager.orElse(null), run.sourceId, run.start.actor());
        return managerChanged && change == RowChange.UNCHANGED ? RowChange.UPDATED : change;
    }

    /** §1.8: a group whose name exactly equals a team name or alias gets a SUGGESTED mapping, never an active one. */
    private RowChange applyGroup(Run run, Map<String, String> row) {
        DirectoryService.GroupObservation observed = directory.observeGroup(group(run.sourceId, row), run.start.runId(), run.start.actor());
        if (row.get("name") != null) mappings.suggest(observed.externalGroupId(), row.get("name"), SYSTEM_ACTOR);
        return observed.change();
    }

    /** A membership whose person or group is not linked yet is rejected and retried when the row is read again. */
    private RowChange applyMembership(Run run, Map<String, String> row) {
        if (row.get("group") == null || row.get("user") == null) return null;
        Optional<UUID> group = directory.groupIdByExternalId(run.sourceId, row.get("group"));
        Optional<UUID> user = directory.userIdByExternalId(run.sourceId, row.get("user"));
        if (group.isEmpty() || user.isEmpty()) return null;
        return directory.observeMembership(group.get(), user.get(), run.sourceId, run.start.runId());
    }

    private void resolvePendingManagers(Run run, Map<UUID, PendingManager> pending) {
        for (Map.Entry<UUID, PendingManager> entry : pending.entrySet()) {
            boolean changed;
            try {
                changed = runner.runScoped(run.tenant, () -> directory.userIdByExternalId(run.sourceId, entry.getValue().managerExternalId())
                        .map(manager -> directory.setSourceManager(entry.getKey(), manager, run.sourceId, run.start.actor())).orElse(false));
            } catch (ResponseStatusException invalid) {
                if (invalid.getStatusCode().is5xxServerError()) throw invalid;
                changed = false;
            }
            if (changed && entry.getValue().countedUnchanged()) {
                run.unchanged--;
                run.updated++;
            }
        }
    }

    /** Complete scans only, after every table was read without an error. Tables held by an anomaly are left alone. */
    private void reconcileAbsent(Run run) {
        UUID runId = run.start.runId();
        if (!run.anomalyTables.contains(DirectoryTable.USERS.tableName())) {
            run.updated += runner.runScoped(run.tenant, () -> directory.deactivateAbsentIdentities(run.sourceId, runId));
            run.updated += runner.runScoped(run.tenant, () -> directory.deactivateSourcePeople(run.sourceId, runId));
        }
        if (!run.anomalyTables.contains(DirectoryTable.GROUPS.tableName())) {
            run.updated += runner.runScoped(run.tenant, () -> directory.deactivateAbsentGroups(run.sourceId, runId));
        }
        if (!run.anomalyTables.contains(DirectoryTable.MEMBERSHIPS.tableName())) {
            run.updated += runner.runScoped(run.tenant, () -> directory.removeAbsentMemberships(run.sourceId, runId));
        }
    }

    private void hold(Run run, String table, long creates, long updates, long deactivations, long active) {
        run.anomalyTables.add(table);
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("sourceId", run.sourceId.toString());
        details.put("runId", run.start.runId().toString());
        details.put("table", table);
        details.put("wouldCreate", creates);
        details.put("wouldUpdate", updates);
        details.put("wouldDeactivate", deactivations);
        details.put("activeRows", active);
        details.put("baselineLoad", run.start.baseline());
        details.put("minChanges", OwnershipSourcePolicy.ANOMALY_MIN_CHANGES);
        details.put("fraction", OwnershipSourcePolicy.ANOMALY_FRACTION);
        details.put("absoluteChanges", OwnershipSourcePolicy.ANOMALY_ABSOLUTE_CHANGES);
        runner.runScoped(run.tenant, () -> reviews.raise(REVIEW_ANOMALY, anomalyKey(run.sourceId, table), null, KIND, details));
    }

    private void finish(Run run, String state, String error) {
        UUID sourceId = run.sourceId;
        Map<String, Object> cursorEnd = new LinkedHashMap<>();
        cursorEnd.put("tables", cursorMap(run.cursors));
        cursorEnd.put("anomalyTables", List.copyOf(run.anomalyTables));
        runner.runScoped(run.tenant, () -> {
            runs.finishProviderRun(run.start.runId(), state, run.counts(), cursorEnd, error);
            switch (state) {
                case "APPLIED" -> directory.recordProviderSyncOutcome(sourceId, "HEALTHY", true, null);
                case "PARTIAL" -> {
                    directory.recordProviderSyncOutcome(sourceId, "HEALTHY", false, "ANOMALY_PAUSED: " + String.join(", ", run.anomalyTables));
                    directory.setProviderSourceState(sourceId, KIND, List.of("ENABLED"), "PAUSED");
                }
                case "FAILED" -> {
                    boolean toError = runs.consecutiveProviderFailures(sourceId, FAILURES_FOR_ERROR) >= FAILURES_FOR_ERROR;
                    directory.recordProviderSyncOutcome(sourceId, toError ? "FAILING" : "DEGRADED", false, error);
                    if (toError) directory.setProviderSourceState(sourceId, KIND, List.of("ENABLED"), "ERROR");
                }
                default -> { }
            }
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("runId", run.start.runId().toString());
            details.put("state", state);
            details.put("complete", run.start.complete());
            details.put("created", run.created);
            details.put("updated", run.updated);
            details.put("rejected", run.rejected);
            details.put("anomalyTables", List.copyOf(run.anomalyTables));
            audit.record("ownership.identity_source.synced", "identity_source", sourceId.toString(), OwnershipEvents.json(details),
                    "APPLIED".equals(state) ? "SUCCESS" : "FAILURE");
        });
    }

    // ----- mapping and cursors ------------------------------------------------------------------------------

    /** §1.3: {@code active = false} or {@code locked_out = true} is inactive. A missing {@code active} field is not read as inactive. */
    static ObservedIdentity identity(UUID sourceId, Map<String, String> row) {
        String name = row.get("name");
        if (name == null) {
            String joined = String.join(" ", java.util.stream.Stream.of(row.get("first_name"), row.get("last_name"))
                    .filter(java.util.Objects::nonNull).toList());
            name = joined.isBlank() ? null : joined;
        }
        boolean active = !"false".equalsIgnoreCase(row.get("active")) && !"true".equalsIgnoreCase(row.get("locked_out"));
        return new ObservedIdentity(sourceId, row.get("sys_id"), name, row.get("email"), row.get("user_name"), row.get("employee_number"), active);
    }

    static ObservedGroup group(UUID sourceId, Map<String, String> row) {
        return new ObservedGroup(sourceId, row.get("sys_id"), row.get("name"), !"false".equalsIgnoreCase(row.get("active")));
    }

    static String anomalyKey(UUID sourceId, String table) {
        return "PRODUCER_ANOMALY|identity-source|" + sourceId + "|" + table;
    }

    private Map<String, Cursor> storedCursors(UUID sourceId) {
        List<String> rows = jdbc.queryForList("SELECT sync_cursor FROM identity_source WHERE id = ?", String.class, sourceId);
        String stored = rows.isEmpty() ? null : rows.get(0); // the list holds a null before the first run
        Map<String, Cursor> cursors = new LinkedHashMap<>();
        if (stored == null || stored.isBlank()) return cursors;
        try {
            JsonNode root = json.readTree(stored);
            for (DirectoryTable table : DirectoryTable.values()) {
                JsonNode entry = root.path(table.tableName());
                if (entry.isObject()) {
                    try {
                        cursors.put(table.tableName(), new Cursor(entry.path("updatedOn").asText(null), entry.path("sysId").asText(null)));
                    } catch (IllegalArgumentException unusable) {
                        // An unusable cursor reads that table from the start, which is safe: observations are idempotent.
                    }
                }
            }
        } catch (JsonProcessingException unreadable) {
            return cursors;
        }
        return cursors;
    }

    private static Map<String, Object> cursorMap(Map<String, Cursor> cursors) {
        Map<String, Object> out = new LinkedHashMap<>();
        cursors.forEach((table, cursor) -> out.put(table, Map.of("updatedOn", cursor.updatedOn(), "sysId", cursor.sysId())));
        return out;
    }

    private String cursorJson(Map<String, Cursor> cursors) {
        try {
            return json.writeValueAsString(cursorMap(cursors));
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static Duration schedule(String value) {
        try {
            return OwnershipSourcePolicy.requireValidInterval(Duration.parse(value == null ? IdentitySourceService.DEFAULT_SCHEDULE.toString() : value));
        } catch (DateTimeParseException | IllegalArgumentException invalid) {
            return IdentitySourceService.DEFAULT_SCHEDULE;
        }
    }
}
