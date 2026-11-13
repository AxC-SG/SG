package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantWorkRunner;
import com.prototype.vulnwatch.service.ownership.DirectoryService.DirectoryGroup;
import com.prototype.vulnwatch.service.ownership.DirectoryService.DirectoryUser;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * CSV import of people, groups, memberships, teams and aliases (plan §6.3). {@link #preview} is a dry run that
 * changes nothing except recording the run; {@link #commit} requires the same file (by SHA-256), the same tenant and
 * importer, and an unexpired preview. Rows apply one per transaction, so one bad row never rolls back the others and
 * a replay is idempotent. Row messages never echo cell values, so they are safe to download.
 */
@Service
public class DirectoryImportService {

    public enum Kind {
        USERS("CSV_USERS", List.of("external_id", "display_name", "email", "manager_external_id", "status")),
        GROUPS("CSV_GROUPS", List.of("external_id", "display_name", "status")),
        MEMBERSHIPS("CSV_MEMBERSHIPS", List.of("group_external_id", "user_external_id", "operation")),
        TEAMS("CSV_TEAMS", List.of("name", "parent_team", "ticket_assignment_group")),
        TEAM_ALIASES("CSV_TEAM_ALIASES", List.of("source_kind", "alias", "team_name"));

        final String runKind;
        final List<String> headers;

        Kind(String runKind, List<String> headers) {
            this.runKind = runKind;
            this.headers = headers;
        }

        public List<String> headers() {
            return headers;
        }
    }

    public enum Outcome { CREATE, UPDATE, UNCHANGED, DUPLICATE, AMBIGUOUS, REJECTED }

    public record RowResult(int row, Outcome outcome, String message) { }

    public record Report(UUID runId, Kind kind, String state, Map<Outcome, Integer> counts, List<RowResult> rows, List<RowResult> warnings) { }

    static final Duration PREVIEW_TTL = Duration.ofMinutes(30);
    private static final int MAX_REPORTED_ROWS = 1_000;

    private interface Row {
        RowResult plan();

        void apply();
    }

    private final JdbcTemplate jdbc;
    private final DirectoryService directory;
    private final TeamNamespaceService teams;
    private final OwnershipReviewService reviews;
    private final TenantDataCipher cipher;
    private final TenantWorkRunner runner;
    private final AuditEventService audit;

    public DirectoryImportService(JdbcTemplate jdbc, DirectoryService directory, TeamNamespaceService teams,
                                  OwnershipReviewService reviews, TenantDataCipher cipher, TenantWorkRunner runner,
                                  AuditEventService audit) {
        this.jdbc = jdbc;
        this.directory = directory;
        this.teams = teams;
        this.reviews = reviews;
        this.cipher = cipher;
        this.runner = runner;
        this.audit = audit;
    }

    public static String template(Kind kind) {
        return String.join(",", kind.headers) + "\r\n";
    }

    /** Dry run: validates every row against current state and records a VALIDATED run. No directory data changes. */
    public Report preview(Kind kind, byte[] file, String actor) {
        UUID tenant = requireTenant();
        List<List<String>> records = parseOrReject(file);
        UUID runId = UUID.randomUUID();
        Plan plan = runner.runScoped(tenant, () -> plan(kind, records, actor));
        runner.runScoped(tenant, () -> {
            UUID source = directory.csvSource(actor);
            jdbc.update("""
                    INSERT INTO identity_import_run (tenant_id, id, source_id, kind, state, file_sha256, rows_total, rows_created, rows_updated,
                                                     rows_unchanged, rows_rejected, actor)
                    VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, 'VALIDATED', ?, ?, ?, ?, ?, ?, ?)
                    """, runId, source, kind.runKind, sha256(file), records.size() - 1, plan.count(Outcome.CREATE),
                    plan.count(Outcome.UPDATE), plan.count(Outcome.UNCHANGED), plan.rejectedCount(), actor);
        });
        return plan.report(runId, kind, "VALIDATED");
    }

    /** Applies a previewed file. The token is the preview's run ID and is bound to file hash, tenant, importer and expiry. */
    public Report commit(UUID previewToken, byte[] file, String actor) {
        UUID tenant = requireTenant();
        Map<String, Object> run = runner.runScoped(tenant, () -> jdbc.queryForList("""
                SELECT kind, state, file_sha256, actor, created_at > now() - make_interval(secs => ?) AS fresh
                  FROM identity_import_run WHERE id = ? FOR UPDATE
                """, PREVIEW_TTL.toSeconds(), previewToken).stream().findFirst().map(row -> {
            if (!"VALIDATED".equals(row.get("state")) || !Boolean.TRUE.equals(row.get("fresh"))
                    || !actor.equals(row.get("actor")) || !sha256(file).equals(row.get("file_sha256"))) {
                return null;
            }
            jdbc.update("UPDATE identity_import_run SET state = 'RUNNING', started_at = now() WHERE id = ?", previewToken);
            return row;
        }).orElse(null));
        if (run == null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "This preview is expired, already used, or for a different file or user; preview again");
        }
        Kind kind = java.util.Arrays.stream(Kind.values()).filter(k -> k.runKind.equals(run.get("kind"))).findFirst().orElseThrow();
        List<List<String>> records = parseOrReject(file);
        Plan plan = runner.runScoped(tenant, () -> plan(kind, records, actor));
        Map<Outcome, Integer> applied = new EnumMap<>(Outcome.class);
        List<RowResult> failures = new ArrayList<>();
        for (int i = 0; i < plan.rows.size(); i++) {
            Row row = plan.rows.get(i);
            RowResult planned = plan.results.get(i);
            if (planned.outcome() == Outcome.CREATE || planned.outcome() == Outcome.UPDATE) {
                try {
                    runner.runScoped(tenant, row::apply);
                    applied.merge(planned.outcome(), 1, Integer::sum);
                } catch (ResponseStatusException ex) {
                    failures.add(new RowResult(planned.row(), Outcome.REJECTED, ex.getReason()));
                }
            } else {
                applied.merge(planned.outcome(), 1, Integer::sum);
                if (planned.outcome() == Outcome.AMBIGUOUS) runner.runScoped(tenant, row::apply); // raises the review item
            }
        }
        plan.afterApply().forEach(after -> {
            try {
                runner.runScoped(tenant, after);
            } catch (ResponseStatusException ex) {
                failures.add(new RowResult(0, Outcome.REJECTED, ex.getReason()));
            }
        });
        int rejected = plan.rejectedCount() + failures.size();
        String state = failures.isEmpty() ? "APPLIED" : "PARTIAL";
        runner.runScoped(tenant, () -> {
            jdbc.update("""
                    UPDATE identity_import_run SET state = ?, rows_created = ?, rows_updated = ?, rows_unchanged = ?, rows_rejected = ?,
                           error_summary = ?, finished_at = now() WHERE id = ?
                    """, state, applied.getOrDefault(Outcome.CREATE, 0), applied.getOrDefault(Outcome.UPDATE, 0),
                    applied.getOrDefault(Outcome.UNCHANGED, 0), rejected,
                    failures.isEmpty() ? null : truncate(failures.size() + " row(s) failed while applying"), previewToken);
            audit.record("ownership.directory_import.committed", "identity_import_run", previewToken.toString(), OwnershipEvents.json(Map.of(
                    "kind", kind.name(), "created", applied.getOrDefault(Outcome.CREATE, 0), "updated", applied.getOrDefault(Outcome.UPDATE, 0),
                    "rejected", rejected)));
        });
        List<RowResult> rows = new ArrayList<>(plan.problemRows());
        rows.addAll(failures);
        Map<Outcome, Integer> counts = new EnumMap<>(applied);
        counts.put(Outcome.REJECTED, rejected);
        return new Report(previewToken, kind, state, counts, cap(rows), cap(plan.warnings));
    }

    // ----- planning -------------------------------------------------------------------------------------------

    private final class Plan {
        final List<Row> rows = new ArrayList<>();
        final List<RowResult> results = new ArrayList<>();
        final List<RowResult> warnings = new ArrayList<>();
        final List<RowResult> fileLevel = new ArrayList<>();
        final List<Runnable> after = new ArrayList<>();

        void add(Row row) {
            rows.add(row);
            results.add(row.plan());
        }

        int count(Outcome outcome) {
            return (int) results.stream().filter(r -> r.outcome() == outcome).count();
        }

        int rejectedCount() {
            return count(Outcome.REJECTED) + count(Outcome.DUPLICATE) + fileLevel.size();
        }

        List<RowResult> problemRows() {
            List<RowResult> problems = new ArrayList<>(fileLevel);
            results.stream().filter(r -> r.outcome() == Outcome.REJECTED || r.outcome() == Outcome.DUPLICATE
                    || r.outcome() == Outcome.AMBIGUOUS).forEach(problems::add);
            return problems;
        }

        List<Runnable> afterApply() {
            return after;
        }

        Report report(UUID runId, Kind kind, String state) {
            Map<Outcome, Integer> counts = new EnumMap<>(Outcome.class);
            for (Outcome o : Outcome.values()) counts.put(o, count(o));
            counts.merge(Outcome.REJECTED, fileLevel.size(), Integer::sum);
            return new Report(runId, kind, state, counts, cap(problemRows()), cap(warnings));
        }
    }

    private Plan plan(Kind kind, List<List<String>> records, String actor) {
        Plan plan = new Plan();
        List<String> header = records.get(0).stream().map(h -> h.strip().toLowerCase(Locale.ROOT)).toList();
        if (!header.equals(kind.headers)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Expected the header " + String.join(",", kind.headers));
        }
        UUID source = directory.csvSource(actor);
        Set<String> seen = new HashSet<>();
        Map<String, String> managers = new HashMap<>();
        for (int i = 1; i < records.size(); i++) {
            int rowNumber = i + 1;
            List<String> cells = records.get(i).stream().map(String::strip).toList();
            Optional<String> invalid = validateCells(cells, kind.headers.size());
            if (invalid.isPresent()) {
                plan.add(fixed(rowNumber, Outcome.REJECTED, invalid.get()));
                continue;
            }
            String identity = switch (kind) {
                case USERS, GROUPS -> cells.get(0);
                case MEMBERSHIPS -> cells.get(0) + "\u0000" + cells.get(1);
                case TEAMS -> cells.get(0).toLowerCase(Locale.ROOT);
                case TEAM_ALIASES -> cells.get(1).toLowerCase(Locale.ROOT);
            };
            if (!seen.add(identity)) {
                plan.add(fixed(rowNumber, Outcome.DUPLICATE, "This row repeats an earlier row's key"));
                continue;
            }
            switch (kind) {
                case USERS -> plan.add(userRow(rowNumber, cells, source, actor, managers));
                case GROUPS -> plan.add(groupRow(rowNumber, cells, source, actor));
                case MEMBERSHIPS -> plan.add(membershipRow(rowNumber, cells, source, actor));
                case TEAMS -> plan.add(teamRow(rowNumber, cells, actor, seen));
                case TEAM_ALIASES -> plan.add(aliasRow(rowNumber, cells, actor));
            }
        }
        if (kind == Kind.USERS && !managers.isEmpty()) {
            for (Map.Entry<String, String> m : managers.entrySet()) {
                if (!seen.contains(m.getValue()) && directory.userIdByExternalId(source, m.getValue()).isEmpty()) {
                    plan.warnings.add(new RowResult(0, Outcome.UPDATE, "A manager_external_id is not in this file or the directory; the manager stays unset"));
                }
            }
            plan.after.add(() -> managers.forEach((employee, manager) -> {
                Optional<UUID> employeeId = directory.userIdByExternalId(source, employee);
                Optional<UUID> managerId = directory.userIdByExternalId(source, manager);
                if (employeeId.isEmpty() || managerId.isEmpty()) return;
                DirectoryUser current = directory.user(employeeId.get()).orElseThrow();
                if (managerId.get().equals(current.managerUserId())) return;
                directory.updateUser(current.id(), null, null, null, managerId.get(), false, current.version(), actor);
            }));
        }
        return plan;
    }

    private Row userRow(int rowNumber, List<String> c, UUID source, String actor, Map<String, String> managers) {
        String externalId = c.get(0);
        String name = c.get(1);
        String email = c.get(2).isEmpty() ? null : c.get(2);
        String status = c.get(4).isEmpty() ? "ACTIVE" : c.get(4).toUpperCase(Locale.ROOT);
        if (!c.get(3).isEmpty()) managers.put(externalId, c.get(3));
        return new Row() {
            public RowResult plan() {
                if (name.isEmpty()) return new RowResult(rowNumber, Outcome.REJECTED, "display_name is required");
                if (!Set.of("ACTIVE", "INACTIVE").contains(status)) return new RowResult(rowNumber, Outcome.REJECTED, "status must be ACTIVE or INACTIVE");
                try {
                    DirectoryService.normalizeEmail(email);
                } catch (ResponseStatusException ex) {
                    return new RowResult(rowNumber, Outcome.REJECTED, "email is not a valid address");
                }
                Optional<UUID> linked = directory.userIdByExternalId(source, externalId);
                if (linked.isPresent()) {
                    DirectoryUser u = directory.user(linked.get()).orElseThrow();
                    boolean same = u.displayName().equals(OwnershipNames.display(name)) && u.status().equals(status)
                            && Objects.equals(u.email(), DirectoryService.normalizeEmail(email));
                    return new RowResult(rowNumber, same ? Outcome.UNCHANGED : Outcome.UPDATE, null);
                }
                if (email != null && directory.userIdByEmail(email).isPresent()) {
                    return new RowResult(rowNumber, Outcome.AMBIGUOUS, "The email belongs to an existing person; sent to review instead of merging");
                }
                return new RowResult(rowNumber, Outcome.CREATE, null);
            }

            public void apply() {
                Optional<UUID> linked = directory.userIdByExternalId(source, externalId);
                if (linked.isEmpty() && email != null && directory.userIdByEmail(email).isPresent()) {
                    byte[] index = cipher.blindIndex(TenantContext.getCurrentTenantId(), DirectoryService.P_EXTERNAL_ID, externalId);
                    reviews.raise("AMBIGUOUS_IDENTITY", "AMBIGUOUS_IDENTITY|" + source + "|" + HexFormat.of().formatHex(index), null, "CSV",
                            Map.of("sourceId", source, "reason", "EMAIL_ALREADY_LINKED"));
                    return;
                }
                if (linked.isEmpty()) {
                    DirectoryUser created = directory.createUser(name, email, null, null, source, actor);
                    directory.linkExternalIdentity(source, externalId, created.id(), null);
                    if (!"ACTIVE".equals(status)) directory.setUserStatus(created.id(), status, created.version(), actor);
                    return;
                }
                DirectoryUser u = directory.user(linked.get()).orElseThrow();
                DirectoryUser updated = directory.updateUser(u.id(), name, email == null ? "" : email, null, null, false, u.version(), actor);
                if (!updated.status().equals(status)) directory.setUserStatus(u.id(), status, updated.version(), actor);
            }
        };
    }

    private Row groupRow(int rowNumber, List<String> c, UUID source, String actor) {
        String externalId = c.get(0);
        String name = c.get(1);
        String status = c.get(2).isEmpty() ? "ACTIVE" : c.get(2).toUpperCase(Locale.ROOT);
        return new Row() {
            public RowResult plan() {
                if (name.isEmpty()) return new RowResult(rowNumber, Outcome.REJECTED, "display_name is required");
                if (!Set.of("ACTIVE", "INACTIVE").contains(status)) return new RowResult(rowNumber, Outcome.REJECTED, "status must be ACTIVE or INACTIVE");
                Optional<DirectoryGroup> existing = directory.groupIdByExternalId(source, externalId).flatMap(directory::group);
                if (existing.isEmpty()) return new RowResult(rowNumber, Outcome.CREATE, null);
                boolean same = existing.get().displayName().equals(OwnershipNames.display(name)) && existing.get().status().equals(status);
                return new RowResult(rowNumber, same ? Outcome.UNCHANGED : Outcome.UPDATE, null);
            }

            public void apply() {
                Optional<DirectoryGroup> existing = directory.groupIdByExternalId(source, externalId).flatMap(directory::group);
                DirectoryGroup group = existing.orElseGet(() -> directory.createGroup(name, source, actor));
                directory.linkExternalGroup(source, externalId, name, group.id(), null);
                if (existing.isPresent() || !"ACTIVE".equals(status)) directory.updateGroup(group.id(), name, status, group.version(), actor);
            }
        };
    }

    private Row membershipRow(int rowNumber, List<String> c, UUID source, String actor) {
        String operation = c.get(2).isEmpty() ? "ADD" : c.get(2).toUpperCase(Locale.ROOT);
        return new Row() {
            public RowResult plan() {
                if (!Set.of("ADD", "REMOVE").contains(operation)) return new RowResult(rowNumber, Outcome.REJECTED, "operation must be ADD or REMOVE");
                Optional<UUID> group = directory.groupIdByExternalId(source, c.get(0));
                Optional<UUID> user = directory.userIdByExternalId(source, c.get(1));
                if (group.isEmpty()) return new RowResult(rowNumber, Outcome.REJECTED, "group_external_id is not a known imported group");
                if (user.isEmpty()) return new RowResult(rowNumber, Outcome.REJECTED, "user_external_id is not a known imported person");
                boolean active = directory.members(group.get()).stream().anyMatch(m -> m.userId().equals(user.get()) && m.sourceId().equals(source));
                if (active == "ADD".equals(operation)) return new RowResult(rowNumber, Outcome.UNCHANGED, null);
                return new RowResult(rowNumber, "ADD".equals(operation) ? Outcome.CREATE : Outcome.UPDATE, null);
            }

            public void apply() {
                UUID group = directory.groupIdByExternalId(source, c.get(0)).orElseThrow(() -> notFound("group"));
                UUID user = directory.userIdByExternalId(source, c.get(1)).orElseThrow(() -> notFound("person"));
                if ("ADD".equals(operation)) directory.addMember(group, user, source, actor);
                else directory.removeMember(group, user, source, actor);
            }
        };
    }

    private Row teamRow(int rowNumber, List<String> c, String actor, Set<String> namesInFile) {
        String name = c.get(0);
        String parent = c.get(1);
        String ticketGroup = c.get(2).isEmpty() ? null : c.get(2);
        return new Row() {
            public RowResult plan() {
                if (name.isEmpty()) return new RowResult(rowNumber, Outcome.REJECTED, "name is required");
                Optional<UUID> parentId = parent.isEmpty() ? Optional.empty() : teams.resolve(parent);
                if (!parent.isEmpty() && parentId.isEmpty() && !namesInFile.contains(parent.toLowerCase(Locale.ROOT))) {
                    return new RowResult(rowNumber, Outcome.REJECTED, "parent_team is not an existing team or an earlier row");
                }
                Optional<TeamNamespaceService.Team> existing = teams.resolve(name).flatMap(teams::team);
                if (existing.isEmpty()) return new RowResult(rowNumber, Outcome.CREATE, null);
                if (!existing.get().name().equalsIgnoreCase(OwnershipNames.display(name))) {
                    return new RowResult(rowNumber, Outcome.REJECTED, "name is an alias of another team");
                }
                boolean same = Objects.equals(existing.get().parentTeamId(), parentId.orElse(null))
                        && Objects.equals(existing.get().ticketAssignmentGroup(), ticketGroup);
                return new RowResult(rowNumber, same ? Outcome.UNCHANGED : Outcome.UPDATE, null);
            }

            public void apply() {
                UUID parentId = parent.isEmpty() ? null : teams.resolve(parent).orElseThrow(() -> notFound("parent team"));
                Optional<TeamNamespaceService.Team> existing = teams.resolve(name).flatMap(teams::team);
                if (existing.isEmpty()) teams.createTeam(name, parentId, ticketGroup, actor);
                else teams.updateTeam(existing.get().id(), parentId, ticketGroup, existing.get().version(), actor);
            }
        };
    }

    private Row aliasRow(int rowNumber, List<String> c, String actor) {
        String sourceKind = c.get(0).toUpperCase(Locale.ROOT);
        String alias = c.get(1);
        String teamName = c.get(2);
        return new Row() {
            public RowResult plan() {
                if (!TeamNamespaceService.ALIAS_SOURCE_KINDS.contains(sourceKind)) return new RowResult(rowNumber, Outcome.REJECTED, "source_kind is not supported");
                if (alias.isEmpty()) return new RowResult(rowNumber, Outcome.REJECTED, "alias is required");
                Optional<UUID> team = teams.resolve(teamName);
                if (team.isEmpty()) return new RowResult(rowNumber, Outcome.REJECTED, "team_name is not an existing team");
                Optional<UUID> holder = teams.resolve(alias);
                if (holder.isPresent() && holder.get().equals(team.get())) return new RowResult(rowNumber, Outcome.UNCHANGED, null);
                if (holder.isPresent()) return new RowResult(rowNumber, Outcome.REJECTED, "alias already names another team");
                return new RowResult(rowNumber, Outcome.CREATE, null);
            }

            public void apply() {
                UUID team = teams.resolve(teamName).orElseThrow(() -> notFound("team"));
                teams.addAlias(team, alias, sourceKind, null, actor);
            }
        };
    }

    // ----- helpers --------------------------------------------------------------------------------------------

    private static Optional<String> validateCells(List<String> cells, int expected) {
        if (cells.size() != expected) return Optional.of("Expected " + expected + " columns");
        for (String cell : cells) {
            if (DirectoryCsv.looksLikeFormula(cell)) return Optional.of("Cells cannot start with =, +, -, @ or a control character");
        }
        return Optional.empty();
    }

    private static Row fixed(int rowNumber, Outcome outcome, String message) {
        return new Row() {
            public RowResult plan() {
                return new RowResult(rowNumber, outcome, message);
            }

            public void apply() { }
        };
    }

    private static List<List<String>> parseOrReject(byte[] file) {
        try {
            return DirectoryCsv.parse(file);
        } catch (DirectoryCsv.CsvRejected ex) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, ex.getMessage());
        }
    }

    private static UUID requireTenant() {
        UUID tenant = TenantContext.getCurrentTenantId();
        if (tenant == null) throw new IllegalStateException("Directory imports require a tenant context");
        return tenant;
    }

    private static List<RowResult> cap(List<RowResult> rows) {
        return rows.size() <= MAX_REPORTED_ROWS ? List.copyOf(rows) : List.copyOf(rows.subList(0, MAX_REPORTED_ROWS));
    }

    private static String truncate(String value) {
        return value.length() <= 2000 ? value : value.substring(0, 2000);
    }

    private static ResponseStatusException notFound(String what) {
        return new ResponseStatusException(HttpStatus.CONFLICT, "The referenced " + what + " no longer exists");
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
