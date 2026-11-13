package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.LinkedHashMap;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * The only writer of {@code team} and {@code team_alias}. Team names and aliases share one
 * case-insensitive namespace per tenant: a value can name exactly one team, either as its name or
 * as an alias. Every write takes a tenant-scoped transaction advisory lock so concurrent writers
 * cannot both claim a key; the per-table unique indexes are only a backstop.
 */
@Service
public class TeamNamespaceService {

    public record Team(UUID id, String name, UUID parentTeamId, String ticketAssignmentGroup, String status, long version) { }

    public record Alias(UUID id, UUID teamId, String alias, String sourceKind, UUID sourceId) { }

    static final Set<String> ALIAS_SOURCE_KINDS = Set.of("MANUAL", "CSV", "SERVICENOW", "ENTRA", "OKTA", "AWS", "GCP", "AI_GRID");
    private static final String LOCK_SCOPE = "ownership.team-namespace";
    private static final int MAX_PARENT_DEPTH = 32;
    private static final com.fasterxml.jackson.databind.ObjectMapper JSON = new com.fasterxml.jackson.databind.ObjectMapper();

    private final JdbcTemplate jdbc;
    private final AuditEventService audit;
    private final OwnershipResolutionService resolution;

    public TeamNamespaceService(JdbcTemplate jdbc, AuditEventService audit, OwnershipResolutionService resolution) {
        this.jdbc = jdbc;
        this.audit = audit;
        this.resolution = resolution;
    }

    @Transactional
    public Team createTeam(String name, UUID parentTeamId, String ticketAssignmentGroup, String actor) {
        String display = display(name);
        String key = display.toLowerCase(java.util.Locale.ROOT);
        lock();
        requireFree(key, null);
        if (parentTeamId != null) requireActiveTeam(parentTeamId);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO team (tenant_id, id, name, name_key, parent_team_id, ticket_assignment_group, created_by, updated_by)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, ?, ?)
                """, id, display, key, parentTeamId, blankToNull(ticketAssignmentGroup), actor, actor);
        audit.record("ownership.team.created", "team", id.toString(), json("name", display, "parentTeamId", parentTeamId));
        return team(id).orElseThrow();
    }

    @Transactional
    public Team renameTeam(UUID teamId, String newName, long expectedVersion, String actor) {
        String display = display(newName);
        String key = display.toLowerCase(java.util.Locale.ROOT);
        lock();
        Team current = requireTeam(teamId);
        requireFree(key, teamId);
        int changed = jdbc.update("""
                UPDATE team SET name = ?, name_key = ?, updated_by = ?, updated_at = now(), version = version + 1
                 WHERE id = ? AND version = ?
                """, display, key, actor, teamId, expectedVersion);
        if (changed != 1) throw conflict("The team changed since it was loaded; reload and try again");
        audit.record("ownership.team.renamed", "team", teamId.toString(), json("from", current.name(), "to", display));
        return team(teamId).orElseThrow();
    }

    @Transactional
    public Team updateTeam(UUID teamId, UUID parentTeamId, String ticketAssignmentGroup, long expectedVersion, String actor) {
        lock();
        requireTeam(teamId);
        if (parentTeamId != null) {
            requireActiveTeam(parentTeamId);
            if (createsCycle(teamId, parentTeamId)) throw badRequest("A team cannot be placed under itself or one of its descendants");
        }
        int changed = jdbc.update("""
                UPDATE team SET parent_team_id = ?, ticket_assignment_group = ?, updated_by = ?, updated_at = now(), version = version + 1
                 WHERE id = ? AND version = ?
                """, parentTeamId, blankToNull(ticketAssignmentGroup), actor, teamId, expectedVersion);
        if (changed != 1) throw conflict("The team changed since it was loaded; reload and try again");
        audit.record("ownership.team.updated", "team", teamId.toString(),
                json("parentTeamId", parentTeamId, "ticketAssignmentGroup", blankToNull(ticketAssignmentGroup)));
        return team(teamId).orElseThrow();
    }

    /** Archived teams keep their name and aliases reserved, so historic references stay unambiguous. */
    @Transactional
    public Team setStatus(UUID teamId, String status, long expectedVersion, String actor) {
        if (!Set.of("ACTIVE", "ARCHIVED").contains(status)) throw badRequest("Unknown team status");
        lock();
        requireTeam(teamId);
        if ("ARCHIVED".equals(status)) {
            Integer children = jdbc.queryForObject("SELECT count(*) FROM team WHERE parent_team_id = ? AND status = 'ACTIVE'", Integer.class, teamId);
            if (children != null && children > 0) throw conflict("Move or archive the child teams first");
        }
        int changed = jdbc.update("""
                UPDATE team SET status = ?, updated_by = ?, updated_at = now(), version = version + 1 WHERE id = ? AND version = ?
                """, status, actor, teamId, expectedVersion);
        if (changed != 1) throw conflict("The team changed since it was loaded; reload and try again");
        audit.record("ownership.team.status_changed", "team", teamId.toString(), json("status", status));
        // Claims naming an archived team become ineligible (plan §6.9 step 2); restoring makes them eligible again.
        resolution.enqueueSubjectsClaimingTeam(teamId);
        return team(teamId).orElseThrow();
    }

    /** Adds an alias; re-adding the same alias to the same team is a no-op that returns the existing alias. */
    @Transactional
    public Alias addAlias(UUID teamId, String alias, String sourceKind, UUID sourceId, String actor) {
        if (!ALIAS_SOURCE_KINDS.contains(sourceKind)) throw badRequest("Unknown alias source");
        String display = display(alias);
        String key = display.toLowerCase(java.util.Locale.ROOT);
        lock();
        requireTeam(teamId);
        Optional<Alias> existing = aliasByKey(key);
        if (existing.isPresent() && existing.get().teamId().equals(teamId)) return existing.get();
        requireFree(key, null);
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO team_alias (tenant_id, id, team_id, alias, alias_key, source_kind, source_id, created_by) VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, ?, ?)
                """, id, teamId, display, key, sourceKind, sourceId, actor);
        audit.record("ownership.team_alias.added", "team", teamId.toString(), json("alias", display, "sourceKind", sourceKind));
        return new Alias(id, teamId, display, sourceKind, sourceId);
    }

    @Transactional
    public void removeAlias(UUID teamId, UUID aliasId) {
        lock();
        List<String> removed = jdbc.queryForList("DELETE FROM team_alias WHERE id = ? AND team_id = ? RETURNING alias", String.class, aliasId, teamId);
        if (removed.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Alias not found");
        audit.record("ownership.team_alias.removed", "team", teamId.toString(), json("alias", removed.get(0)));
    }

    /** Resolves a value to the team it names, by team name or alias. Never guesses. */
    @Transactional(readOnly = true)
    public Optional<UUID> resolve(String value) {
        String key;
        try {
            key = OwnershipNames.key(value);
        } catch (IllegalArgumentException ex) {
            return Optional.empty();
        }
        List<UUID> ids = jdbc.queryForList("""
                SELECT id FROM team WHERE name_key = ?
                UNION ALL
                SELECT team_id FROM team_alias WHERE alias_key = ?
                """, UUID.class, key, key);
        return ids.size() == 1 ? Optional.of(ids.get(0)) : Optional.empty();
    }

    @Transactional(readOnly = true)
    public Optional<Team> team(UUID id) {
        return jdbc.query("SELECT id, name, parent_team_id, ticket_assignment_group, status, version FROM team WHERE id = ?",
                (rs, row) -> new Team(rs.getObject(1, UUID.class), rs.getString(2), rs.getObject(3, UUID.class), rs.getString(4),
                        rs.getString(5), rs.getLong(6)), id).stream().findFirst();
    }

    /** Bounded, name-ordered page of teams whose name starts with {@code prefix} (blank = all). */
    @Transactional(readOnly = true)
    public List<Team> list(String prefix, String status, int limit, int offset) {
        String key = prefix == null ? "" : prefix.strip().toLowerCase(java.util.Locale.ROOT)
                .replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
        return jdbc.query("""
                SELECT id, name, parent_team_id, ticket_assignment_group, status, version FROM team
                 WHERE name_key LIKE ? ESCAPE '\\' AND (?::text IS NULL OR status = ?)
                 ORDER BY name_key LIMIT ? OFFSET ?
                """, (rs, row) -> new Team(rs.getObject(1, UUID.class), rs.getString(2), rs.getObject(3, UUID.class), rs.getString(4),
                rs.getString(5), rs.getLong(6)), key + "%", status, status, Math.max(1, Math.min(limit, 200)), Math.max(0, offset));
    }

    @Transactional(readOnly = true)
    public List<Alias> aliases(UUID teamId) {
        return jdbc.query("SELECT id, team_id, alias, source_kind, source_id FROM team_alias WHERE team_id = ? ORDER BY alias_key",
                (rs, row) -> new Alias(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getString(3), rs.getString(4),
                        rs.getObject(5, UUID.class)), teamId);
    }

    private Optional<Alias> aliasByKey(String key) {
        return jdbc.query("SELECT id, team_id, alias, source_kind, source_id FROM team_alias WHERE alias_key = ?",
                (rs, row) -> new Alias(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getString(3), rs.getString(4),
                        rs.getObject(5, UUID.class)), key).stream().findFirst();
    }

    /** Fails when {@code key} is used by any alias, or by a team other than {@code exceptTeamId}. */
    private void requireFree(String key, UUID exceptTeamId) {
        List<UUID> teams = jdbc.queryForList("SELECT id FROM team WHERE name_key = ?", UUID.class, key);
        if (teams.stream().anyMatch(id -> !id.equals(exceptTeamId))) throw conflict("Another team already uses this name");
        Integer aliases = jdbc.queryForObject("SELECT count(*) FROM team_alias WHERE alias_key = ?", Integer.class, key);
        if (aliases != null && aliases > 0) throw conflict("This name is already an alias of a team");
    }

    private boolean createsCycle(UUID teamId, UUID newParent) {
        UUID cursor = newParent;
        for (int depth = 0; cursor != null; depth++) {
            if (cursor.equals(teamId)) return true;
            if (depth >= MAX_PARENT_DEPTH) throw badRequest("Team hierarchy is too deep");
            List<UUID> next = jdbc.queryForList("SELECT parent_team_id FROM team WHERE id = ?", UUID.class, cursor);
            cursor = next.isEmpty() ? null : next.get(0); // the list holds a null when the team has no parent
        }
        return false;
    }

    private Team requireTeam(UUID teamId) {
        return team(teamId).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Team not found"));
    }

    private void requireActiveTeam(UUID teamId) {
        Team parent = team(teamId).orElseThrow(() -> badRequest("Parent team not found"));
        if (!"ACTIVE".equals(parent.status())) throw badRequest("Parent team is archived");
    }

    private void lock() {
        UUID tenantId = TenantContext.getCurrentTenantId();
        if (tenantId == null) throw new IllegalStateException("Team namespace writes require a tenant context");
        jdbc.query("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", rs -> null, tenantId + "|" + LOCK_SCOPE);
    }

    private static String display(String value) {
        try {
            return OwnershipNames.display(value);
        } catch (IllegalArgumentException ex) {
            throw badRequest(ex.getMessage());
        }
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.strip();
    }

    private static String json(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) map.put((String) pairs[i], pairs[i + 1]);
        try {
            return JSON.writeValueAsString(map);
        } catch (com.fasterxml.jackson.core.JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static ResponseStatusException conflict(String message) {
        return new ResponseStatusException(HttpStatus.CONFLICT, message);
    }

    private static ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
