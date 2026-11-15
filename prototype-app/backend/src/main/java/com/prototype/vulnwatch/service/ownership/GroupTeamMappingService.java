package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantWorkRunner;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Function;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * The only writer of {@code external_group_team_mapping} (Phase 0B contract §1.8). An external group maps to a team
 * only through an explicit ACTIVE mapping with MANUAL or CSV provenance, at most one per group. The directory sync may
 * propose a SUGGESTED mapping when the group's name exactly equals a team name or alias; it never activates one.
 *
 * <p>Activating or retiring a mapping first needs a preview of its impact (the CMDB CIs, subjects and open findings
 * whose {@code support_group} names the group) and that preview's token, bound to the group, the target team, the
 * current mapping and the admin. A change affecting more than {@value #LARGE_CHANGE} CIs needs a second confirmation
 * and is applied by the next CMDB sync rather than inline. Otherwise the affected CIs are republished at once, when
 * the ServiceNow producer is enabled. Audit payloads carry IDs and counts only.
 */
@Service
public class GroupTeamMappingService {

    public record Mapping(UUID id, UUID externalGroupId, UUID teamId, String teamName, String state, String provenance, String reason,
                          String actor, Instant effectiveFrom, Instant effectiveTo) { }

    /** An external group with its active mapping and any pending suggestion. */
    public record GroupRow(UUID externalGroupId, UUID sourceId, String sourceName, String displayName, String status, Mapping active,
                           Mapping suggestion) { }

    /**
     * What a change would affect. {@code sameInstance} is false when the group's source is on a different ServiceNow
     * instance than the CMDB connector, so no CI can reference it. The token is valid for 30 minutes.
     */
    public record Impact(UUID externalGroupId, UUID currentTeamId, UUID targetTeamId, boolean sameInstance, int affectedCis,
                         int affectedSubjects, long openFindings, List<UUID> sampleSubjectIds, boolean largeChange, String previewToken,
                         Instant expiresAt) { }

    /** {@code republishSkipped} says why the affected CIs were left for the next CMDB sync, or is null. */
    public record ChangeResult(Mapping mapping, int republishedCis, String republishSkipped) { }

    static final int LARGE_CHANGE = 10_000;
    static final int SAMPLE_SUBJECTS = 20;
    static final String P_PREVIEW_TOKEN = "ownership.group_mapping.preview_token";
    static final String SUGGESTION_REASON = "EXACT_NAME_MATCH";
    private static final int MAX_REASON = 500;

    private record GroupFacts(UUID id, String sysId, String instance, UUID currentMappingId, UUID currentTeamId) { }

    private record Affected(List<String> sysIds, List<UUID> subjects, long openFindings) { }

    private final JdbcTemplate jdbc;
    private final TenantWorkRunner runner;
    private final TeamNamespaceService teams;
    private final GroupMappingResolver resolver;
    private final ServiceNowOwnershipProducer producer;
    private final TenantDataCipher cipher;
    private final AuditEventService audit;
    private final boolean producerEnabled;

    public GroupTeamMappingService(JdbcTemplate jdbc, TenantWorkRunner runner, TeamNamespaceService teams, GroupMappingResolver resolver,
                                   ServiceNowOwnershipProducer producer, TenantDataCipher cipher, AuditEventService audit,
                                   @Value("${app.ownership.servicenow.producer-enabled:false}") boolean producerEnabled) {
        this.jdbc = jdbc;
        this.runner = runner;
        this.teams = teams;
        this.resolver = resolver;
        this.producer = producer;
        this.cipher = cipher;
        this.audit = audit;
        this.producerEnabled = producerEnabled;
    }

    // ----- reads ----------------------------------------------------------------------------------------------

    /** External groups of ServiceNow sources whose name starts with {@code query} (case-insensitive), by name. */
    @Transactional(readOnly = true)
    public List<GroupRow> groups(String query, int limit) {
        String prefix = query == null ? "" : query.strip().toLowerCase(Locale.ROOT);
        String escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_");
        return jdbc.query("""
                SELECT e.id, e.source_id, s.display_name, e.display_name, e.status FROM external_group e
                  JOIN identity_source s ON s.id = e.source_id
                 WHERE s.kind = 'SERVICENOW' AND lower(e.display_name) LIKE ? ESCAPE '\\'
                 ORDER BY lower(e.display_name), e.id LIMIT ?
                """, (rs, n) -> {
                    UUID id = rs.getObject(1, UUID.class);
                    return new GroupRow(id, rs.getObject(2, UUID.class), rs.getString(3), rs.getString(4), rs.getString(5),
                            mappingFor(id, "ACTIVE"), mappingFor(id, "PROPOSED"));
                }, escaped + "%", Math.max(1, Math.min(limit, 200)));
    }

    /** Mappings in {@code state} (default ACTIVE), newest first. */
    @Transactional(readOnly = true)
    public List<Mapping> mappings(String state, int limit) {
        String wanted = state == null || state.isBlank() ? "ACTIVE" : state.strip().toUpperCase(Locale.ROOT);
        if (!List.of("ACTIVE", "PROPOSED", "RETIRED").contains(wanted)) throw bad("State must be ACTIVE, PROPOSED or RETIRED");
        return jdbc.query(MAPPING_SELECT + " WHERE m.state = ? ORDER BY m.updated_at DESC, m.id LIMIT ?", this::mapping, wanted,
                Math.max(1, Math.min(limit, 500)));
    }

    // ----- preview and changes --------------------------------------------------------------------------------

    /** The impact of mapping {@code externalGroupId} to {@code teamId}, or of retiring its mapping when {@code teamId} is null. */
    public Impact preview(UUID externalGroupId, UUID teamId, String actor) {
        UUID tenant = requireReady();
        return runner.runScoped(tenant, () -> {
            GroupFacts group = group(externalGroupId);
            validateTarget(group, teamId);
            Affected affected = affected(group);
            Instant expiresAt = Instant.now().plus(IdentitySourcePreviewToken.TTL);
            String token = IdentitySourcePreviewToken.issue(mac(tenant), externalGroupId, 0L, scope(group, teamId), actor, expiresAt);
            return new Impact(externalGroupId, group.currentTeamId(), teamId, sameInstance(group), affected.sysIds().size(),
                    affected.subjects().size(), affected.openFindings(), affected.subjects().stream().limit(SAMPLE_SUBJECTS).toList(),
                    affected.sysIds().size() > LARGE_CHANGE, token, expiresAt);
        });
    }

    /**
     * Maps {@code externalGroupId} to {@code teamId} (MANUAL), replacing the active mapping, if any, and closing any
     * pending suggestion; confirming a suggestion is this call with the suggested team.
     */
    public ChangeResult activate(UUID externalGroupId, UUID teamId, String reason, String previewToken, boolean confirmLarge, String actor) {
        if (teamId == null) throw bad("A team is required");
        String note = reason(reason);
        UUID tenant = requireReady();
        Object[] done = runner.runScoped(tenant, () -> {
            lock(externalGroupId);
            GroupFacts group = group(externalGroupId);
            validateTarget(group, teamId);
            requireToken(tenant, previewToken, group, teamId, actor);
            Affected affected = affected(group);
            requireLargeConfirmation(affected, confirmLarge);
            if (group.currentMappingId() != null) retireRow(group.currentMappingId());
            int closedSuggestions = jdbc.update("""
                    UPDATE external_group_team_mapping SET state = 'RETIRED', effective_to = now(), updated_at = now()
                     WHERE external_group_id = ? AND state = 'PROPOSED'
                    """, externalGroupId);
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    INSERT INTO external_group_team_mapping (tenant_id, id, external_group_id, team_id, state, provenance, reason, actor)
                    VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, 'ACTIVE', 'MANUAL', ?, ?)
                    """, id, externalGroupId, teamId, note, actor);
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("externalGroupId", externalGroupId.toString());
            details.put("teamId", teamId.toString());
            details.put("previousTeamId", group.currentTeamId() == null ? "" : group.currentTeamId().toString());
            details.put("closedSuggestions", closedSuggestions);
            details.put("affectedCis", affected.sysIds().size());
            audit.record("ownership.group_mapping.activated", "external_group", externalGroupId.toString(), OwnershipEvents.json(details));
            return new Object[] {id, affected, sameInstance(group)};
        });
        return republish(tenant, (UUID) done[0], (Affected) done[1], (Boolean) done[2]);
    }

    /** Retires an active mapping. CIs that named the group fall back to team name or alias resolution. */
    public ChangeResult retire(UUID mappingId, String reason, String previewToken, boolean confirmLarge, String actor) {
        String note = reason(reason);
        UUID tenant = requireReady();
        Object[] done = runner.runScoped(tenant, () -> {
            UUID externalGroupId = mappingRow(mappingId).filter(m -> "ACTIVE".equals(m.state()))
                    .orElseThrow(() -> conflict("Only an active mapping can be retired")).externalGroupId();
            lock(externalGroupId);
            GroupFacts group = group(externalGroupId);
            if (!mappingId.equals(group.currentMappingId())) throw conflict("The mapping changed; preview again");
            requireToken(tenant, previewToken, group, null, actor);
            Affected affected = affected(group);
            requireLargeConfirmation(affected, confirmLarge);
            retireRow(mappingId);
            if (note != null) jdbc.update("UPDATE external_group_team_mapping SET reason = ? WHERE id = ?", note, mappingId);
            audit.record("ownership.group_mapping.retired", "external_group", externalGroupId.toString(), OwnershipEvents.json(Map.of(
                    "mappingId", mappingId.toString(), "teamId", group.currentTeamId().toString(), "affectedCis", affected.sysIds().size())));
            return new Object[] {mappingId, affected, sameInstance(group)};
        });
        return republish(tenant, (UUID) done[0], (Affected) done[1], (Boolean) done[2]);
    }

    /** Dismisses a suggestion. A dismissed suggestion is not proposed again for the same team. */
    @Transactional
    public Mapping dismiss(UUID mappingId, String actor) {
        requireReady();
        Mapping current = mappingRow(mappingId).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Mapping not found"));
        if (!"PROPOSED".equals(current.state())) throw conflict("Only a suggestion can be dismissed");
        retireRow(mappingId);
        audit.record("ownership.group_mapping.dismissed", "external_group", current.externalGroupId().toString(),
                OwnershipEvents.json(Map.of("mappingId", mappingId.toString(), "teamId", current.teamId().toString())));
        return mappingRow(mappingId).orElseThrow();
    }

    /**
     * Called by the directory sync for each group it sees: proposes a SUGGESTED mapping when the group's name exactly
     * equals a team name or alias in the shared namespace, the group has no active or pending mapping, and the same
     * suggestion was not dismissed before. Never activates it. Returns true when a suggestion was written.
     */
    @Transactional
    public boolean suggest(UUID externalGroupId, String groupName, String actor) {
        if (groupName == null || groupName.isBlank()) return false;
        lock(externalGroupId);
        if (jdbc.queryForObject("SELECT count(*) FROM external_group_team_mapping WHERE external_group_id = ? AND state IN ('ACTIVE','PROPOSED')",
                Integer.class, externalGroupId) > 0) {
            return false;
        }
        Optional<UUID> team;
        try {
            team = teams.resolve(groupName).filter(id -> teams.team(id).map(t -> "ACTIVE".equals(t.status())).orElse(false));
        } catch (IllegalArgumentException | ResponseStatusException unusable) {
            return false;
        }
        if (team.isEmpty()) return false;
        if (jdbc.queryForObject("""
                SELECT count(*) FROM external_group_team_mapping WHERE external_group_id = ? AND team_id = ? AND provenance = 'SUGGESTED'
                """, Integer.class, externalGroupId, team.get()) > 0) {
            return false;
        }
        UUID id = UUID.randomUUID();
        jdbc.update("""
                INSERT INTO external_group_team_mapping (tenant_id, id, external_group_id, team_id, state, provenance, reason, actor)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, 'PROPOSED', 'SUGGESTED', ?, ?)
                """, id, externalGroupId, team.get(), SUGGESTION_REASON, actor);
        audit.record("ownership.group_mapping.suggested", "external_group", externalGroupId.toString(),
                OwnershipEvents.json(Map.of("mappingId", id.toString(), "teamId", team.get().toString())));
        return true;
    }

    // ----- helpers --------------------------------------------------------------------------------------------

    private ChangeResult republish(UUID tenant, UUID mappingId, Affected affected, boolean sameInstance) {
        Mapping mapping = runner.runScoped(tenant, () -> mappingRow(mappingId).orElseThrow());
        if (!sameInstance || affected.sysIds().isEmpty()) return new ChangeResult(mapping, 0, null);
        if (affected.sysIds().size() > LARGE_CHANGE) return new ChangeResult(mapping, 0, "LARGE_CHANGE_NEXT_CMDB_SYNC");
        if (!producerEnabled) return new ChangeResult(mapping, 0, "PRODUCER_DISABLED");
        ServiceNowOwnershipProducer.Result result = producer.republish(tenant, affected.sysIds());
        return new ChangeResult(mapping, result.paused() ? 0 : affected.sysIds().size(), result.paused() ? result.pauseReason() : null);
    }

    private GroupFacts group(UUID externalGroupId) {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT e.id, e.external_id_enc, s.kind, s.scope_config ->> 'instanceUrl' AS instance FROM external_group e
                  JOIN identity_source s ON s.id = e.source_id WHERE e.id = ?
                """, externalGroupId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "External group not found");
        if (!"SERVICENOW".equals(rows.get(0).get("kind"))) throw conflict("Only ServiceNow groups map to teams here");
        Mapping active = mappingFor(externalGroupId, "ACTIVE");
        String sysId = cipher.decrypt(TenantContext.getCurrentTenantId(), DirectoryService.P_EXTERNAL_ID, (String) rows.get(0).get("external_id_enc"));
        return new GroupFacts(externalGroupId, sysId, (String) rows.get(0).get("instance"), active == null ? null : active.id(),
                active == null ? null : active.teamId());
    }

    private void validateTarget(GroupFacts group, UUID teamId) {
        if (teamId == null) {
            if (group.currentMappingId() == null) throw conflict("This group has no active mapping");
            return;
        }
        TeamNamespaceService.Team team = teams.team(teamId).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Team not found"));
        if (!"ACTIVE".equals(team.status())) throw conflict("Only an active team can own a group");
        if (teamId.equals(group.currentTeamId())) throw conflict("The group already maps to this team");
    }

    /** CMDB CIs whose support group references this group's sys_id, on the CMDB's instance only. */
    private Affected affected(GroupFacts group) {
        if (!sameInstance(group)) return new Affected(List.of(), List.of(), 0);
        String sysId = group.sysId().toLowerCase(Locale.ROOT);
        List<Object[]> rows = jdbc.query("""
                SELECT ci.sys_id, a.ownership_subject_id FROM cis ci LEFT JOIN assets a ON a.id = ci.asset_id
                 WHERE ci.support_group_sys_id = ? AND ci.sys_id ~* '^[0-9a-f]{32}$' ORDER BY ci.sys_id
                """, (rs, n) -> new Object[] {rs.getString(1), rs.getObject(2, UUID.class)}, sysId);
        long findings = jdbc.queryForObject("""
                SELECT count(*) FROM findings f WHERE f.status = 'OPEN' AND f.asset_id IN (
                    SELECT ci.asset_id FROM cis ci WHERE ci.support_group_sys_id = ? AND ci.sys_id ~* '^[0-9a-f]{32}$')
                """, Long.class, sysId);
        return new Affected(rows.stream().map(r -> (String) r[0]).toList(),
                rows.stream().map(r -> (UUID) r[1]).filter(Objects::nonNull).distinct().toList(), findings);
    }

    private boolean sameInstance(GroupFacts group) {
        String cmdb = resolver.cmdbInstance();
        return cmdb != null && cmdb.equals(group.instance());
    }

    private void requireToken(UUID tenant, String token, GroupFacts group, UUID teamId, String actor) {
        if (!IdentitySourcePreviewToken.valid(mac(tenant), token, group.id(), 0L, scope(group, teamId), actor, Instant.now())) {
            throw conflict("Preview the change again: the preview is missing, expired or out of date");
        }
    }

    private static void requireLargeConfirmation(Affected affected, boolean confirmLarge) {
        if (affected.sysIds().size() > LARGE_CHANGE && !confirmLarge) {
            throw conflict("This change affects more than " + LARGE_CHANGE + " CIs; confirm it a second time");
        }
    }

    /** The token covers the target and the mapping it replaces, so any change in between invalidates it. */
    private static String scope(GroupFacts group, UUID teamId) {
        return IdentitySourcePreviewToken.scopeHash((teamId == null ? "RETIRE" : teamId.toString()) + "|" + group.currentMappingId());
    }

    private Function<String, byte[]> mac(UUID tenant) {
        return payload -> cipher.blindIndex(tenant, P_PREVIEW_TOKEN, payload);
    }

    private void retireRow(UUID mappingId) {
        jdbc.update("""
                UPDATE external_group_team_mapping SET state = 'RETIRED', effective_to = greatest(now(), effective_from + interval '1 microsecond'),
                       updated_at = now()
                 WHERE id = ? AND state IN ('ACTIVE','PROPOSED')
                """, mappingId);
    }

    private void lock(UUID externalGroupId) {
        jdbc.query("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", rs -> null,
                TenantContext.getCurrentTenantId() + "|ownership.group-mapping|" + externalGroupId);
    }

    private static final String MAPPING_SELECT = """
            SELECT m.id, m.external_group_id, m.team_id, t.name, m.state, m.provenance, m.reason, m.actor, m.effective_from, m.effective_to
              FROM external_group_team_mapping m JOIN team t ON t.id = m.team_id""";

    private Mapping mappingFor(UUID externalGroupId, String state) {
        return jdbc.query(MAPPING_SELECT + " WHERE m.external_group_id = ? AND m.state = ? ORDER BY m.created_at DESC LIMIT 1", this::mapping,
                externalGroupId, state).stream().findFirst().orElse(null);
    }

    private Optional<Mapping> mappingRow(UUID id) {
        return jdbc.query(MAPPING_SELECT + " WHERE m.id = ?", this::mapping, id).stream().findFirst();
    }

    private Mapping mapping(ResultSet rs, int n) throws SQLException {
        Timestamp to = rs.getTimestamp(10);
        return new Mapping(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getObject(3, UUID.class), rs.getString(4),
                rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8), rs.getTimestamp(9).toInstant(),
                to == null ? null : to.toInstant());
    }

    private static String reason(String reason) {
        String note = reason == null || reason.isBlank() ? null : reason.strip();
        if (note != null && note.length() > MAX_REASON) throw bad("The reason is limited to " + MAX_REASON + " characters");
        return note;
    }

    private UUID requireReady() {
        UUID tenant = TenantContext.getCurrentTenantId();
        if (tenant == null) throw new IllegalStateException("Group mappings require a tenant context");
        if (!cipher.readiness(tenant).ready()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Tenant encryption is not ready");
        }
        return tenant;
    }

    private static ResponseStatusException bad(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private static ResponseStatusException conflict(String message) {
        return new ResponseStatusException(HttpStatus.CONFLICT, message);
    }
}
