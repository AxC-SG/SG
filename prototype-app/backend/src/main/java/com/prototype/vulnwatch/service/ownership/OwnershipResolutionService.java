package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.service.ownership.OwnershipResolver.ClaimInput;
import com.prototype.vulnwatch.service.ownership.OwnershipResolver.DirectResult;
import java.sql.Array;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * The only writer of {@code ownership_assignment} (design §5). Re-resolving a subject whose eligible inputs are
 * unchanged writes nothing. Only subjects with claims get a row; descendants inherit through the read view.
 */
@Service
public class OwnershipResolutionService {

    public record Assignment(UUID id, UUID subjectId, String status, UUID teamId, UUID winningClaimId, Integer winningPriority,
                             String winningSourceKind, List<UUID> conflictTeamIds, String reason, int resolverVersion,
                             String inputWatermark, Instant resolvedAt, long version) { }

    private static final String ROLE = "TECHNICAL_OWNER";

    private final JdbcTemplate jdbc;
    private final OwnershipEvents events;
    private final OwnershipReviewService reviews;
    private final OwnershipEffectiveCacheService cache;
    private final Clock clock;

    public OwnershipResolutionService(JdbcTemplate jdbc, OwnershipEvents events, OwnershipReviewService reviews,
            OwnershipEffectiveCacheService cache, org.springframework.beans.factory.ObjectProvider<Clock> clock) {
        this.jdbc = jdbc;
        this.events = events;
        this.reviews = reviews;
        this.cache = cache;
        this.clock = clock.getIfAvailable(Clock::systemUTC);
    }

    /** Re-resolves one subject's direct result. Returns the current assignment, or empty if it has never had claims. */
    @Transactional
    public Optional<Assignment> resolveSubject(UUID subjectId, String actor) {
        // Serialises concurrent resolutions of the same subject.
        if (jdbc.queryForList("SELECT id FROM ownership_subject WHERE id = ? FOR UPDATE", UUID.class, subjectId).isEmpty()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Ownership subject not found");
        }
        List<ClaimInput> claims = jdbc.query("""
                SELECT c.id, c.priority, c.team_id, c.source_kind, c.observed_at, c.stale_after, c.expires_at,
                       t.status = 'ACTIVE' AS team_active,
                       EXISTS (SELECT 1 FROM platform.ownership_kill_switches k
                                WHERE k.source_kind = c.source_kind AND k.state = 'PAUSED'
                                  AND (k.tenant_id IS NULL OR k.tenant_id = c.tenant_id)) AS source_paused
                  FROM ownership_claim c JOIN team t ON t.id = c.team_id
                 WHERE c.subject_id = ? AND c.role = ? AND c.status = 'ACTIVE'
                """, (rs, row) -> new ClaimInput(rs.getObject(1, UUID.class), rs.getInt(2), rs.getObject(3, UUID.class),
                rs.getString(4), instant(rs.getTimestamp(5)), instant(rs.getTimestamp(6)), instant(rs.getTimestamp(7)),
                true, rs.getBoolean(8), rs.getBoolean(9)), subjectId, ROLE);
        Optional<Assignment> existing = current(subjectId);
        if (claims.isEmpty() && existing.isEmpty()) return Optional.empty();

        DirectResult result = OwnershipResolver.resolve(claims, clock.instant());
        if (existing.isPresent() && existing.get().resolverVersion() == OwnershipResolver.RESOLVER_VERSION
                && existing.get().inputWatermark().equals(result.inputWatermark())) {
            return existing;
        }
        UUID assignmentId = existing.map(Assignment::id).orElseGet(UUID::randomUUID);
        String conflictTeams = "{" + String.join(",", result.conflictTeamIds().stream().map(UUID::toString).toList()) + "}";
        if (existing.isEmpty()) {
            jdbc.update("""
                    INSERT INTO ownership_assignment (id, subject_id, role, status, team_id, winning_claim_id, winning_priority,
                        winning_source_kind, conflict_team_ids, reason, resolver_version, input_watermark, resolved_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?::uuid[], ?, ?, ?, now())
                    """, assignmentId, subjectId, ROLE, result.status().name(), result.teamId(), result.winningClaimId(),
                    result.winningPriority(), result.winningSourceKind(), conflictTeams, result.reason(),
                    OwnershipResolver.RESOLVER_VERSION, result.inputWatermark());
        } else {
            jdbc.update("""
                    UPDATE ownership_assignment SET status = ?, team_id = ?, winning_claim_id = ?, winning_priority = ?,
                        winning_source_kind = ?, conflict_team_ids = ?::uuid[], reason = ?, resolver_version = ?, input_watermark = ?,
                        resolved_at = now(), version = version + 1
                     WHERE id = ?
                    """, result.status().name(), result.teamId(), result.winningClaimId(), result.winningPriority(),
                    result.winningSourceKind(), conflictTeams, result.reason(), OwnershipResolver.RESOLVER_VERSION,
                    result.inputWatermark(), assignmentId);
        }
        if (existing.isEmpty() || materiallyChanged(existing.get(), result)) {
            cache.enqueue(subjectId, "ASSIGNMENT_CHANGED");
            events.record("ASSIGNMENT_CHANGED", subjectId, assignmentId, result.winningClaimId(), actor,
                    "fromStatus", existing.map(Assignment::status).orElse(null),
                    "fromTeamId", existing.map(Assignment::teamId).orElse(null),
                    "toStatus", result.status().name(), "toTeamId", result.teamId(),
                    "conflictTeamIds", result.conflictTeamIds(), "resolverVersion", OwnershipResolver.RESOLVER_VERSION);
            if (result.status() == OwnershipResolver.Status.CONFLICT) {
                reviews.raise("CONFLICT", "CONFLICT|" + subjectId, subjectId, result.winningSourceKind(),
                        Map.of("conflictTeamIds", result.conflictTeamIds(), "priority", result.winningPriority()));
            }
            claims.stream().filter(c -> c.active() && !c.teamActive()).map(ClaimInput::teamId).distinct()
                    .forEach(team -> reviews.raise("INACTIVE_OWNER", "INACTIVE_OWNER|" + subjectId + "|" + team, subjectId, null,
                            Map.of("teamId", team)));
        }
        return current(subjectId);
    }

    /**
     * Queues every subject with an active claim naming {@code teamId} for re-resolution, e.g. after the team is
     * archived or restored. One set-based insert, so it stays cheap for large teams; the maintenance job drains it.
     */
    @Transactional
    public int enqueueSubjectsClaimingTeam(UUID teamId) {
        return jdbc.update("""
                INSERT INTO ownership_resolution_queue (subject_id, reason)
                SELECT DISTINCT subject_id, 'TEAM_STATUS_CHANGED' FROM ownership_claim WHERE team_id = ? AND status = 'ACTIVE'
                ON CONFLICT (tenant_id, subject_id) DO NOTHING
                """, teamId);
    }

    /** Re-resolves up to {@code limit} queued subjects, oldest first. Returns how many were drained. */
    @Transactional
    public int drainQueue(int limit, String actor) {
        List<UUID> subjects = jdbc.queryForList("""
                DELETE FROM ownership_resolution_queue
                 WHERE subject_id IN (SELECT subject_id FROM ownership_resolution_queue ORDER BY enqueued_at, subject_id
                                       LIMIT ? FOR UPDATE SKIP LOCKED)
                RETURNING subject_id
                """, UUID.class, limit);
        subjects.stream().sorted().forEach(subject -> resolveSubject(subject, actor));
        return subjects.size();
    }

    @Transactional(readOnly = true)
    public Optional<Assignment> current(UUID subjectId) {
        return jdbc.query("""
                SELECT id, subject_id, status, team_id, winning_claim_id, winning_priority, winning_source_kind, conflict_team_ids,
                       reason, resolver_version, input_watermark, resolved_at, version
                  FROM ownership_assignment WHERE subject_id = ? AND role = ?
                """, (rs, row) -> new Assignment(rs.getObject(1, UUID.class), rs.getObject(2, UUID.class), rs.getString(3),
                rs.getObject(4, UUID.class), rs.getObject(5, UUID.class), (Integer) rs.getObject(6), rs.getString(7),
                uuids(rs.getArray(8)), rs.getString(9), rs.getInt(10), rs.getString(11), instant(rs.getTimestamp(12)),
                rs.getLong(13)), subjectId, ROLE).stream().findFirst();
    }

    private static boolean materiallyChanged(Assignment before, DirectResult after) {
        return !before.status().equals(after.status().name()) || !Objects.equals(before.teamId(), after.teamId())
                || !Objects.equals(before.winningClaimId(), after.winningClaimId())
                || !before.conflictTeamIds().equals(after.conflictTeamIds());
    }

    private static List<UUID> uuids(Array array) throws SQLException {
        if (array == null) return List.of();
        return Arrays.stream((Object[]) array.getArray()).map(o -> (UUID) o).sorted().toList();
    }

    private static Instant instant(Timestamp ts) {
        return ts == null ? null : ts.toInstant();
    }
}
