package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * Manual subject assignment (plan §6.10, design §4). A manual claim is fallback ownership for descendants, never a
 * forced subtree override. Analysts are limited server-side: one subject, which must be the subject of an open
 * finding assigned to them; a mandatory reason; expiry within 30 days; and an impact of at most 100 changed
 * descendants and 1,000 affected findings. Every analyst assignment raises a security alert in the same transaction.
 */
@Service
public class ManualAssignmentService {

    public record Preview(UUID subjectId, UUID currentTeamId, String currentStatus, int directFindings, int wouldChange,
                          int blockedByDirectClaim, int conflict, int alreadyEffective, int affectedFindings) { }

    public record Explanation(Map<String, Object> effective, List<Map<String, Object>> directClaims) { }

    static final Duration ANALYST_MAX_EXPIRY = Duration.ofDays(30);
    static final int ANALYST_MAX_DESCENDANTS = 100;
    static final int ANALYST_MAX_FINDINGS = 1_000;

    private final JdbcTemplate jdbc;
    private final OwnershipClaimService claims;
    private final OwnershipAuthorityService authority;
    private final OwnershipEvents events;
    private final AuditEventService audit;
    private final Clock clock;

    public ManualAssignmentService(JdbcTemplate jdbc, OwnershipClaimService claims, OwnershipAuthorityService authority,
                                   OwnershipEvents events, AuditEventService audit, ObjectProvider<Clock> clock) {
        this.jdbc = jdbc;
        this.claims = claims;
        this.authority = authority;
        this.events = events;
        this.audit = audit;
        this.clock = clock.getIfAvailable(Clock::systemUTC);
    }

    /**
     * Counts what assigning {@code teamId} to the subject would change. Descendants with any direct result keep it
     * ("blocked by direct claim"); the rest inherit and are counted as would-change, conflict or already-effective.
     */
    @Transactional(readOnly = true)
    public Preview preview(UUID subjectId, UUID teamId) {
        Map<String, Object> current = effective(subjectId);
        Integer direct = jdbc.queryForObject("SELECT count(*) FROM findings WHERE ownership_subject_id = ? AND status = 'OPEN'",
                Integer.class, subjectId);
        Map<String, Object> counts = jdbc.queryForMap("""
                WITH RECURSIVE down AS (
                    SELECT e.child_subject_id AS id, 1 AS depth FROM ownership_subject_edge e
                     WHERE e.parent_subject_id = ? AND e.edge_type = 'OWNERSHIP_PARENT' AND e.status = 'ACTIVE'
                    UNION ALL
                    SELECT e.child_subject_id, down.depth + 1 FROM down
                      JOIN ownership_subject_edge e ON e.parent_subject_id = down.id AND e.edge_type = 'OWNERSHIP_PARENT' AND e.status = 'ACTIVE'
                     -- a child with its own direct result keeps it and shields its subtree
                     WHERE down.depth < 6 AND NOT EXISTS (SELECT 1 FROM ownership_assignment a WHERE a.subject_id = down.id
                                                          AND a.status IN ('OWNED','CONFLICT'))
                ), classified AS (
                    SELECT d.id,
                           EXISTS (SELECT 1 FROM ownership_assignment a WHERE a.subject_id = d.id AND a.status IN ('OWNED','CONFLICT')) AS blocked,
                           v.ownership_status, v.owner_team_id
                      FROM down d JOIN ownership_effective_assignment v ON v.subject_id = d.id
                )
                SELECT count(*) FILTER (WHERE blocked) AS blocked,
                       count(*) FILTER (WHERE NOT blocked AND owner_team_id IS NOT DISTINCT FROM ?) AS already,
                       count(*) FILTER (WHERE NOT blocked AND ownership_status = 'CONFLICT') AS conflict,
                       count(*) FILTER (WHERE NOT blocked AND ownership_status <> 'CONFLICT' AND owner_team_id IS DISTINCT FROM ?) AS would_change,
                       (SELECT count(*) FROM findings f WHERE f.status = 'OPEN' AND f.ownership_subject_id IN
                            (SELECT id FROM classified WHERE NOT blocked AND owner_team_id IS DISTINCT FROM ?)) AS descendant_findings
                  FROM classified
                """, subjectId, teamId, teamId, teamId);
        int directFindings = direct == null ? 0 : direct;
        boolean subjectChanges = !Objects.equals(current.get("owner_team_id"), teamId);
        return new Preview(subjectId, (UUID) current.get("owner_team_id"), (String) current.get("ownership_status"), directFindings,
                num(counts.get("would_change")), num(counts.get("blocked")), num(counts.get("conflict")), num(counts.get("already")),
                (subjectChanges ? directFindings : 0) + num(counts.get("descendant_findings")));
    }

    /**
     * Creates (or replaces) the subject's manual claim. {@code idempotencyKey} makes a retried request a no-op.
     * {@code analystPrincipal} is null for admins; for analysts it is the caller's application principal ID.
     */
    @Transactional
    public Preview assign(UUID subjectId, String subjectType, UUID teamId, String reason, Instant expiresAt, String idempotencyKey,
                          String actor, UUID analystPrincipal) {
        authority.requireCanonicalWrites(subjectType);
        if (reason == null || reason.isBlank()) throw bad("A reason is required");
        Instant now = clock.instant();
        Preview preview = preview(subjectId, teamId);
        if (analystPrincipal != null) {
            Integer scoped = jdbc.queryForObject("""
                    SELECT count(*) FROM findings WHERE ownership_subject_id = ? AND assignee_principal_id = ? AND status = 'OPEN'
                    """, Integer.class, subjectId, analystPrincipal);
            if (scoped == null || scoped == 0) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Analysts can assign owners only for subjects of findings assigned to them");
            }
            Instant max = now.plus(ANALYST_MAX_EXPIRY);
            if (expiresAt == null) expiresAt = max;
            if (expiresAt.isAfter(max)) throw bad("Analyst assignments must expire within 30 days");
            if (preview.wouldChange() > ANALYST_MAX_DESCENDANTS || preview.affectedFindings() > ANALYST_MAX_FINDINGS) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                        "This assignment affects too much for an analyst; ask a tenant or inventory admin");
            }
        }
        if (expiresAt != null && !expiresAt.isAfter(now)) throw bad("Expiry must be in the future");
        String observation = idempotencyKey == null || idempotencyKey.isBlank() ? UUID.randomUUID().toString() : idempotencyKey.strip();
        var recorded = claims.recordClaim(new ClaimRequest(subjectId, teamId, null, "MANUAL", "MANUAL", null, "manual:" + subjectId,
                observation, "manual-1", now, null, expiresAt, reason, actor));
        if (recorded.created() && analystPrincipal != null) {
            events.record("OWNERSHIP_ANALYST_ASSIGNMENT", subjectId, null, recorded.claimId(), actor,
                    "previousTeamId", preview.currentTeamId(), "newTeamId", teamId, "expiresAt", expiresAt.toString());
            audit.record("ownership.analyst_assignment", "ownership_subject", subjectId.toString(), OwnershipEvents.json(Map.of(
                    "claimId", recorded.claimId(), "previousTeamId", String.valueOf(preview.currentTeamId()), "newTeamId", teamId,
                    "reason", reason.strip(), "expiresAt", expiresAt.toString())), "ALERT");
        }
        return preview(subjectId, teamId);
    }

    /** Revokes the subject's active manual claim; ownership falls back to the next eligible claim or parent. */
    @Transactional
    public void revoke(UUID subjectId, String subjectType, String actor, String reason) {
        authority.requireCanonicalWrites(subjectType);
        List<UUID> active = jdbc.queryForList("""
                SELECT id FROM ownership_claim WHERE subject_id = ? AND source_kind = 'MANUAL' AND status = 'ACTIVE'
                """, UUID.class, subjectId);
        if (active.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No active manual assignment");
        active.forEach(id -> claims.revokeClaim(id, actor, reason));
    }

    @Transactional(readOnly = true)
    public Explanation explain(UUID subjectId) {
        List<Map<String, Object>> direct = jdbc.queryForList("""
                SELECT c.id AS claim_id, c.source_kind, c.priority_class, c.priority, c.team_id, c.status, c.observed_at, c.stale_after,
                       c.expires_at, (c.stale_after IS NOT NULL AND c.stale_after <= now()) AS stale,
                       (c.status = 'ACTIVE' AND t.status = 'ACTIVE' AND (c.expires_at IS NULL OR c.expires_at > now())) AS eligible
                  FROM ownership_claim c JOIN team t ON t.id = c.team_id
                 WHERE c.subject_id = ? AND (c.status = 'ACTIVE' OR c.ended_at > now() - interval '30 days')
                 ORDER BY c.priority, c.observed_at DESC LIMIT 50
                """, subjectId);
        return new Explanation(effective(subjectId), direct);
    }

    public Optional<UUID> analystPrincipal(String userId, boolean admin) {
        if (admin) return Optional.empty();
        try {
            return Optional.of(UUID.fromString(userId));
        } catch (IllegalArgumentException | NullPointerException ex) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Analyst scope requires an application principal");
        }
    }

    private Map<String, Object> effective(UUID subjectId) {
        List<Map<String, Object>> rows = jdbc.queryForList("""
                SELECT subject_id, ownership_status, resolution, owner_team_id, ownership_origin_subject_id, ownership_assignment_id,
                       ownership_source_kind, ownership_resolved_at, ownership_stale, inheritance_depth, inheritance_path::text AS inheritance_path
                  FROM ownership_effective_assignment WHERE subject_id = ?
                """, subjectId);
        if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Ownership subject not found");
        return rows.get(0);
    }

    private static int num(Object value) {
        return value == null ? 0 : ((Number) value).intValue();
    }

    private static ResponseStatusException bad(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
