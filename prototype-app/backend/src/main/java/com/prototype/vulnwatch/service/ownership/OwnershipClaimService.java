package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.service.TenantContext;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * The only writer of {@code ownership_claim} (plan §6.8). Claims are idempotent per observation: the key covers
 * tenant, producer, subject, role, source reference and observation version. A new observation of the same source
 * reference supersedes the previous one. Every change re-resolves the subject's direct result.
 */
@Service
public class OwnershipClaimService {

    public record ClaimRequest(UUID subjectId, UUID teamId, UUID principalUserId, String sourceKind, String priorityClass,
                               UUID sourceId, String sourceRef, String observationVersion, String producerVersion,
                               Instant observedAt, Instant staleAfter, Instant expiresAt, String reason, String actor) { }

    public record RecordedClaim(UUID claimId, boolean created) { }

    private static final String ROLE = "TECHNICAL_OWNER";
    private static final Map<String, Set<String>> CLASSES_BY_KIND = Map.of(
            "MANUAL", Set.of("MANUAL"),
            "SERVICENOW", Set.of("SERVICENOW"),
            "AWS", Set.of("CLOUD_STRUCTURED", "CLOUD_TAG"),
            "GCP", Set.of("CLOUD_STRUCTURED", "CLOUD_TAG"),
            "AI_GRID", Set.of("AI_GRID"),
            "ENTRA", Set.of("DIRECTORY"),
            "OKTA", Set.of("DIRECTORY"));

    private final JdbcTemplate jdbc;
    private final OwnershipResolutionService resolution;
    private final OwnershipEvents events;

    public OwnershipClaimService(JdbcTemplate jdbc, OwnershipResolutionService resolution, OwnershipEvents events) {
        this.jdbc = jdbc;
        this.resolution = resolution;
        this.events = events;
    }

    @Transactional
    public RecordedClaim recordClaim(ClaimRequest req) {
        validate(req);
        if (sourcePaused(req.sourceKind())) throw new ResponseStatusException(HttpStatus.CONFLICT, "This ownership source is paused");
        Boolean teamActive = jdbc.query("SELECT status = 'ACTIVE' FROM team WHERE id = ?", rs -> rs.next() ? rs.getBoolean(1) : null, req.teamId());
        if (teamActive == null) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Team not found");
        if (!teamActive) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Team is archived");

        String key = idempotencyKey(req);
        List<UUID> inserted = jdbc.queryForList("""
                INSERT INTO ownership_claim (tenant_id, id, subject_id, role, team_id, principal_user_id, source_kind, priority_class, source_id,
                    source_ref, idempotency_key, producer_version, observed_at, stale_after, expires_at, reason, actor)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
                RETURNING id
                """, UUID.class, UUID.randomUUID(), req.subjectId(), ROLE, req.teamId(), req.principalUserId(), req.sourceKind(),
                req.priorityClass(), req.sourceId(), req.sourceRef(), key, req.producerVersion(), ts(req.observedAt()),
                ts(req.staleAfter()), ts(req.expiresAt()), blankToNull(req.reason()), req.actor());
        if (inserted.isEmpty()) {
            // Replay of an observation already recorded: no write. A different team under the same key is a producer bug.
            UUID existingTeam = jdbc.queryForObject("SELECT team_id FROM ownership_claim WHERE idempotency_key = ?", UUID.class, key);
            if (!req.teamId().equals(existingTeam)) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "This observation was already recorded with a different team");
            }
            UUID id = jdbc.queryForObject("SELECT id FROM ownership_claim WHERE idempotency_key = ?", UUID.class, key);
            return new RecordedClaim(id, false);
        }
        UUID claimId = inserted.get(0);
        List<UUID> superseded = jdbc.queryForList("""
                UPDATE ownership_claim SET status = 'SUPERSEDED', ended_at = now(), ended_by = ?, updated_at = now()
                 WHERE subject_id = ? AND role = ? AND source_kind = ? AND source_ref = ? AND status = 'ACTIVE' AND id <> ?
                RETURNING id
                """, UUID.class, req.actor(), req.subjectId(), ROLE, req.sourceKind(), req.sourceRef(), claimId);
        events.record("CLAIM_RECORDED", req.subjectId(), null, claimId, req.actor(), "sourceKind", req.sourceKind(),
                "priorityClass", req.priorityClass(), "teamId", req.teamId(), "supersededClaimIds", superseded);
        resolution.resolveSubject(req.subjectId(), req.actor());
        return new RecordedClaim(claimId, true);
    }

    @Transactional
    public void revokeClaim(UUID claimId, String actor, String reason) {
        List<UUID> subject = jdbc.queryForList("""
                UPDATE ownership_claim SET status = 'REVOKED', ended_at = now(), ended_by = ?, updated_at = now()
                 WHERE id = ? AND status = 'ACTIVE' RETURNING subject_id
                """, UUID.class, actor, claimId);
        if (subject.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Active claim not found");
        events.record("CLAIM_REVOKED", subject.get(0), null, claimId, actor, "hasReason", reason != null && !reason.isBlank());
        resolution.resolveSubject(subject.get(0), actor);
    }

    /**
     * Records that active claims were observed again unchanged: moves only their observation, staleness and expiry
     * timestamps. The eligible set and the resolver watermark are unchanged, so no assignment is rewritten.
     */
    @Transactional
    public int reobserve(List<UUID> claimIds, Instant observedAt, Instant staleAfter, Instant expiresAt) {
        if (claimIds.isEmpty()) return 0;
        if (expiresAt != null && !expiresAt.isAfter(observedAt)) throw bad("Expiry must be after the observation time");
        if (staleAfter != null && !staleAfter.isAfter(observedAt)) throw bad("Staleness must be after the observation time");
        return jdbc.update("""
                UPDATE ownership_claim SET observed_at = ?, stale_after = ?, expires_at = ?, updated_at = now()
                 WHERE id = ANY (?::uuid[]) AND status = 'ACTIVE' AND observed_at <= ?
                """, ts(observedAt), ts(staleAfter), ts(expiresAt),
                "{" + String.join(",", claimIds.stream().map(UUID::toString).toList()) + "}", ts(observedAt));
    }

    /** Ends active claims whose source no longer reports them (only after a complete authoritative scan). */
    @Transactional
    public int endAbsent(List<UUID> claimIds, String actor) {
        if (claimIds.isEmpty()) return 0;
        List<UUID> subjects = jdbc.queryForList("""
                UPDATE ownership_claim SET status = 'REVOKED', ended_at = now(), ended_by = ?, updated_at = now()
                 WHERE id = ANY (?::uuid[]) AND status = 'ACTIVE' RETURNING subject_id
                """, UUID.class, actor, "{" + String.join(",", claimIds.stream().map(UUID::toString).toList()) + "}");
        subjects.stream().distinct().sorted().forEach(subject -> {
            events.record("CLAIM_ABSENT", subject, null, null, actor);
            resolution.resolveSubject(subject, actor);
        });
        return subjects.size();
    }

    /**
     * Marks up to {@code limit} past-expiry claims EXPIRED and re-resolves their subjects. The resolver already
     * ignores expired claims, so this keeps stored direct results current between other changes.
     */
    @Transactional
    public int expireDue(int limit) {
        List<UUID> subjects = jdbc.queryForList("""
                UPDATE ownership_claim SET status = 'EXPIRED', ended_at = now(), ended_by = 'system', updated_at = now()
                 WHERE id IN (SELECT id FROM ownership_claim WHERE status = 'ACTIVE' AND expires_at <= now()
                               ORDER BY expires_at LIMIT ? FOR UPDATE SKIP LOCKED)
                RETURNING subject_id
                """, UUID.class, limit);
        List<UUID> distinct = subjects.stream().distinct().sorted().toList();
        distinct.forEach(subject -> {
            events.record("CLAIMS_EXPIRED", subject, null, null, "system");
            resolution.resolveSubject(subject, "system");
        });
        return subjects.size();
    }

    public boolean sourcePaused(String sourceKind) {
        UUID tenantId = TenantContext.getCurrentTenantId();
        if (tenantId == null) throw new IllegalStateException("Ownership claims require a tenant context");
        return Boolean.TRUE.equals(jdbc.queryForObject("""
                SELECT EXISTS (SELECT 1 FROM platform.ownership_kill_switches
                                WHERE source_kind = ? AND state = 'PAUSED' AND (tenant_id IS NULL OR tenant_id = ?))
                """, Boolean.class, sourceKind, tenantId));
    }

    static String idempotencyKey(ClaimRequest req) {
        return String.join("|", String.valueOf(TenantContext.getCurrentTenantId()), req.sourceKind(), req.subjectId().toString(),
                ROLE, req.sourceRef(), req.observationVersion());
    }

    private static void validate(ClaimRequest req) {
        Objects.requireNonNull(req.subjectId(), "subjectId");
        Objects.requireNonNull(req.teamId(), "teamId");
        Objects.requireNonNull(req.observedAt(), "observedAt");
        Set<String> classes = CLASSES_BY_KIND.get(req.sourceKind());
        if (classes == null || !classes.contains(req.priorityClass())) throw bad("Unsupported source kind / priority class");
        if (blank(req.sourceRef()) || blank(req.observationVersion()) || blank(req.producerVersion()) || blank(req.actor())) {
            throw bad("Source reference, observation version, producer version and actor are required");
        }
        if ("MANUAL".equals(req.priorityClass()) && blank(req.reason())) throw bad("A reason is required for manual assignment");
        if (req.expiresAt() != null && !req.expiresAt().isAfter(req.observedAt())) throw bad("Expiry must be after the observation time");
        if (req.staleAfter() != null && !req.staleAfter().isAfter(req.observedAt())) throw bad("Staleness must be after the observation time");
    }

    private static boolean blank(String value) {
        return value == null || value.isBlank();
    }

    private static String blankToNull(String value) {
        return blank(value) ? null : value.strip();
    }

    private static ResponseStatusException bad(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private static Timestamp ts(Instant instant) {
        return instant == null ? null : Timestamp.from(instant);
    }
}
