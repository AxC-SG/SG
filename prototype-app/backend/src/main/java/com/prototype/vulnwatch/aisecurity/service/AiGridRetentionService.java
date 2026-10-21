package com.prototype.vulnwatch.aisecurity.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AiGridRetentionService {
    private final NamedParameterJdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactions;
    @org.springframework.beans.factory.annotation.Value("${app.ai-security.retention.batch-size:100}")
    private int batchSize = 100;
    @org.springframework.beans.factory.annotation.Value("${app.ai-security.retention.max-batches:10}")
    private int maxBatches = 10;
    @org.springframework.beans.factory.annotation.Value("${app.ai-security.retention.max-sweep-seconds:30}")
    private int maxSweepSeconds = 30;

    public AiGridRetentionService(NamedParameterJdbcTemplate jdbc,
                                  TenantSchemaExecutionService tenantExecution,
                                  TransactionTemplate transactions) {
        this.jdbc = jdbc;
        this.tenantExecution = tenantExecution;
        this.transactions = transactions;
    }

    public RetentionStatus status(Tenant tenant) {
        return tenantExecution.run(tenant, () -> new RetentionStatus(policies(), counts(), activeHolds(), cleanupState()));
    }

    public RetentionPolicy updatePolicy(Tenant tenant, PolicyCommand command, String actor) {
        if (!List.of("HOT", "ARCHIVE", "RESTRICTED_EVIDENCE").contains(command.retentionClass())) {
            throw badRequest("Invalid retention class");
        }
        if (command.retainDays() <= 0 || (command.archiveAfterDays() != null
                && (command.archiveAfterDays() < 0 || command.archiveAfterDays() >= command.retainDays()))) {
            throw badRequest("Invalid retention duration");
        }
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            jdbc.update("""
                    update ai_grid_retention_policies set retain_days = :retainDays,
                        archive_after_days = :archiveDays, restricted = :restricted,
                        updated_by = :actor, reason = :reason, updated_at = now()
                     where retention_class = :class
                    """, new MapSqlParameterSource().addValue("retainDays", command.retainDays())
                    .addValue("archiveDays", command.archiveAfterDays()).addValue("restricted", command.restricted())
                    .addValue("actor", actor).addValue("reason", required(command.reason(), "reason"))
                    .addValue("class", command.retentionClass()));
            String retentionBound = command.restricted() ? "least" : "greatest";
            jdbc.update(("""
                    update ai_grid_snapshot_bodies
                       set retain_until = %s(retain_until, created_at + (:days * interval '1 day'))
                     where retention_class = :class
                    """).formatted(retentionBound), Map.of("days", command.retainDays(),
                    "class", command.retentionClass()));
            return policies().stream().filter(policy -> policy.retentionClass().equals(command.retentionClass()))
                    .findFirst().orElseThrow();
        }));
    }

    public EvidenceHold createHold(Tenant tenant, HoldCommand command, String actor) {
        if (!List.of("ACTIVE_FINDING", "EXCEPTION", "LEGAL_HOLD", "REPLAY_COMMITMENT")
                .contains(command.holdType())) throw badRequest("Invalid evidence hold type");
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            lockHoldBody(command.snapshotBodyId());
            UUID id = UUID.randomUUID();
            int inserted = jdbc.update("""
                    insert into ai_grid_evidence_holds
                        (id, tenant_id, snapshot_body_id, hold_type, reference_id, reason,
                         expires_at, created_by)
                    values (:id, :tenantId, :bodyId, :type, :referenceId, :reason, :expiresAt, :actor)
                    on conflict (tenant_id, snapshot_body_id, hold_type, reference_id) do nothing
                    """, new MapSqlParameterSource().addValue("id", id).addValue("tenantId", tenant.getId())
                    .addValue("bodyId", command.snapshotBodyId()).addValue("type", command.holdType())
                    .addValue("referenceId", required(command.referenceId(), "referenceId"))
                    .addValue("reason", required(command.reason(), "reason"))
                    .addValue("expiresAt", command.expiresAt() == null ? null : Timestamp.from(command.expiresAt()))
                    .addValue("actor", actor));
            if (inserted == 0) {
                id = jdbc.queryForObject("""
                        select id from ai_grid_evidence_holds where snapshot_body_id = :bodyId
                          and hold_type = :type and reference_id = :referenceId
                        """, Map.of("bodyId", command.snapshotBodyId(), "type", command.holdType(),
                        "referenceId", command.referenceId()), UUID.class);
                EvidenceHold existing = hold(id);
                if (existing.releasedAt() != null || (existing.expiresAt() != null && !existing.expiresAt().isAfter(Instant.now()))) {
                    throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,
                            "Released or expired holds require a new referenceId; historical provenance is retained");
                }
            }
            if ("LEGAL_HOLD".equals(command.holdType())) {
                jdbc.update("update ai_grid_snapshot_bodies set legal_hold = true where id = :id",
                        Map.of("id", command.snapshotBodyId()));
            }
            if ("REPLAY_COMMITMENT".equals(command.holdType()) && command.expiresAt() != null) {
                jdbc.update("""
                        update ai_grid_snapshot_bodies set replay_commitment_until =
                            greatest(coalesce(replay_commitment_until, :expiresAt), :expiresAt)
                         where id = :id
                        """, Map.of("expiresAt", Timestamp.from(command.expiresAt()), "id", command.snapshotBodyId()));
            }
            return hold(id);
        }));
    }

    public EvidenceHold releaseHold(Tenant tenant, UUID holdId, String actor) {
        return tenantExecution.run(tenant, () -> transactions.execute(status -> {
            EvidenceHold existing = hold(holdId);
            lockHoldBody(existing.snapshotBodyId());
            jdbc.update("""
                    update ai_grid_evidence_holds set released_at = now(), released_by = :actor
                     where id = :id and released_at is null
                    """, Map.of("actor", actor, "id", holdId));
            if ("LEGAL_HOLD".equals(existing.holdType())) {
                jdbc.update("""
                        update ai_grid_snapshot_bodies set legal_hold = false where id = :bodyId
                          and not exists (select 1 from ai_grid_evidence_holds
                              where snapshot_body_id = :bodyId and hold_type = 'LEGAL_HOLD'
                                and released_at is null and (expires_at is null or expires_at > now()))
                        """, Map.of("bodyId", existing.snapshotBodyId()));
            }
            return hold(holdId);
        }));
    }

    private void lockHoldBody(UUID bodyId) {
        jdbc.query("select id from ai_grid_snapshot_bodies where id=:id for update", Map.of("id",bodyId), rs -> null);
    }

    public SweepResult sweep(Tenant tenant) {
        return tenantExecution.run(tenant, () -> {
            int evaluated = 0, retained = 0, archived = 0, blocked = 0, eligible = 0, purged = 0, batches = 0;
            long started = System.nanoTime();
            boolean complete = false;
            TransactionTemplate bounded = new TransactionTemplate(transactions.getTransactionManager());
            bounded.setPropagationBehavior(org.springframework.transaction.TransactionDefinition.PROPAGATION_REQUIRES_NEW);
            bounded.setTimeout(10);
            try {
                while (batches < Math.max(1, maxBatches)
                        && System.nanoTime() - started < Math.max(1, maxSweepSeconds) * 1_000_000_000L) {
                    SweepResult batch = bounded.execute(status -> sweepBatch(tenant));
                    if (batch == null) throw new IllegalStateException("Retention batch returned no outcome");
                    evaluated += batch.evaluated(); retained += batch.retained(); archived += batch.archived();
                    blocked += batch.purgeBlocked(); eligible += batch.purgeEligible(); purged += batch.purged();
                    batches++;
                    if ("COMPLETED".equals(batch.status())) { complete = true; break; }
                }
            } catch (RuntimeException error) {
                bounded.executeWithoutResult(status -> jdbc.update("""
                        insert into ai_grid_retention_progress (tenant_id, state, last_error)
                        values (:tenantId, 'FAILED', 'BATCH_FAILED')
                        on conflict (tenant_id) do update set state = 'FAILED', last_error = 'BATCH_FAILED',
                            updated_at = now()
                        """, Map.of("tenantId", tenant.getId())));
                throw error;
            }
            return new SweepResult(evaluated, retained, archived, blocked, eligible, purged,
                    complete ? "COMPLETED" : "INCOMPLETE", batches, Math.max(1, batchSize));
        });
    }

    private SweepResult sweepBatch(Tenant tenant) {
        jdbc.getJdbcTemplate().execute("set local statement_timeout = '10s'");
        jdbc.getJdbcTemplate().execute("set local lock_timeout = '1s'");
        jdbc.update("""
                insert into ai_grid_retention_progress (tenant_id, state) values (:tenantId, 'NOT_RUN')
                on conflict (tenant_id) do nothing
                """, Map.of("tenantId", tenant.getId()));
        Map<String, Object> progress = jdbc.queryForMap("""
                select after_id, upper_id from ai_grid_retention_progress
                 where tenant_id = :tenantId for update
                """, Map.of("tenantId", tenant.getId()));
        UUID after = (UUID) progress.get("after_id");
        UUID upper = (UUID) progress.get("upper_id");
        if (upper == null) {
            upper = jdbc.query("select id from ai_grid_snapshot_bodies order by id desc limit 1",
                    (rs, row) -> rs.getObject(1, UUID.class)).stream().findFirst().orElse(null);
            jdbc.update("""
                    update ai_grid_retention_progress set upper_id = :upper, after_id = null,
                        state = 'RUNNING', last_started_at = now(), last_error = null, updated_at = now()
                     where tenant_id = :tenantId
                    """, new MapSqlParameterSource("tenantId", tenant.getId()).addValue("upper", upper));
        }
        List<Body> bodies = upper == null ? List.of() : jdbc.query("""
                select id, retention_class, retention_state, created_at, retain_until,
                       legal_hold, replay_commitment_until from ai_grid_snapshot_bodies
                 where (:afterId::uuid is null or id > :afterId::uuid) and id <= :upperId
                 order by id limit :batchSize for update
                """, new MapSqlParameterSource("afterId", after).addValue("upperId", upper)
                .addValue("batchSize", Math.max(1, batchSize)),
                (rs, n) -> new Body(rs.getObject("id", UUID.class), rs.getString("retention_class"),
                rs.getString("retention_state"), rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("retain_until").toInstant(), rs.getBoolean("legal_hold"),
                instant(rs, "replay_commitment_until")));
            Map<String, RetentionPolicy> policyByClass = new java.util.HashMap<>();
            policies().forEach(policy -> policyByClass.put(policy.retentionClass(), policy));
            int retained = 0, archived = 0, blocked = 0, eligible = 0;
            for (Body body : bodies) {
                String decision;
                String reason;
                Instant now = Instant.now();
                RetentionPolicy policy = policyByClass.get(body.retentionClass());
                boolean archiveAgeReached = "HOT".equals(body.retentionClass()) && policy != null
                        && policy.archiveAfterDays() != null
                        && !body.createdAt().plusSeconds(policy.archiveAfterDays() * 86400L).isAfter(now);
                RetentionPolicy archivePolicy = policyByClass.get("ARCHIVE");
                Instant archiveUntil = archivePolicy == null ? body.retainUntil()
                        : body.createdAt().plusSeconds(archivePolicy.retainDays() * 86400L);
                if (archiveAgeReached && archiveUntil.isAfter(now)) {
                        jdbc.update("""
                                update ai_grid_snapshot_bodies set retention_class = 'ARCHIVE',
                                    retention_state = 'ARCHIVED', retain_until = :retainUntil
                                 where id = :id
                                """, Map.of("id", body.id(), "retainUntil", Timestamp.from(archiveUntil)));
                    decision = "ARCHIVE"; reason = "ARCHIVE_AGE_REACHED"; archived++;
                } else if (body.retainUntil().isAfter(now)) {
                    decision = "RETAIN"; reason = "RETENTION_WINDOW_ACTIVE"; retained++;
                } else {
                    String protection = protection(body);
                    if (protection == null) {
                        jdbc.update("update ai_grid_snapshot_bodies set retention_state = 'PURGE_ELIGIBLE' where id = :id",
                                Map.of("id", body.id()));
                        decision = "PURGE_ELIGIBLE"; reason = "RETENTION_EXPIRED_UNPROTECTED"; eligible++;
                    } else {
                        jdbc.update("update ai_grid_snapshot_bodies set retention_state = 'PURGE_BLOCKED' where id = :id",
                                Map.of("id", body.id()));
                        decision = "PURGE_BLOCKED"; reason = protection; blocked++;
                    }
                }
                jdbc.update("""
                        insert into ai_grid_retention_decisions
                            (id, tenant_id, snapshot_body_id, decision, reason_code)
                        select :id, :tenantId, :bodyId, :decision, :reason
                         where not exists (select 1 from ai_grid_retention_decisions
                           where snapshot_body_id = :bodyId and decision = :decision and reason_code = :reason)
                        """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                        .addValue("tenantId", tenant.getId()).addValue("bodyId", body.id())
                        .addValue("decision", decision).addValue("reason", reason));
            }
            int purged = bodies.isEmpty() ? 0 : purgeUnreferencedEligible(tenant, bodies.stream().map(Body::id).toList());
            boolean complete = bodies.size() < Math.max(1, batchSize);
            jdbc.update("""
                    update ai_grid_retention_progress set after_id = :afterId, upper_id = :upperId,
                        state = :state, updated_at = now(), last_error = null,
                        last_completed_at = case when :complete then now() else last_completed_at end
                     where tenant_id = :tenantId
                    """, new MapSqlParameterSource("tenantId", tenant.getId())
                    .addValue("afterId", complete ? null : bodies.get(bodies.size() - 1).id())
                    .addValue("upperId", complete ? null : upper).addValue("complete", complete)
                    .addValue("state", complete ? "COMPLETED" : "INCOMPLETE"));
            return new SweepResult(bodies.size(), retained, archived, blocked, eligible, purged,
                    complete ? "COMPLETED" : "INCOMPLETE", 1, Math.max(1, batchSize));
    }

    private int purgeUnreferencedEligible(Tenant tenant, List<UUID> bodyIds) {
        List<PurgeCandidate> candidates = jdbc.query("""
                select b.id, b.content_hash, b.byte_size
                  from ai_grid_snapshot_bodies b
                 where b.retention_state = 'PURGE_ELIGIBLE' and b.id in (:bodyIds)
                   and b.retain_until <= now() and b.legal_hold = false
                   and (b.replay_commitment_until is null or b.replay_commitment_until <= now())
                   and not exists (select 1 from ai_grid_snapshot_manifests m where m.body_id = b.id)
                   and not exists (select 1 from ai_grid_evidence_holds h
                                    where h.snapshot_body_id = b.id and h.released_at is null
                                      and (h.expires_at is null or h.expires_at > now()))
                 order by b.retain_until, b.id limit :batchSize
                 for update
                """, Map.of("bodyIds", bodyIds, "batchSize", Math.max(1, batchSize)), (rs, n) -> new PurgeCandidate(rs.getObject("id", UUID.class),
                rs.getString("content_hash"), rs.getLong("byte_size")));
        for (PurgeCandidate candidate : candidates) {
            jdbc.update("""
                    insert into ai_grid_retention_purge_audit
                        (id, tenant_id, snapshot_body_id, content_hash, byte_size, reason_code, purged_by)
                    values (:id, :tenantId, :bodyId, :hash, :bytes,
                            'RETENTION_EXPIRED_UNREFERENCED', 'ai-grid-retention-sweeper')
                    """, new MapSqlParameterSource().addValue("id", UUID.randomUUID())
                    .addValue("tenantId", tenant.getId()).addValue("bodyId", candidate.id())
                    .addValue("hash", candidate.contentHash()).addValue("bytes", candidate.byteSize()));
            jdbc.update("delete from ai_grid_snapshot_bodies where id = :id", Map.of("id", candidate.id()));
        }
        return candidates.size();
    }

    private String protection(Body body) {
        if (body.legalHold()) return "LEGAL_HOLD";
        if (body.replayCommitmentUntil() != null && body.replayCommitmentUntil().isAfter(Instant.now())) {
            return "REPLAY_COMMITMENT";
        }
        Integer explicit = jdbc.queryForObject("""
                select count(*) from ai_grid_evidence_holds where snapshot_body_id = :id
                  and released_at is null and (expires_at is null or expires_at > now())
                """, Map.of("id", body.id()), Integer.class);
        if (explicit != null && explicit > 0) return "ACTIVE_EVIDENCE_HOLD";
        Integer activeFinding = jdbc.queryForObject("""
                select count(*) from ai_grid_snapshot_manifests m
                  join ai_grid_assessments a on a.snapshot_manifest_id = m.id
                  join findings f on f.assessment_id = a.id
                 where m.body_id = :id and f.status = 'OPEN'
                """, Map.of("id", body.id()), Integer.class);
        if (activeFinding != null && activeFinding > 0) return "ACTIVE_FINDING";
        Integer references = jdbc.queryForObject(
                "select count(*) from ai_grid_snapshot_manifests where body_id = :id",
                Map.of("id", body.id()), Integer.class);
        return references != null && references > 0 ? "SNAPSHOT_REFERENCE" : null;
    }

    private List<RetentionPolicy> policies() {
        return jdbc.query("""
                select retention_class, retain_days, archive_after_days, restricted,
                       updated_by, reason, updated_at from ai_grid_retention_policies
                 order by retention_class
                """, (rs, n) -> new RetentionPolicy(rs.getString("retention_class"), rs.getInt("retain_days"),
                (Integer) rs.getObject("archive_after_days"), rs.getBoolean("restricted"),
                rs.getString("updated_by"), rs.getString("reason"), rs.getTimestamp("updated_at").toInstant()));
    }

    private CleanupState cleanupState() {
        return jdbc.query("""
                select state, after_id, last_started_at, last_completed_at, updated_at, last_error
                  from ai_grid_retention_progress
                """, (rs, row) -> new CleanupState(rs.getString("state"), rs.getObject("after_id", UUID.class),
                instant(rs, "last_started_at"), instant(rs, "last_completed_at"), instant(rs, "updated_at"),
                rs.getString("last_error"))).stream().findFirst()
                .orElse(new CleanupState("NOT_RUN", null, null, null, null, null));
    }

    private RetentionCounts counts() {
        return jdbc.queryForObject("""
                select count(*) bodies, coalesce(sum(byte_size), 0) bytes,
                       count(*) filter (where retention_state = 'ARCHIVED') archived,
                       count(*) filter (where retention_state = 'PURGE_BLOCKED') blocked,
                       count(*) filter (where retention_state = 'PURGE_ELIGIBLE') eligible
                  from ai_grid_snapshot_bodies
                """, Map.of(), (rs, n) -> new RetentionCounts(rs.getLong("bodies"), rs.getLong("bytes"),
                rs.getLong("archived"), rs.getLong("blocked"), rs.getLong("eligible")));
    }

    private List<EvidenceHold> activeHolds() {
        return jdbc.query("""
                select * from ai_grid_evidence_holds where released_at is null
                  and (expires_at is null or expires_at > now()) order by created_at desc
                """, (rs, n) -> mapHold(rs));
    }

    private EvidenceHold hold(UUID id) {
        EvidenceHold value = jdbc.query("select * from ai_grid_evidence_holds where id = :id",
                Map.of("id", id), rs -> rs.next() ? mapHold(rs) : null);
        if (value == null) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Evidence hold not found");
        return value;
    }

    private EvidenceHold mapHold(java.sql.ResultSet rs) throws java.sql.SQLException {
        return new EvidenceHold(rs.getObject("id", UUID.class), rs.getObject("snapshot_body_id", UUID.class),
                rs.getString("hold_type"), rs.getString("reference_id"), rs.getString("reason"),
                instant(rs, "expires_at"), instant(rs, "released_at"), rs.getString("created_by"),
                rs.getTimestamp("created_at").toInstant());
    }

    private Instant instant(java.sql.ResultSet rs, String column) throws java.sql.SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }
    private String required(String value, String field) {
        if (value == null || value.isBlank()) throw badRequest(field + " is required");
        return value;
    }
    private ResponseStatusException badRequest(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }

    private record Body(UUID id, String retentionClass, String retentionState, Instant createdAt,
                        Instant retainUntil, boolean legalHold, Instant replayCommitmentUntil) {}
    private record PurgeCandidate(UUID id, String contentHash, long byteSize) {}
    public record RetentionPolicy(String retentionClass, int retainDays, Integer archiveAfterDays,
                                  boolean restricted, String updatedBy, String reason, Instant updatedAt) {}
    public record RetentionCounts(long bodies, long retainedBytes, long archived, long purgeBlocked,
                                  long purgeEligible) {}
    public record RetentionStatus(List<RetentionPolicy> policies, RetentionCounts counts,
                                  List<EvidenceHold> activeHolds, CleanupState cleanup) {}
    public record CleanupState(String state, UUID afterId, Instant lastStartedAt, Instant lastCompletedAt,
                               Instant updatedAt, String lastError) {}
    public record EvidenceHold(UUID id, UUID snapshotBodyId, String holdType, String referenceId,
                               String reason, Instant expiresAt, Instant releasedAt, String createdBy,
                               Instant createdAt) {}
    public record SweepResult(int evaluated, int retained, int archived, int purgeBlocked,
                              int purgeEligible, int purged, String status, int batches, int batchSize) {}
    public record PolicyCommand(String retentionClass, int retainDays, Integer archiveAfterDays,
                                boolean restricted, String reason) {}
    public record HoldCommand(UUID snapshotBodyId, String holdType, String referenceId, String reason,
                              Instant expiresAt) {}
}
