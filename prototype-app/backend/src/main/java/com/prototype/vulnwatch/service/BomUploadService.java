package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.IngestionJob;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomIngestionResultResponse;
import com.prototype.vulnwatch.dto.BomSourceSelector;
import com.prototype.vulnwatch.dto.BomUploadRequest;
import com.zaxxer.hikari.HikariDataSource;
import java.io.IOException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import software.amazon.awssdk.services.s3.model.S3Exception;

@Service
public class BomUploadService {
    private static final Duration PUT_TTL = Duration.ofMinutes(5);
    private static final Duration INTENT_TTL = Duration.ofHours(24);
    private static final long GLOBAL_IMPORT_LOCK = 0x424F4D55504C4F41L;
    private static final Set<String> UPLOAD_ROLES = Set.of("INVENTORY_ADMIN", "TENANT_ADMIN", "CREATOR");
    private static final String INTENT_SELECT = """
            select u.id,u.actor_id,u.metadata,u.expires_at,u.object_version,u.job_id,j.status
              from bom_upload_intents u left join ingestion_jobs j on j.id=u.job_id
             where u.tenant_id=?
            """;

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final BomUploadStorage storage;
    private final TenantSchemaExecutionService schemas;
    private final IngestionJobService jobs;
    private final TenantQuotaService quotas;
    private final BomIngestionOrchestrator orchestrator;
    private final HikariDataSource database;
    private final AtomicBoolean workerSlotBusy = new AtomicBoolean();

    BomUploadService(JdbcTemplate jdbc, ObjectMapper mapper, BomUploadStorage storage,
                     TenantSchemaExecutionService schemas, IngestionJobService jobs,
                     TenantQuotaService quotas, BomIngestionOrchestrator orchestrator,
                     @Qualifier("hikariDataSource") HikariDataSource database) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.storage = storage;
        this.schemas = schemas;
        this.jobs = jobs;
        this.quotas = quotas;
        this.orchestrator = orchestrator;
        this.database = database;
    }

    public UploadTicket create(Tenant tenant, RequestActor actor, UUID idempotencyKey, BomUploadRequest request) {
        storage.requireConfigured();
        byte[] sha = Base64.getDecoder().decode(request.sha256());
        if (sha.length != 32 || !request.sha256().equals(Base64.getEncoder().encodeToString(sha))) {
            throw error(HttpStatus.BAD_REQUEST, "Use a canonical base64 SHA-256 checksum");
        }
        Intent intent = jobs.withAdmission(tenant, () -> {
            Member member = currentMember(tenant, actor);
            Intent existing = find(INTENT_SELECT + " and u.actor_id=? and u.idempotency_key=?",
                    tenant.getId(), member.id(), idempotencyKey);
            if (existing != null) {
                if (!existing.metadata().equals(request)) {
                    throw error(HttpStatus.CONFLICT, "Idempotency key was already used for a different upload");
                }
                return existing;
            }
            quotas.assertCanCreateSbomIngestionJob(tenant, "bom-upload");
            boolean pending = Boolean.TRUE.equals(jdbc.queryForObject("""
                    select exists(select 1 from bom_upload_intents
                     where tenant_id=? and job_id is null and expires_at>now())
                    """, Boolean.class, tenant.getId()));
            if (pending) {
                throw error(HttpStatus.CONFLICT, "The workspace already has an unfinished BOM upload");
            }
            UUID id = UUID.randomUUID();
            Instant expiresAt = Instant.now().plus(INTENT_TTL);
            jdbc.update("""
                    insert into bom_upload_intents(id,tenant_id,actor_id,idempotency_key,metadata,expires_at)
                    values (?,?,?,?,cast(? as jsonb),?)
                    """, id, tenant.getId(), member.id(), idempotencyKey, jobs.toJson(request), Timestamp.from(expiresAt));
            return new Intent(id, member.id(), request, expiresAt, null, null, null);
        });
        if (intent.jobId() != null) {
            return new UploadTicket(status(intent), null, Map.of());
        }
        Duration remaining = Duration.between(Instant.now(), intent.expiresAt());
        if (remaining.toSeconds() < 1) {
            throw error(HttpStatus.GONE, "BOM upload intent has expired");
        }
        Duration ttl = remaining.compareTo(PUT_TTL) < 0 ? remaining : PUT_TTL;
        var signed = storage.sign(key(tenant, intent.id()), request.size(), request.sha256(), ttl);
        return new UploadTicket(status(intent), signed.url(), signed.headers());
    }

    public UploadStatus get(Tenant tenant, RequestActor actor, UUID id) {
        return schemas.run(tenant, () -> status(ownedIntent(tenant, actor, id)));
    }

    public UploadStatus complete(Tenant tenant, RequestActor actor, UUID id) {
        Intent pending = schemas.run(tenant, () -> ownedIntent(tenant, actor, id));
        if (pending.jobId() != null) {
            return status(pending);
        }
        assertUnexpired(pending);
        String version;
        try {
            version = storage.verifiedVersion(key(tenant, id), pending.metadata().size(), pending.metadata().sha256());
        } catch (IllegalArgumentException mismatch) {
            throw error(HttpStatus.UNPROCESSABLE_ENTITY, mismatch.getMessage());
        } catch (S3Exception failure) {
            if (failure.statusCode() == 404) {
                throw error(HttpStatus.CONFLICT, "BOM upload has not reached object storage");
            }
            throw error(HttpStatus.BAD_GATEWAY, "Object storage could not verify the BOM upload");
        }
        return jobs.withAdmission(tenant, () -> {
            Intent current = ownedIntent(tenant, actor, id);
            if (current.jobId() != null) {
                return status(current);
            }
            assertUnexpired(current);
            var job = jobs.enqueueBomUpload(tenant, id, current.metadata().assetIdentifier(), actor.userId());
            jdbc.update("""
                    update bom_upload_intents set object_version=?,job_id=?
                     where tenant_id=? and id=?
                    """, version, job.jobId(), tenant.getId(), id);
            return new UploadStatus(id, job.status(), current.expiresAt(), job.jobId());
        });
    }

    PreparedUpload prepare(Tenant tenant, IngestionJob job) throws IOException {
        UUID id = jobs.readPayload(job, IngestionJobService.BomUploadJobPayload.class).uploadId();
        Intent intent = schemas.run(tenant, () -> {
            Intent accepted = find(INTENT_SELECT + " and u.id=? and u.job_id=?", tenant.getId(), id, job.getId());
            if (accepted == null || accepted.version() == null) {
                throw new IllegalStateException("BOM job has no accepted upload intent");
            }
            currentMember(tenant.getId(), accepted.actorId(), null, false);
            return accepted;
        });
        BomUploadRequest request = intent.metadata();
        byte[] bytes = storage.read(key(tenant, id), intent.version(), request.size(), request.sha256());
        var document = orchestrator.prepareDocument(tenant, request.bomType(), request.supplier(), bytes);
        return new PreparedUpload(intent.actorId(), request, document);
    }

    BomIngestionResultResponse persist(Tenant tenant, PreparedUpload upload) throws IOException {
        Member member = currentMember(tenant.getId(), upload.actorId(), null, true);
        BomUploadRequest request = upload.metadata();
        var selector = new BomSourceSelector(request.sourceId(), null, request.completeness(),
                Set.of(member.role()), member.subject());
        return orchestrator.ingestPreparedUpload(tenant, request, upload.document(), selector);
    }

    boolean withWorkerSlot(Tenant tenant, BooleanSupplier claimAndRun) {
        if (!storage.configured() || !workerSlotBusy.compareAndSet(false, true)) {
            return false;
        }
        try {
            boolean pending = schemas.run(tenant, () -> Boolean.TRUE.equals(jdbc.queryForObject("""
                    select exists(select 1 from ingestion_jobs
                     where job_type='BOM_UPLOAD' and status='QUEUED' and visible_at<=now())
                    """, Boolean.class)));
            if (!pending) {
                return false;
            }
            // Reserve one connection before claiming. The session-level lock survives the
            // short claim transaction and releases on worker loss. No transaction spans S3.
            try (Connection connection = database.getConnection()) {
                if (!workerLock(connection, "select pg_try_advisory_lock(?)")) {
                    return false;
                }
                try {
                    return claimAndRun.getAsBoolean();
                } finally {
                    if (!workerLock(connection, "select pg_advisory_unlock(?)")) {
                        database.evictConnection(connection);
                        throw new IllegalStateException("BOM upload worker slot was lost");
                    }
                }
            } catch (SQLException failure) {
                throw new IllegalStateException("BOM upload worker slot is unavailable", failure);
            }
        } finally {
            workerSlotBusy.set(false);
        }
    }

    private boolean workerLock(Connection connection, String sql) throws SQLException {
        try (var statement = connection.prepareStatement(sql)) {
            statement.setLong(1, GLOBAL_IMPORT_LOCK);
            try (var result = statement.executeQuery()) {
                return result.next() && result.getBoolean(1);
            }
        } catch (SQLException failure) {
            // Never return a session that may still hold the global lock to Hikari.
            database.evictConnection(connection);
            throw failure;
        }
    }

    private Intent ownedIntent(Tenant tenant, RequestActor actor, UUID id) {
        Member member = currentMember(tenant, actor);
        Intent intent = find(INTENT_SELECT + " and u.id=? and u.actor_id=?", tenant.getId(), id, member.id());
        if (intent == null) {
            throw error(HttpStatus.NOT_FOUND, "BOM upload intent not found");
        }
        return intent;
    }

    private Member currentMember(Tenant tenant, RequestActor actor) {
        if (!tenant.getId().equals(actor.tenantId()) || !actor.hasDirectTenantMembership()) {
            throw error(HttpStatus.FORBIDDEN, "A direct workspace membership is required for BOM uploads");
        }
        return currentMember(tenant.getId(), null, actor.userId(), false);
    }

    private Member currentMember(UUID tenantId, UUID actorId, String subject, boolean lock) {
        String match = actorId == null ? "u.external_subject" : "u.id";
        List<Member> matches = jdbc.query("""
                select u.id,u.external_subject,m.role
                  from platform.app_users u join platform.tenant_memberships m on m.user_id=u.id
                  join platform.tenants t on t.id=m.tenant_id
                 where m.tenant_id=? and t.status='ACTIVE' and t.deleted_at is null
                   and t.purge_started_at is null and t.purged_at is null and t.expired_at is null
                   and (t.demo_expires_at is null or t.demo_expires_at>now())
                   and m.status='ACTIVE' and u.status='ACTIVE' and %s=?
                """.formatted(match) + (lock ? " for share of u,m,t" : ""),
                (rs, row) -> new Member(rs.getObject("id", UUID.class), rs.getString("external_subject"), rs.getString("role")),
                tenantId, actorId == null ? subject : actorId);
        if (matches.size() != 1 || !UPLOAD_ROLES.contains(matches.get(0).role())) {
            throw error(HttpStatus.FORBIDDEN, "Current membership does not permit BOM uploads");
        }
        return matches.get(0);
    }

    private Intent find(String sql, Object... args) {
        RowMapper<Intent> row = (rs, index) -> new Intent(rs.getObject("id", UUID.class),
                rs.getObject("actor_id", UUID.class), readMetadata(rs.getString("metadata")),
                rs.getTimestamp("expires_at").toInstant(), rs.getString("object_version"),
                rs.getObject("job_id", UUID.class), rs.getString("status"));
        return jdbc.query(sql, row, args).stream().findFirst().orElse(null);
    }

    private BomUploadRequest readMetadata(String json) {
        try {
            return mapper.readValue(json, BomUploadRequest.class);
        } catch (JsonProcessingException failure) {
            throw new IllegalStateException("Stored BOM upload metadata is invalid", failure);
        }
    }

    private static void assertUnexpired(Intent intent) {
        if (!Instant.now().isBefore(intent.expiresAt())) {
            throw error(HttpStatus.GONE, "BOM upload intent has expired");
        }
    }

    private static UploadStatus status(Intent intent) {
        String state = intent.jobId() != null ? intent.jobStatus()
                : Instant.now().isBefore(intent.expiresAt()) ? "PENDING" : "EXPIRED";
        return new UploadStatus(intent.id(), state, intent.expiresAt(), intent.jobId());
    }

    private static String key(Tenant tenant, UUID id) {
        return tenant.getId() + "/" + id;
    }

    private static ResponseStatusException error(HttpStatus status, String message) {
        return new ResponseStatusException(status, message);
    }

    private record Member(UUID id, String subject, String role) { }
    private record Intent(UUID id, UUID actorId, BomUploadRequest metadata, Instant expiresAt,
                          String version, UUID jobId, String jobStatus) { }
    record PreparedUpload(UUID actorId, BomUploadRequest metadata, BomIngestionOrchestrator.PreparedDocument document) { }
    public record UploadStatus(UUID uploadId, String status, Instant expiresAt, UUID jobId) { }
    public record UploadTicket(UploadStatus upload, String uploadUrl, Map<String, String> uploadHeaders) { }
}
