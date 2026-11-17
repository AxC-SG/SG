package com.prototype.vulnwatch.service;

import java.time.Instant;
import java.sql.Timestamp;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Draft catalog instructions only; no finding or active membership mutation. */
@Service
public class CatalogOverrideService {
    public enum Operation { INCLUDE, EXCLUDE, RESTORE }
    public record Change(Long expectedRevision, Operation operation, String reason, Instant expiresAt) {}
    public record Entry(UUID vulnerabilityId, long revision, Operation operation, String reason,
                        Instant expiresAt, Instant createdAt) {}
    private final WorkspaceService workspace;
    private final NamedParameterJdbcTemplate jdbc;
    private final AuditEventService audit;
    public CatalogOverrideService(WorkspaceService workspace, NamedParameterJdbcTemplate jdbc, AuditEventService audit) {
        this.workspace = workspace; this.jdbc = jdbc; this.audit = audit;
    }

    @Transactional(readOnly = true)
    public List<Entry> history(UUID vulnerabilityId, Long beforeRevision) {
        UUID tenant = requireTenant();
        if (beforeRevision != null && beforeRevision <= 0) fail(HttpStatus.BAD_REQUEST, "Invalid history cursor");
        return jdbc.query("""
                select * from intelligence_catalog_overrides
                where tenant_id=:tenant and vulnerability_id=:id
                  and (cast(:before as bigint) is null or revision < :before)
                order by revision desc limit 100
                """, new MapSqlParameterSource("tenant", tenant).addValue("id", vulnerabilityId).addValue("before", beforeRevision),
                (rs, n) -> new Entry(rs.getObject("vulnerability_id", UUID.class), rs.getLong("revision"),
                        Operation.valueOf(rs.getString("operation")), rs.getString("reason"),
                        rs.getTimestamp("expires_at") == null ? null : rs.getTimestamp("expires_at").toInstant(),
                        rs.getTimestamp("created_at").toInstant()));
    }

    @Transactional
    public Entry change(UUID vulnerabilityId, Change change) {
        UUID tenant = requireTenant();
        if (change == null || change.operation() == null || change.expectedRevision() == null || change.expectedRevision() < 0
                || change.reason() == null || change.reason().isBlank() || change.reason().length() > 500)
            fail(HttpStatus.BAD_REQUEST, "Operation, expected revision and reason (1–500 characters) are required");
        if (change.expiresAt() != null && (change.operation() == Operation.RESTORE || !change.expiresAt().isAfter(Instant.now())))
            fail(HttpStatus.BAD_REQUEST, "Expiry must be in the future and cannot be used for restore");
        jdbc.getJdbcTemplate().query("select pg_advisory_xact_lock(hashtext(?))", rs -> null, "catalog-overrides:" + tenant);
        var withdrawn = jdbc.query("select intelligence_withdrawn from platform.vulnerabilities where id=:id for share",
                Map.of("id", vulnerabilityId), (rs, n) -> rs.getBoolean(1));
        if (withdrawn.isEmpty()) fail(HttpStatus.NOT_FOUND, "Central vulnerability not found");
        if (withdrawn.get(0) && change.operation() == Operation.INCLUDE)
            fail(HttpStatus.CONFLICT, "Withdrawn intelligence cannot be manually included");
        Long current = jdbc.queryForObject("""
                select coalesce(max(revision),0) from intelligence_catalog_overrides
                where tenant_id=:tenant and vulnerability_id=:id
                """, Map.of("tenant", tenant, "id", vulnerabilityId), Long.class);
        if (!change.expectedRevision().equals(current)) fail(HttpStatus.CONFLICT, "Override changed; reload history before saving");
        if (current == 0 && change.operation() == Operation.RESTORE) fail(HttpStatus.CONFLICT, "No override exists to restore");
        long next = current + 1;
        var params = new MapSqlParameterSource("tenant", tenant).addValue("id", vulnerabilityId).addValue("revision", next)
                .addValue("operation", change.operation().name()).addValue("reason", change.reason().strip())
                .addValue("expires", change.expiresAt() == null ? null : Timestamp.from(change.expiresAt()));
        Instant created = jdbc.queryForObject("""
                insert into intelligence_catalog_overrides(tenant_id,vulnerability_id,revision,operation,reason,expires_at)
                values(:tenant,:id,:revision,:operation,:reason,:expires) returning created_at
                """, params, Timestamp.class).toInstant();
        audit.record("tenant.intelligence_catalog_override.changed", "vulnerability", vulnerabilityId.toString(),
                "{\"revision\":" + next + ",\"operation\":\"" + change.operation().name() + "\"}");
        return new Entry(vulnerabilityId, next, change.operation(), change.reason().strip(), change.expiresAt(), created);
    }

    private UUID requireTenant() {
        UUID tenant = TenantContext.getCurrentTenantId();
        if (tenant == null || TenantContext.isPlatformContext()) fail(HttpStatus.FORBIDDEN, "An active tenant context is required");
        if (!tenant.equals(workspace.getWorkspace().getId())) fail(HttpStatus.FORBIDDEN, "Tenant context mismatch");
        return tenant;
    }
    private static void fail(HttpStatus status, String message) { throw new ResponseStatusException(status, message); }
}
