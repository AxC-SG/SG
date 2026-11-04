package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.service.TenantContext;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Durable rollout lease in {@code platform.cbom_rule_rollout_leases}. Every statement is a single
 * atomic row operation guarded by owner, so two instances can never both advance the same
 * package's cursor. A lease left by a dead owner becomes acquirable once it expires, and the new
 * owner resumes from the last committed cursor; per-tenant processing is idempotent, so a replayed
 * tenant is safe.
 */
@Component
public class CbomRuleRolloutLeaseStore {

    public record Lease(String packageKey, String stage, UUID cursorTenantId, String completedStage) { }

    private final JdbcTemplate jdbc;

    public CbomRuleRolloutLeaseStore(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    /**
     * Acquires or renews the lease. When the release-configured stage differs from the recorded
     * one, the cursor restarts so tenants that just became eligible are visited.
     */
    public Optional<Lease> acquire(String packageKey, String owner, String stage, long ttlSeconds) {
        return TenantContext.runAsPlatform(() -> {
            List<Lease> acquired = jdbc.query("""
                    INSERT INTO platform.cbom_rule_rollout_leases
                        (package_key, owner, lease_expires_at, heartbeat_at, stage, updated_at)
                    VALUES (?, ?, now() + (? * interval '1 second'), now(), ?, now())
                    ON CONFLICT (package_key) DO UPDATE SET
                        owner = EXCLUDED.owner,
                        lease_expires_at = EXCLUDED.lease_expires_at,
                        heartbeat_at = now(),
                        updated_at = now()
                    WHERE platform.cbom_rule_rollout_leases.owner IS NULL
                       OR platform.cbom_rule_rollout_leases.owner = EXCLUDED.owner
                       OR platform.cbom_rule_rollout_leases.lease_expires_at < now()
                    RETURNING package_key, stage, cursor_tenant_id, completed_stage
                    """, (rs, row) -> new Lease(rs.getString(1), rs.getString(2),
                            rs.getObject(3, UUID.class), rs.getString(4)),
                    packageKey, owner, ttlSeconds, stage);
            if (acquired.isEmpty()) return Optional.<Lease>empty();
            Lease lease = acquired.get(0);
            if (!stage.equals(lease.stage())) {
                jdbc.update("""
                        UPDATE platform.cbom_rule_rollout_leases
                           SET stage = ?, cursor_tenant_id = NULL, completed_stage = NULL, updated_at = now()
                         WHERE package_key = ? AND owner = ?
                        """, stage, packageKey, owner);
                lease = new Lease(packageKey, stage, null, null);
            }
            return Optional.of(lease);
        });
    }

    /** Commits progress after one tenant and heartbeats. False means the lease was lost: stop. */
    public boolean commitCursor(String packageKey, String owner, UUID tenantId, int jobsEnqueued, long ttlSeconds) {
        return TenantContext.runAsPlatform(() -> jdbc.update("""
                UPDATE platform.cbom_rule_rollout_leases
                   SET cursor_tenant_id = ?, tenants_processed = tenants_processed + 1,
                       jobs_enqueued = jobs_enqueued + ?, heartbeat_at = now(),
                       lease_expires_at = now() + (? * interval '1 second'), updated_at = now()
                 WHERE package_key = ? AND owner = ? AND lease_expires_at >= now()
                """, tenantId, jobsEnqueued, ttlSeconds, packageKey, owner) == 1);
    }

    /** Records a full pass for the current stage; the next stage change restarts the cursor. */
    public boolean completePass(String packageKey, String owner) {
        return TenantContext.runAsPlatform(() -> jdbc.update("""
                UPDATE platform.cbom_rule_rollout_leases
                   SET completed_stage = stage, cursor_tenant_id = NULL, updated_at = now()
                 WHERE package_key = ? AND owner = ?
                """, packageKey, owner) == 1);
    }

    public void release(String packageKey, String owner) {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                UPDATE platform.cbom_rule_rollout_leases
                   SET owner = NULL, lease_expires_at = NULL, updated_at = now()
                 WHERE package_key = ? AND owner = ?
                """, packageKey, owner));
    }

    public record LeaseStatus(String packageKey, String owner, java.time.Instant leaseExpiresAt, java.time.Instant heartbeatAt,
            String stage, UUID cursorTenantId, String completedStage, long tenantsProcessed, long jobsEnqueued) { }

    public List<LeaseStatus> list() {
        return TenantContext.runAsPlatform(() -> jdbc.query("""
                SELECT package_key, owner, lease_expires_at, heartbeat_at, stage, cursor_tenant_id,
                       completed_stage, tenants_processed, jobs_enqueued
                  FROM platform.cbom_rule_rollout_leases ORDER BY package_key
                """, (rs, row) -> new LeaseStatus(rs.getString(1), rs.getString(2),
                        rs.getTimestamp(3) == null ? null : rs.getTimestamp(3).toInstant(),
                        rs.getTimestamp(4) == null ? null : rs.getTimestamp(4).toInstant(),
                        rs.getString(5), rs.getObject(6, UUID.class), rs.getString(7), rs.getLong(8), rs.getLong(9))));
    }
}
