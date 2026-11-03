package com.prototype.vulnwatch.service.cbom;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Tenant-local rule-package availability and selection history. Callers must already be inside
 * the tenant's schema context and transaction; table names resolve through the tenant search path.
 */
@Component
public class CbomRuleLifecycleStore {

    public record Availability(String packageId, String version, String digest, int evaluatorMajor,
            String rolloutStage, String status, Instant discoveredAt) { }

    public record HistoryEntry(UUID id, String packageId, String action, String fromVersion, String toVersion,
            String versionPolicy, String actor, String reason, String impactJson, Instant createdAt) { }

    private final JdbcTemplate jdbc;

    public CbomRuleLifecycleStore(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    /** Idempotent: records first discovery time once and keeps stage/status current. */
    public void recordAvailability(UUID tenantId, CbomRulePackageRegistry.RulePackage pkg, String status) {
        jdbc.update("""
                INSERT INTO cbom_rule_availability
                    (tenant_id, package_id, package_version, package_digest, evaluator_major, rollout_stage, status)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (tenant_id, package_id, package_version) DO UPDATE SET
                    rollout_stage = EXCLUDED.rollout_stage, status = EXCLUDED.status, updated_at = now()
                WHERE cbom_rule_availability.rollout_stage <> EXCLUDED.rollout_stage
                   OR cbom_rule_availability.status <> EXCLUDED.status
                """, tenantId, pkg.packageId(), pkg.version(), pkg.digest(), pkg.evaluatorMajor(), pkg.stage().name(), status);
    }

    public void recordHistory(UUID tenantId, String packageId, String action, String fromVersion, String toVersion,
            String versionPolicy, String actor, String reason, String parametersJson, String impactJson) {
        jdbc.update("""
                INSERT INTO cbom_rule_selection_history
                    (id, tenant_id, package_id, action, from_version, to_version, version_policy, actor, reason, parameters_json, impact_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, cast(? as jsonb), cast(? as jsonb))
                """, UUID.randomUUID(), tenantId, packageId, action, fromVersion, toVersion, versionPolicy, actor, reason,
                parametersJson == null ? "{}" : parametersJson, impactJson);
    }

    public boolean hasHistory(UUID tenantId, String action, String toVersion) {
        Integer count = jdbc.queryForObject("""
                SELECT count(*) FROM cbom_rule_selection_history
                 WHERE tenant_id = ? AND action = ? AND to_version IS NOT DISTINCT FROM ?
                """, Integer.class, tenantId, action, toVersion);
        return count != null && count > 0;
    }

    public List<Availability> availability(UUID tenantId) {
        return jdbc.query("""
                SELECT package_id, package_version, package_digest, evaluator_major, rollout_stage, status, discovered_at
                  FROM cbom_rule_availability WHERE tenant_id = ? ORDER BY package_id, discovered_at
                """, (rs, row) -> new Availability(rs.getString(1), rs.getString(2), rs.getString(3), rs.getInt(4),
                        rs.getString(5), rs.getString(6), rs.getTimestamp(7).toInstant()), tenantId);
    }

    public List<HistoryEntry> history(UUID tenantId, int limit) {
        return jdbc.query("""
                SELECT id, package_id, action, from_version, to_version, version_policy, actor, reason,
                       impact_json::text, created_at
                  FROM cbom_rule_selection_history WHERE tenant_id = ? ORDER BY created_at DESC, id LIMIT ?
                """, (rs, row) -> new HistoryEntry(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                        rs.getString(4), rs.getString(5), rs.getString(6), rs.getString(7), rs.getString(8),
                        rs.getString(9), rs.getTimestamp(10).toInstant()), tenantId, Math.max(1, Math.min(200, limit)));
    }
}
