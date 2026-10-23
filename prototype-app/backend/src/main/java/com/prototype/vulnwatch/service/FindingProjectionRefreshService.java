package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.sql.Timestamp;
import java.time.Instant;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class FindingProjectionRefreshService {

    private static final String STATUS_KEY = "finding-workspace";

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final FindingRepository findingRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final OperationalMetricsService operationalMetricsService;
    private final TransactionTemplate writeTransactionTemplate;

    public FindingProjectionRefreshService(
            NamedParameterJdbcTemplate jdbcTemplate,
            FindingRepository findingRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            OperationalMetricsService operationalMetricsService,
            PlatformTransactionManager transactionManager
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.findingRepository = findingRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.operationalMetricsService = operationalMetricsService;
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public int refreshTenant(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return 0;
        }
        return tenantSchemaExecutionService.run(tenant, () -> {
            Integer refreshed = writeTransactionTemplate.execute(status -> refreshTenantInCurrentTenantSchema(tenant));
            return refreshed == null ? 0 : refreshed;
        });
    }

    /** Workflow publication joins its source transaction; after-commit callers keep refreshTenant. */
    public int refreshTenantWithSource(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) return 0;
        return tenantSchemaExecutionService.run(tenant, () -> {
            TransactionTemplate joined = new TransactionTemplate(writeTransactionTemplate.getTransactionManager());
            Integer refreshed = joined.execute(status -> refreshTenantInCurrentTenantSchema(tenant));
            return refreshed == null ? 0 : refreshed;
        });
    }

    long countProjectedRows(Tenant tenant) {
        Long count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM " + qualifiedTenantTable(tenant, "finding_list_projection"),
                new MapSqlParameterSource(),
                Long.class
        );
        return count == null ? 0L : count;
    }

    long countSourceFindings() {
        return findingRepository.count();
    }

    private int refreshTenantInCurrentTenantSchema(Tenant tenant) {
        // JDBC must see this transaction's pending JPA workflow changes.
        findingRepository.flush();
        String projectionTable = qualifiedTenantTable(tenant, "finding_list_projection");
        String statusTable = qualifiedTenantTable(tenant, "finding_workspace_projection_status");
        long startedAtNs = System.nanoTime();
        int statusCode = 200;
        try {
            jdbcTemplate.getJdbcTemplate().execute("LOCK TABLE " + projectionTable + " IN EXCLUSIVE MODE");
            jdbcTemplate.update("DELETE FROM " + projectionTable, new MapSqlParameterSource());
            jdbcTemplate.update("""
                    INSERT INTO %s (
                        finding_id,
                        tenant_id,
                        display_id,
                        severity,
                        status,
                        decision_state,
                        creation_source,
                        match_method,
                        vex_status,
                        vex_freshness,
                        vex_provider,
                        confidence_score,
                        finding_kind,
                        vulnerability_id,
                        package_name,
                        ecosystem,
                        owner_group,
                        assigned_to,
                        incident_id,
                        due_at,
                        asset_name,
                        support_group,
                        patch_available,
                        suppressed_until,
                        risk_score,
                        updated_at,
                        created_at,
                        first_observed_at
                    )
                    SELECT
                        finding.id,
                        finding.tenant_id,
                        finding.display_id,
                        upper(coalesce(finding.severity_override, finding.intelligence_severity, vulnerability.severity,
                            case when finding.risk_score >= 9 then 'CRITICAL'
                                 when finding.risk_score >= 7 then 'HIGH'
                                 when finding.risk_score >= 4 then 'MEDIUM' else 'LOW' end)),
                        cast(finding.status as varchar),
                        cast(finding.decision_state as varchar),
                        cast(finding.creation_source as varchar),
                        lower(finding.matched_by),
                        finding.vex_status,
                        finding.vex_freshness,
                        finding.vex_provider,
                        finding.confidence_score,
                        finding.finding_kind,
                        coalesce(vulnerability.external_id, finding.policy_id),
                        coalesce(component.package_name, ai_artifact.name),
                        coalesce(component.ecosystem, case when finding.finding_kind <> 'VULNERABILITY' then 'AI' end),
                        finding.owner_group,
                        finding.assigned_to,
                        finding.incident_id,
                        finding.due_at,
                        coalesce(asset.name, ai_artifact.name),
                        asset.support_group,
                        patchable_cves.external_id_upper IS NOT NULL,
                        finding.suppressed_until,
                        finding.risk_score,
                        finding.updated_at,
                        finding.created_at,
                        finding.first_observed_at
                    FROM findings finding
                    LEFT JOIN vulnerabilities vulnerability ON vulnerability.id = finding.vulnerability_id
                    LEFT JOIN inventory_components component ON component.id = finding.component_id
                    LEFT JOIN assets asset ON asset.id = finding.asset_id
                    LEFT JOIN LATERAL (
                        SELECT subject_id FROM finding_subjects subject
                         WHERE subject.finding_id=finding.id AND subject.subject_type='ARTIFACT'
                           AND subject.subject_role IN ('PRIMARY','ROOT_CAUSE')
                         ORDER BY CASE subject.subject_role WHEN 'ROOT_CAUSE' THEN 0 ELSE 1 END,subject.subject_id
                         LIMIT 1
                    ) ai_subject ON true
                    LEFT JOIN ai_security_artifacts ai_artifact ON ai_artifact.id = ai_subject.subject_id
                    LEFT JOIN (
                        SELECT DISTINCT upper(fix_record.cve_id) AS external_id_upper
                        FROM fix_records fix_record
                        WHERE upper(fix_record.fix_type) <> 'NO_FIX'
                    ) patchable_cves
                      ON patchable_cves.external_id_upper = upper(vulnerability.external_id)
                    """.formatted(projectionTable),
                    new MapSqlParameterSource());
            long findingCount = countProjectedRows(tenant);
            long sourceFindingCount = countSourceFindings();
            long rebuildDurationMs = (System.nanoTime() - startedAtNs) / 1_000_000L;
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("projectionKey", STATUS_KEY)
                    .addValue("lastComputedAt", Timestamp.from(Instant.now()))
                    .addValue("findingCount", findingCount)
                    .addValue("sourceFindingCount", sourceFindingCount)
                    .addValue("lastRebuildDurationMs", rebuildDurationMs);
            jdbcTemplate.update("""
                    INSERT INTO %s (
                        projection_key,
                        tenant_id,
                        last_computed_at,
                        finding_count,
                        source_finding_count,
                        last_rebuild_duration_ms
                    )
                    VALUES (
                        :projectionKey,
                        :tenantId,
                        :lastComputedAt,
                        :findingCount,
                        :sourceFindingCount,
                        :lastRebuildDurationMs
                    )
                    ON CONFLICT (projection_key) DO UPDATE SET
                        tenant_id = EXCLUDED.tenant_id,
                        last_computed_at = EXCLUDED.last_computed_at,
                        finding_count = EXCLUDED.finding_count,
                        source_finding_count = EXCLUDED.source_finding_count,
                        last_rebuild_duration_ms = EXCLUDED.last_rebuild_duration_ms
                    """.formatted(statusTable), params.addValue("tenantId", TenantContext.getCurrentTenantId()));
            return Math.toIntExact(findingCount);
        } catch (RuntimeException ex) {
            statusCode = 500;
            throw ex;
        } finally {
            operationalMetricsService.record(
                    OperationalMetricsService.KEY_FINDINGS_PROJECTION_REFRESH,
                    (System.nanoTime() - startedAtNs) / 1_000_000L,
                    statusCode
            );
        }
    }

    private String qualifiedTenantTable(Tenant tenant, String tableName) {
        String schema = tenant == null ? null : tenant.getSchemaName();
        if (schema == null || !schema.matches("[a-z][a-z0-9_]*")) {
            throw new IllegalArgumentException("Invalid tenant schema name");
        }
        return '"' + schema + '"' + "." + '"' + tableName + '"';
    }
}
