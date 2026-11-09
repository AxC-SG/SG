package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingsFilter;
import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class FindingProjectionQueryService {

    private static final Instant MAX_DUE_AT = Instant.parse("9999-12-31T00:00:00Z");

    private final NamedParameterJdbcTemplate jdbcTemplate;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final FindingProjectionStatusService findingProjectionStatusService;
    private final FindingProjectionRefreshService findingProjectionRefreshService;
    private final TransactionTemplate readTransactionTemplate;
    private com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter ownershipReads;

    public FindingProjectionQueryService(
            NamedParameterJdbcTemplate jdbcTemplate,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            FindingProjectionStatusService findingProjectionStatusService,
            FindingProjectionRefreshService findingProjectionRefreshService,
            PlatformTransactionManager transactionManager
    ) {
        this.jdbcTemplate = jdbcTemplate;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.findingProjectionStatusService = findingProjectionStatusService;
        this.findingProjectionRefreshService = findingProjectionRefreshService;
        this.readTransactionTemplate = new TransactionTemplate(transactionManager);
        this.readTransactionTemplate.setReadOnly(true);
        this.readTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    /** Optional: canonical owner-team/status filtering (ownership plan §9.7); absent in narrow unit tests. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setOwnershipReads(com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter ownershipReads) {
        this.ownershipReads = ownershipReads;
    }

    public void ensureTenantProjection(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return;
        }
        FindingListProjectionService.ProjectionStatus status = findingProjectionStatusService.inspectProjectionStatus(tenant);
        if (status.missing() || status.stale() || status.driftCount() != 0) {
            findingProjectionRefreshService.refreshTenant(tenant);
        }
    }

    public FindingListProjectionService.ProjectionPage queryPage(Tenant tenant, FindingsFilter filter, String cursor, int limit) {
        ensureTenantProjection(tenant);
        int safeLimit = Math.max(1, Math.min(200, limit));
        String projectionTable = qualifiedTenantTable(tenant, "finding_list_projection");
        return tenantSchemaExecutionService.run(tenant, () -> {
            FindingListProjectionService.ProjectionPage page = readTransactionTemplate.execute(transactionStatus -> {
                SqlFilter sqlFilter = buildSqlFilter(filter);
                CursorState cursorState = decodeCursor(cursor);
                MapSqlParameterSource params = sqlFilter.params()
                        .addValue("maxDueAt", Timestamp.from(MAX_DUE_AT));
                if (cursorState != null) {
                    params.addValue("cursorRiskScore", cursorState.riskScore())
                            .addValue("cursorDueAt", Timestamp.from(cursorState.dueAt()))
                            .addValue("cursorUpdatedAt", Timestamp.from(cursorState.updatedAt()))
                            .addValue("cursorFindingId", cursorState.findingId());
                }
                long totalItems = jdbcTemplate.queryForObject(
                        "SELECT COUNT(*) FROM " + projectionTable + " WHERE 1=1 " + sqlFilter.whereClause(),
                        params,
                        Long.class
                );
                String cursorClause = cursorState == null
                        ? ""
                        : """
                            AND (
                                risk_score < :cursorRiskScore
                                OR (risk_score = :cursorRiskScore AND coalesce(due_at, :maxDueAt) > :cursorDueAt)
                                OR (risk_score = :cursorRiskScore AND coalesce(due_at, :maxDueAt) = :cursorDueAt AND updated_at < :cursorUpdatedAt)
                                OR (risk_score = :cursorRiskScore AND coalesce(due_at, :maxDueAt) = :cursorDueAt AND updated_at = :cursorUpdatedAt AND finding_id > :cursorFindingId)
                            )
                            """;
                params.addValue("limit", safeLimit + 1);
                List<PageRow> rows = jdbcTemplate.query("""
                        SELECT finding_id, risk_score, due_at, updated_at
                        FROM %s
                        WHERE 1=1
                        """.formatted(projectionTable) + sqlFilter.whereClause() + cursorClause + """
                        
                        ORDER BY risk_score DESC, coalesce(due_at, :maxDueAt) ASC, updated_at DESC, finding_id ASC
                        LIMIT :limit
                        """,
                        params,
                        (rs, rowNum) -> mapPageRow(rs)
                );
                boolean hasMore = rows.size() > safeLimit;
                List<PageRow> pageRows = hasMore ? rows.subList(0, safeLimit) : rows;
                String nextCursor = hasMore && !pageRows.isEmpty()
                        ? encodeCursor(pageRows.get(pageRows.size() - 1))
                        : null;
                return new FindingListProjectionService.ProjectionPage(
                        pageRows.stream().map(PageRow::findingId).toList(),
                        totalItems,
                        nextCursor
                );
            });
            return page == null
                    ? new FindingListProjectionService.ProjectionPage(List.of(), 0L, null)
                    : page;
        });
    }

    public List<FindingListProjectionService.ProjectionRecord> loadRows(Tenant tenant, FindingsFilter filter) {
        ensureTenantProjection(tenant);
        String projectionTable = qualifiedTenantTable(tenant, "finding_list_projection");
        return tenantSchemaExecutionService.run(tenant, () -> {
            List<FindingListProjectionService.ProjectionRecord> rows = readTransactionTemplate.execute(transactionStatus -> {
                SqlFilter sqlFilter = buildSqlFilter(filter);
                return jdbcTemplate.query("""
                        SELECT finding_id, severity, status, decision_state, creation_source, match_method,
                               vex_status, vex_freshness, vex_provider, confidence_score, vulnerability_id,
                               package_name, ecosystem, owner_group, assigned_to, incident_id, due_at,
                               asset_name, support_group, patch_available, suppressed_until, risk_score,
                               updated_at, created_at, first_observed_at
                        FROM %s
                        WHERE 1=1
                        """.formatted(projectionTable) + sqlFilter.whereClause(),
                        sqlFilter.params(),
                        (rs, rowNum) -> mapProjectionRecord(rs)
                );
            });
            return rows == null ? List.of() : rows;
        });
    }

    public List<com.prototype.vulnwatch.dto.FindingCountBucketResponse> groupCounts(Tenant tenant, FindingsFilter filter, String field) {
        ensureTenantProjection(tenant);
        String expression = groupExpression(field);
        String table = qualifiedTenantTable(tenant, "finding_list_projection");
        return tenantSchemaExecutionService.run(tenant, () -> {
            SqlFilter sql = buildSqlFilter(filter);
            return jdbcTemplate.query("SELECT " + expression + " AS group_value, COUNT(*) AS group_count FROM "
                    + table + " WHERE 1=1 " + sql.whereClause() + " GROUP BY 1 ORDER BY 2 DESC, 1 ASC",
                    sql.params(), (rs, row) -> new com.prototype.vulnwatch.dto.FindingCountBucketResponse(
                            rs.getString("group_value"), rs.getLong("group_count")));
        });
    }

    private String groupExpression(String field) {
        // Only fixed expressions enter SQL; the selected value is always bound.
        return switch (field) {
            case "severity" -> "coalesce(nullif(severity, ''), 'UNKNOWN')";
            case "status" -> "status";
            case "assetName" -> "coalesce(nullif(asset_name, ''), 'Unknown')";
            case "packageName" -> "coalesce(nullif(package_name, ''), 'Unknown')";
            case "vulnerabilityId" -> "coalesce(nullif(vulnerability_id, ''), 'Unknown')";
            case "owner" -> "coalesce((select coalesce(nullif(trim(a.owner_team), ''), nullif(trim(a.owner_email), '')) "
                    + "from findings f left join inventory_components ic on ic.id = f.component_id "
                    + "left join assets a on a.id = coalesce(f.asset_id, ic.asset_id) "
                    + "where f.id = finding_list_projection.finding_id), 'Unassigned')";
            default -> throw new IllegalArgumentException("Unsupported finding group: " + field);
        };
    }

    private String qualifiedTenantTable(Tenant tenant, String tableName) {
        String schema = tenant == null ? null : tenant.getSchemaName();
        if (schema == null || !schema.matches("[a-z][a-z0-9_]*")) {
            throw new IllegalArgumentException("Invalid tenant schema name");
        }
        return '"' + schema + '"' + "." + '"' + tableName + '"';
    }

    private SqlFilter buildSqlFilter(FindingsFilter filter) {
        MapSqlParameterSource params = new MapSqlParameterSource();
        StringBuilder where = new StringBuilder(" AND (finding_kind IS NULL OR finding_kind <> 'AI_RUNTIME') ");
        appendOwnershipFilter(where, params, filter);
        appendInClause(where, params, "severity", "severity", upperValues(filter.severity()));
        appendInClause(where, params, "status", "status", upperValues(filter.status()));
        appendInClause(where, params, "decisionState", "decision_state", upperValues(filter.decisionState()));
        appendInClause(where, params, "creationSource", "creation_source", upperValues(filter.creationSource()));
        appendInClause(where, params, "matchMethod", "match_method", lowerValues(filter.matchMethod()));
        // Must mirror the JPA specification path exactly: the two paths serve the same filter
        // (cursor paging uses this one, offset paging the other) and disagreeing on kind would
        // change the result set depending on how the client pages.
        appendInClause(where, params, "findingKind", "finding_kind", upperValues(filter.findingKind()));
        // Existence-style, not a join: a finding can be reached by more than one declared AI
        // resource, and a join to ai_bom_resource_vulnerability_links would multiply rows here
        // (COUNT(*) and LIMIT-based paging both need exactly one row per finding). Must mirror
        // FindingFilterSpecifications.byAffectedAiResourceId/byHasAffectedAiResource exactly --
        // same reason findingKind above does.
        appendAffectedAiResourceFilter(where, params, filter);
        appendNullableUpperMatch(where, params, "vexStatus", "vex_status", filter.vexStatus());
        appendNullableUpperMatch(where, params, "vexFreshness", "vex_freshness", filter.vexFreshness());
        appendNullableLowerMatch(where, params, "vexProvider", "vex_provider", filter.vexProvider());
        if (filter.minConfidence() != null) {
            where.append(" AND confidence_score >= :minConfidence");
            params.addValue("minConfidence", filter.minConfidence());
        }
        appendEqualsIgnoreCase(where, params, "vulnerabilityId", "vulnerability_id", filter.vulnerabilityId(), true);
        appendEqualsIgnoreCase(where, params, "packageName", "package_name", filter.packageName(), false);
        appendEqualsIgnoreCase(where, params, "ecosystem", "ecosystem", filter.ecosystem(), false);
        appendLikeIgnoreCase(where, params, "ownerGroup", "owner_group", filter.ownerGroup());
        appendLikeIgnoreCase(where, params, "assignedTo", "assigned_to", filter.assignedTo());
        if (filter.unassignedOnly() != null) {
            where.append(Boolean.TRUE.equals(filter.unassignedOnly())
                    ? " AND (assigned_to IS NULL OR trim(assigned_to) = '')"
                    : " AND (assigned_to IS NOT NULL AND trim(assigned_to) <> '')");
        }
        if (filter.incidentLinked() != null) {
            where.append(Boolean.TRUE.equals(filter.incidentLinked())
                    ? " AND (incident_id IS NOT NULL AND trim(incident_id) <> '')"
                    : " AND (incident_id IS NULL OR trim(incident_id) = '')");
        }
        appendDueDateBand(where, params, filter.dueDateBand());
        appendLikeIgnoreCase(where, params, "assetName", "asset_name", filter.assetName());
        appendLikeIgnoreCase(where, params, "supportGroup", "support_group", filter.supportGroup());
        if (filter.patchAvailable() != null) {
            where.append(" AND patch_available = :patchAvailable");
            params.addValue("patchAvailable", filter.patchAvailable());
        }
        appendSuppressedUntilBand(where, params, filter.suppressedUntilBand());
        if (FindingFilterSpecifications.hasText(filter.groupField()) && filter.groupValue() != null) {
            where.append(" AND ").append(groupExpression(filter.groupField())).append(" = :groupValue");
            params.addValue("groupValue", filter.groupValue());
        }
        if (filter.assetType() != null && !filter.assetType().isEmpty()) {
            where.append(" AND finding_id IN (SELECT f.id FROM findings f LEFT JOIN inventory_components ic ON ic.id = f.component_id LEFT JOIN assets a ON a.id = coalesce(f.asset_id, ic.asset_id) WHERE cast(a.type as text) IN (:assetTypes))");
            params.addValue("assetTypes", upperValues(filter.assetType()));
        }
        return new SqlFilter(where.toString(), params);
    }

    private void appendAffectedAiResourceFilter(StringBuilder where, MapSqlParameterSource params, FindingsFilter filter) {
        List<String> rawIds = filter.affectedAiResourceId();
        if (rawIds != null && !rawIds.isEmpty()) {
            List<UUID> ids = FindingFilterSpecifications.normalizeFilterValues(rawIds).stream()
                    .map(value -> {
                        try {
                            return UUID.fromString(value.trim());
                        } catch (IllegalArgumentException ex) {
                            return null;
                        }
                    })
                    .filter(java.util.Objects::nonNull)
                    .toList();
            if (!ids.isEmpty()) {
                where.append(" AND finding_id IN (SELECT link.finding_id FROM ai_bom_resource_vulnerability_links link"
                        + " WHERE link.status = 'ACTIVE' AND link.declared_resource_id IN (:affectedAiResourceIds))");
                params.addValue("affectedAiResourceIds", ids);
            }
        }
        if (filter.hasAffectedAiResource() != null) {
            where.append(Boolean.TRUE.equals(filter.hasAffectedAiResource())
                    ? " AND finding_id IN (SELECT link.finding_id FROM ai_bom_resource_vulnerability_links link WHERE link.status = 'ACTIVE')"
                    : " AND finding_id NOT IN (SELECT link.finding_id FROM ai_bom_resource_vulnerability_links link WHERE link.status = 'ACTIVE')");
        }
    }

    private void appendDueDateBand(StringBuilder where, MapSqlParameterSource params, String dueDateBand) {
        if (!FindingFilterSpecifications.hasText(dueDateBand)) {
            return;
        }
        String normalized = dueDateBand.trim().toLowerCase(Locale.ROOT);
        Instant now = Instant.now();
        Instant soon = now.plus(7, ChronoUnit.DAYS);
        params.addValue("dueNow", Timestamp.from(now));
        params.addValue("dueSoon", Timestamp.from(soon));
        switch (normalized) {
            case "overdue" -> where.append(" AND status = 'OPEN' AND due_at IS NOT NULL AND due_at < :dueNow");
            case "due-soon" -> where.append(" AND status = 'OPEN' AND due_at IS NOT NULL AND due_at >= :dueNow AND due_at < :dueSoon");
            case "on-track" -> where.append(" AND status = 'OPEN' AND due_at IS NOT NULL AND due_at >= :dueSoon");
            case "no-sla" -> where.append(" AND status = 'OPEN' AND due_at IS NULL");
            default -> { }
        }
    }

    private void appendSuppressedUntilBand(StringBuilder where, MapSqlParameterSource params, String band) {
        if (!FindingFilterSpecifications.hasText(band)) {
            return;
        }
        String normalized = band.trim().toLowerCase(Locale.ROOT);
        Instant now = Instant.now();
        Instant soon = now.plus(7, ChronoUnit.DAYS);
        params.addValue("suppressedNow", Timestamp.from(now));
        params.addValue("suppressedSoon", Timestamp.from(soon));
        switch (normalized) {
            case "expiring-soon" -> where.append(
                    " AND status = 'SUPPRESSED' AND suppressed_until IS NOT NULL AND suppressed_until >= :suppressedNow AND suppressed_until < :suppressedSoon"
            );
            case "expired" -> where.append(
                    " AND status = 'SUPPRESSED' AND suppressed_until IS NOT NULL AND suppressed_until < :suppressedNow"
            );
            default -> { }
        }
    }

    private void appendInClause(StringBuilder where, MapSqlParameterSource params, String paramKey, String column, List<String> values) {
        if (values.isEmpty()) {
            return;
        }
        where.append(" AND ").append(column).append(" IN (:").append(paramKey).append(")");
        params.addValue(paramKey, values);
    }

    private void appendNullableUpperMatch(StringBuilder where, MapSqlParameterSource params, String paramKey, String column, List<String> rawValues) {
        List<String> values = upperValues(rawValues);
        if (values.isEmpty()) {
            return;
        }
        boolean includesUnknown = values.contains("UNKNOWN");
        List<String> concrete = values.stream().filter(value -> !"UNKNOWN".equals(value)).toList();
        if (includesUnknown && concrete.isEmpty()) {
            where.append(" AND ").append(column).append(" IS NULL");
            return;
        }
        if (includesUnknown) {
            where.append(" AND (").append(column).append(" IS NULL OR ").append(column).append(" IN (:").append(paramKey).append("))");
        } else {
            where.append(" AND ").append(column).append(" IN (:").append(paramKey).append(")");
        }
        params.addValue(paramKey, concrete);
    }

    private void appendNullableLowerMatch(StringBuilder where, MapSqlParameterSource params, String paramKey, String column, List<String> rawValues) {
        List<String> values = lowerValues(rawValues);
        if (values.isEmpty()) {
            return;
        }
        boolean includesUnknown = values.contains("unknown");
        List<String> concrete = values.stream().filter(value -> !"unknown".equals(value)).toList();
        if (includesUnknown && concrete.isEmpty()) {
            where.append(" AND ").append(column).append(" IS NULL");
            return;
        }
        if (includesUnknown) {
            where.append(" AND (").append(column).append(" IS NULL OR lower(").append(column).append(") IN (:").append(paramKey).append("))");
        } else {
            where.append(" AND lower(").append(column).append(") IN (:").append(paramKey).append(")");
        }
        params.addValue(paramKey, concrete);
    }

    private void appendEqualsIgnoreCase(StringBuilder where, MapSqlParameterSource params, String paramKey, String column, String value, boolean upper) {
        if (!FindingFilterSpecifications.hasText(value)) {
            return;
        }
        where.append(" AND ");
        if (upper) {
            where.append("upper(").append(column).append(")");
        } else {
            where.append("lower(").append(column).append(")");
        }
        where.append(" = :").append(paramKey);
        params.addValue(paramKey, upper ? value.trim().toUpperCase(Locale.ROOT) : value.trim().toLowerCase(Locale.ROOT));
    }

    /** Owner team / ownership status by stable ID, resolved through the canonical model (never the free-text owner_group). */
    private void appendOwnershipFilter(StringBuilder where, MapSqlParameterSource params, FindingsFilter filter) {
        if (!filter.hasOwnershipFilter()) return;
        if (ownershipReads == null) {
            throw new org.springframework.web.server.ResponseStatusException(org.springframework.http.HttpStatus.CONFLICT,
                    "Ownership filters are not available");
        }
        String status = FindingFilterSpecifications.hasText(filter.ownershipStatus())
                ? filter.ownershipStatus().trim().toUpperCase(Locale.ROOT) : null;
        where.append(" AND finding_id IN (").append(ownershipReads.findingFilterSubquery(status)).append(") ");
        params.addValue("ownershipTeamId", filter.ownerTeamId()).addValue("ownershipStatus", status);
    }

    private void appendLikeIgnoreCase(StringBuilder where, MapSqlParameterSource params, String paramKey, String column, String value) {
        if (!FindingFilterSpecifications.hasText(value)) {
            return;
        }
        where.append(" AND lower(").append(column).append(") LIKE :").append(paramKey);
        params.addValue(paramKey, "%" + value.trim().toLowerCase(Locale.ROOT) + "%");
    }

    private List<String> upperValues(List<String> rawValues) {
        return FindingFilterSpecifications.normalizeUpperFilterValues(rawValues).stream().toList();
    }

    private List<String> lowerValues(List<String> rawValues) {
        return FindingFilterSpecifications.normalizeLowerFilterValues(rawValues).stream().toList();
    }

    private PageRow mapPageRow(ResultSet rs) throws java.sql.SQLException {
        return new PageRow(
                UUID.fromString(rs.getString("finding_id")),
                rs.getDouble("risk_score"),
                rs.getTimestamp("due_at") == null ? MAX_DUE_AT : rs.getTimestamp("due_at").toInstant(),
                rs.getTimestamp("updated_at").toInstant()
        );
    }

    private FindingListProjectionService.ProjectionRecord mapProjectionRecord(ResultSet rs) throws java.sql.SQLException {
        return new FindingListProjectionService.ProjectionRecord(
                UUID.fromString(rs.getString("finding_id")),
                rs.getString("severity"),
                rs.getString("status"),
                rs.getString("decision_state"),
                rs.getString("creation_source"),
                rs.getString("match_method"),
                rs.getString("vex_status"),
                rs.getString("vex_freshness"),
                rs.getString("vex_provider"),
                rs.getDouble("confidence_score"),
                rs.getString("vulnerability_id"),
                rs.getString("package_name"),
                rs.getString("ecosystem"),
                rs.getString("owner_group"),
                rs.getString("assigned_to"),
                rs.getString("incident_id"),
                rs.getTimestamp("due_at") == null ? null : rs.getTimestamp("due_at").toInstant(),
                rs.getString("asset_name"),
                rs.getString("support_group"),
                rs.getBoolean("patch_available"),
                rs.getTimestamp("suppressed_until") == null ? null : rs.getTimestamp("suppressed_until").toInstant(),
                rs.getDouble("risk_score"),
                rs.getTimestamp("updated_at").toInstant(),
                rs.getTimestamp("created_at").toInstant(),
                rs.getTimestamp("first_observed_at") == null ? null : rs.getTimestamp("first_observed_at").toInstant()
        );
    }

    private String encodeCursor(PageRow row) {
        String payload = row.riskScore() + "|" + row.dueAt().toEpochMilli() + "|" + row.updatedAt().toEpochMilli() + "|" + row.findingId();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
    }

    private CursorState decodeCursor(String cursor) {
        if (!FindingFilterSpecifications.hasText(cursor)) {
            return null;
        }
        String decoded = new String(Base64.getUrlDecoder().decode(cursor), StandardCharsets.UTF_8);
        String[] parts = decoded.split("\\|", 4);
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid findings cursor");
        }
        return new CursorState(
                Double.parseDouble(parts[0]),
                Instant.ofEpochMilli(Long.parseLong(parts[1])),
                Instant.ofEpochMilli(Long.parseLong(parts[2])),
                UUID.fromString(parts[3])
        );
    }

    private record SqlFilter(String whereClause, MapSqlParameterSource params) {
    }

    private record PageRow(UUID findingId, double riskScore, Instant dueAt, Instant updatedAt) {
    }

    private record CursorState(double riskScore, Instant dueAt, Instant updatedAt, UUID findingId) {
    }
}
