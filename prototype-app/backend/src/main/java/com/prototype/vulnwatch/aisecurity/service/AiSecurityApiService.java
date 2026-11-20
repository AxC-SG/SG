package com.prototype.vulnwatch.aisecurity.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ReviewDisposition;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyDefinition.PolicyDefinition;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyDefinition.PolicyParameterSpec;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ArtifactScopeFacts;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ScopeCondition;
import com.prototype.vulnwatch.aisecurity.policy.AiSecurityPolicyScopeMatcher.ScopeConfig;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AiSecurityApiService {

    private static final Logger LOG = LoggerFactory.getLogger(AiSecurityApiService.class);
    /** One deterministic matching subject context per canonical finding, shared by list and count. */
    private static final String FINDING_CONTEXT = """
              join lateral (
                  select subject.subject_type,subject.subject_id,
                         artifact.id artifact_id,path.id exposure_path_id
                    from finding_subjects subject
                    left join ai_grid_exposure_paths path on subject.subject_type='EXPOSURE_PATH' and path.id=subject.subject_id
                    left join ai_grid_exposure_associations association on association.exposure_path_id=path.id and association.artifact_id is not null
                    left join ai_security_artifacts artifact on artifact.id=case
                        when subject.subject_type='ARTIFACT' then subject.subject_id else coalesce(association.artifact_id,path.root_cause_artifact_id) end
                   where subject.finding_id=f.id and subject.subject_role='PRIMARY'
                     and subject.subject_type in ('ARTIFACT','EXPOSURE_PATH')
                     and (:provider is null or artifact.provider=:provider)
                     and (:subscription is null or artifact.account_id=:subscription)
                     and (:nativeKind is null or artifact.native_kind=any(string_to_array(:nativeKind,',')))
                   order by case when path.status='OPEN' and path.state='VALIDATED_EXPOSURE' then 0
                                 when path.status='OPEN' then 1 else 2 end,
                            path.last_observed_at desc nulls last,subject.subject_id,
                            case association.association_role when 'ROOT_CAUSE' then 0 when 'ENTRY_POINT' then 1 else 2 end,artifact.id
                   limit 1
              ) fs on true
              left join ai_security_artifacts a on a.id=fs.artifact_id
            """;
    private static final String FINDING_PATHS = """
              left join lateral (
                  select coalesce(jsonb_agg(jsonb_build_object('id',p.id,'title',p.title,'state',p.state,'status',p.status)
                       order by case when p.status='OPEN' and p.state='VALIDATED_EXPOSURE' then 0 else 1 end,
                                p.last_observed_at desc,p.id),'[]'::jsonb)::text path_summaries
                    from ai_grid_exposure_paths p where p.finding_id=f.id
              ) paths on true
            """;
    private static final String ARTIFACT_SELECT_FIELDS = """
            id, provider, provider_resource_id, artifact_type, native_kind, name,
            account_id, region, active, attributes_json::text, owner_name, owner_state,
            owner_source, owner_confidence, owner_confidence_method,
            owner_confidence_method_version, business_criticality, environment,
            first_observed_at, last_observed_at, pii_scan_status, pii_source,
            pii_info_types::text, pii_finding_count, pii_last_scanned_at,
            array(select distinct s.id
                    from ai_grid_systems s
                    join ai_grid_system_revisions revision
                      on revision.system_id=s.id and revision.revision=s.current_revision
                    join ai_grid_system_memberships membership
                      on membership.system_revision_id=revision.id
                   where s.status='ACTIVE' and membership.valid_until is null
                     and membership.artifact_id=ai_security_artifacts.id
                   order by s.id) system_ids
            """;

    private final NamedParameterJdbcTemplate jdbc;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantExecution;
    private final TransactionTemplate transactionTemplate;
    private final AiGridReevaluationService reevaluationService;
    private final AiGridApiService aiGridApi;
    private final AiGridFindingService canonicalFindings;
    private final AiSecuritySyncRunFacade syncRunFacade;
    private final AuditEventService auditEventService;
    private final AiSecurityMetadataSanitizer metadataSanitizer;
    private final AiGridTenantPolicyDefaultsService policyDefaults;
    private final AiAgentExecutionRelationshipProjectionService runtimeRelationships;

    public AiSecurityApiService(
            NamedParameterJdbcTemplate jdbc,
            ObjectMapper objectMapper,
            TenantSchemaExecutionService tenantExecution,
            TransactionTemplate transactionTemplate,
            AiGridReevaluationService reevaluationService,
            AiGridApiService aiGridApi,
            AiGridFindingService canonicalFindings,
            AiSecuritySyncRunFacade syncRunFacade,
            AuditEventService auditEventService,
            AiSecurityMetadataSanitizer metadataSanitizer,
            AiGridTenantPolicyDefaultsService policyDefaults,
            AiAgentExecutionRelationshipProjectionService runtimeRelationships
    ) {
        this.jdbc = jdbc;
        this.objectMapper = objectMapper;
        this.tenantExecution = tenantExecution;
        this.transactionTemplate = transactionTemplate;
        this.reevaluationService = reevaluationService;
        this.aiGridApi = aiGridApi;
        this.canonicalFindings = canonicalFindings;
        this.syncRunFacade = syncRunFacade;
        this.auditEventService = auditEventService;
        this.metadataSanitizer = metadataSanitizer;
        this.policyDefaults = policyDefaults;
        this.runtimeRelationships = runtimeRelationships;
    }

    private AiAgentDeploymentService deploymentService;

    @org.springframework.beans.factory.annotation.Autowired
    public void setDeploymentService(AiAgentDeploymentService service) { this.deploymentService = service; }

    public SummaryResponse summary(Tenant tenant) {
        return tenantExecution.run(tenant, () -> {
            Map<String, Long> counts = jdbc.query("""
                    select artifact_type, count(*) as total
                      from ai_security_artifacts
                     where active = true
                     group by artifact_type
                    """, rs -> {
                Map<String, Long> result = new LinkedHashMap<>();
                while (rs.next()) {
                    result.put(rs.getString("artifact_type"), rs.getLong("total"));
                }
                return result;
            });
            Map<String, Long> nativeKindCounts = jdbc.query("""
                    select native_kind, count(*) as total
                      from ai_security_artifacts
                     where active = true
                     group by native_kind
                     order by total desc
                    """, rs -> {
                Map<String, Long> result = new LinkedHashMap<>();
                while (rs.next()) {
                    result.put(rs.getString("native_kind"), rs.getLong("total"));
                }
                return result;
            });
            Map<String, Long> providerCounts = jdbc.query("""
                    select provider, count(*) as total
                      from ai_security_artifacts
                     where active = true
                     group by provider
                     order by total desc
                    """, rs -> {
                Map<String, Long> result = new LinkedHashMap<>();
                while (rs.next()) {
                    result.put(rs.getString("provider"), rs.getLong("total"));
                }
                return result;
            });
            long openFindings = count("""
                    select count(*) from findings
                     where finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                       and status = 'OPEN'
                    """, Map.of());
            long incomplete = count("""
                    select count(*) from ai_security_snapshot_scopes
                     where status in ('PARTIAL','ERROR','UNSUPPORTED_API')
                    """, Map.of());
            Instant lastCompleted = jdbc.query("""
                    select max(completed_at) from ai_security_snapshot_scopes where status = 'COMPLETE'
                    """, rs -> rs.next() && rs.getTimestamp(1) != null ? rs.getTimestamp(1).toInstant() : null);
            return new SummaryResponse(counts, nativeKindCounts, providerCounts, openFindings, incomplete, lastCompleted,
                    count("select count(*) from ai_security_artifacts a where a.active = true and "
                            + AiAgentInventoryClassification.agentSql("a"), Map.of()));
        });
    }

    /** Distinct AI artifacts with an open finding, bucketed by native artifact kind x severity —
     * a cell is "how many artifacts have a critical/high/medium/low finding", not a finding
     * count, so one artifact with three high findings still counts once. Seeded with every
     * native kind currently in inventory so a kind with zero findings still renders as a full
     * row — mirrors {@code DashboardService.getGridExposure}'s "seed every value" approach. */
    public SeverityGridResponse severityGrid(Tenant tenant) {
        return tenantExecution.run(tenant, () -> {
            Map<String, long[]> countsByNativeKind = new LinkedHashMap<>();
            for (String nativeKind : jdbc.queryForList("""
                    select distinct native_kind from ai_security_artifacts where active = true
                    """, Map.of(), String.class)) {
                countsByNativeKind.put(nativeKind, new long[4]);
            }
            jdbc.query("""
                    select a.native_kind,
                           coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                               when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) severity,
                           count(distinct fs.subject_id) as total
                      from findings f
                      join finding_subjects fs on fs.finding_id = f.id and fs.subject_type = 'ARTIFACT' and fs.subject_role in ('PRIMARY','ROOT_CAUSE')
                      join ai_security_artifacts a on a.id = fs.subject_id
                     where f.status = 'OPEN' and f.finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                     group by a.native_kind, severity
                    """, rs -> {
                while (rs.next()) {
                    long[] counts = countsByNativeKind.computeIfAbsent(rs.getString("native_kind"), ignored -> new long[4]);
                    int index = severityGridIndex(rs.getString("severity"));
                    if (index >= 0) {
                        counts[index] += rs.getLong("total");
                    }
                }
                return null;
            });
            Map<String, Long> distinctArtifactTotals = new LinkedHashMap<>();
            jdbc.query("""
                    select a.native_kind, count(distinct fs.subject_id) as total
                      from findings f
                      join finding_subjects fs on fs.finding_id = f.id and fs.subject_type = 'ARTIFACT' and fs.subject_role in ('PRIMARY','ROOT_CAUSE')
                      join ai_security_artifacts a on a.id = fs.subject_id
                     where f.status = 'OPEN' and f.finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                     group by a.native_kind
                    """, rs -> {
                while (rs.next()) {
                    distinctArtifactTotals.put(rs.getString("native_kind"), rs.getLong("total"));
                }
                return null;
            });
            List<SeverityGridRow> rows = new ArrayList<>();
            for (Map.Entry<String, long[]> entry : countsByNativeKind.entrySet()) {
                long[] counts = entry.getValue();
                long total = distinctArtifactTotals.getOrDefault(entry.getKey(), 0L);
                rows.add(new SeverityGridRow(entry.getKey(), counts[0], counts[1], counts[2], counts[3], total));
            }
            return new SeverityGridResponse(rows);
        });
    }

    private static int severityGridIndex(String severity) {
        return switch (severity == null ? "" : severity.toUpperCase(Locale.ROOT)) {
            case "CRITICAL" -> 0;
            case "HIGH" -> 1;
            case "MEDIUM" -> 2;
            case "LOW" -> 3;
            default -> -1;
        };
    }

    /** Ranks AI artifacts by a weighted score over their open findings' severities
     * (critical=4, high=3, medium=2, low=1) — the "Top N assets at risk" signal. Unlike the
     * exposure-correlation engine's validated paths (a narrower, rarer signal), this only
     * needs an open finding to surface, so it stays populated even before any exposure path
     * has been validated. */
    public List<TopRiskArtifact> topRiskArtifacts(Tenant tenant, int limit) {
        int safeLimit = Math.max(1, Math.min(50, limit));
        return tenantExecution.run(tenant, () -> jdbc.query("""
                with open_findings as (
                    select fs.subject_id as artifact_id,
                           coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                               when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) as severity
                      from findings f
                      join finding_subjects fs on fs.finding_id = f.id
                       and fs.subject_type = 'ARTIFACT' and fs.subject_role in ('PRIMARY','ROOT_CAUSE')
                     where f.status = 'OPEN' and f.finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                )
                select a.id, a.name, a.native_kind, a.provider, a.account_id,
                       count(*) filter (where o.severity = 'CRITICAL') as critical_count,
                       count(*) filter (where o.severity = 'HIGH') as high_count,
                       count(*) filter (where o.severity = 'MEDIUM') as medium_count,
                       count(*) filter (where o.severity = 'LOW') as low_count
                  from open_findings o
                  join ai_security_artifacts a on a.id = o.artifact_id
                 group by a.id, a.name, a.native_kind, a.provider, a.account_id
                 order by (count(*) filter (where o.severity = 'CRITICAL') * 4
                         + count(*) filter (where o.severity = 'HIGH') * 3
                         + count(*) filter (where o.severity = 'MEDIUM') * 2
                         + count(*) filter (where o.severity = 'LOW')) desc,
                       a.name
                 limit :limit
                """, Map.of("limit", safeLimit), (rs, n) -> {
            long critical = rs.getLong("critical_count");
            long high = rs.getLong("high_count");
            long medium = rs.getLong("medium_count");
            long low = rs.getLong("low_count");
            long score = critical * 4 + high * 3 + medium * 2 + low;
            return new TopRiskArtifact(rs.getObject("id", UUID.class), rs.getString("name"),
                    rs.getString("native_kind"), rs.getString("provider"), rs.getString("account_id"),
                    critical, high, medium, low, score);
        }));
    }

    public PageResponse<ArtifactResponse> artifacts(Tenant tenant, String artifactType, int page, int size) {
        validateArtifactTypeFilter(artifactType);
        return artifacts(tenant, artifactType, null, null, null, null, page, size);
    }

    public PageResponse<ArtifactResponse> knowledgeData(
            Tenant tenant, String provider, String kind, String sourceType, String sensitivity,
            String publicContentAccess, Boolean active, int page, int size) {
        return inventory(tenant, List.of("KNOWLEDGE_BASE", "DATA_SOURCE", "DATA_STORE", "SEARCH_INDEX"), provider,
                kind, sourceType, sensitivity, publicContentAccess, null, null, null, active, page, size);
    }

    public PageResponse<ArtifactResponse> mcp(
            Tenant tenant, String provider, String role, String authenticationType, String endpointExposure,
            String synchronizationStatus, Boolean active, int page, int size) {
        return inventory(tenant, List.of("MCP_GATEWAY", "MCP_TARGET", "MCP_SERVER"), provider,
                role, null, null, null, authenticationType, endpointExposure, synchronizationStatus, active, page, size);
    }

    private PageResponse<ArtifactResponse> inventory(
            Tenant tenant, List<String> types, String provider, String kind, String sourceType, String sensitivity,
            String publicContentAccess, String authenticationType, String endpointExposure, String synchronizationStatus,
            Boolean active, int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(100, size));
        return tenantExecution.run(tenant, () -> {
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("types", types.toArray(String[]::new))
                    .addValue("provider", normalizedProvider(provider), Types.VARCHAR)
                    .addValue("kind", blankToNull(kind), Types.VARCHAR)
                    .addValue("sourceType", filterValue("sourceType", sourceType), Types.VARCHAR)
                    .addValue("sensitivity", filterValue("sensitivity", sensitivity), Types.VARCHAR)
                    .addValue("publicContentAccess", filterValue("publicContentAccess", publicContentAccess), Types.VARCHAR)
                    .addValue("authenticationType", filterValue("configuredAuthType", authenticationType), Types.VARCHAR)
                    .addValue("endpointExposure", filterValue("endpointExposure", endpointExposure), Types.VARCHAR)
                    .addValue("synchronizationStatus", filterValue("status", synchronizationStatus), Types.VARCHAR)
                    .addValue("active", active, Types.BOOLEAN)
                    .addValue("limit", safeSize, Types.INTEGER).addValue("offset", safePage * safeSize, Types.INTEGER);
            String where = """
                    where artifact_type = any(:types)
                      and (:provider is null or provider = :provider)
                      and (:kind is null or artifact_type = :kind)
                      and (:sourceType is null or attributes_json ->> 'sourceType' = :sourceType)
                      and (:sensitivity is null or pii_scan_status = :sensitivity)
                      and (:publicContentAccess is null or attributes_json ->> 'publicContentAccess' = :publicContentAccess)
                      and (:authenticationType is null or coalesce(attributes_json ->> 'configuredAuthType',
                              attributes_json ->> 'inboundAuthType', attributes_json ->> 'outboundAuthType') = :authenticationType)
                      and (:endpointExposure is null or attributes_json ->> 'endpointExposure' = :endpointExposure)
                      and (:synchronizationStatus is null or attributes_json ->> 'status' = :synchronizationStatus)
                      and (:active is null or active = :active)
                    """;
            List<ArtifactResponse> items = jdbc.query("select " + ARTIFACT_SELECT_FIELDS + " from ai_security_artifacts " + where
                    + " order by active desc, last_observed_at desc, id limit :limit offset :offset", params, this::artifact);
            return new PageResponse<>(items, safePage, safeSize, count("select count(*) from ai_security_artifacts " + where, params));
        });
    }

    public PageResponse<ArtifactResponse> artifacts(
            Tenant tenant,
            String artifactType,
            String nativeKind,
            String provider,
            String subscription,
            String severity,
            int page,
            int size
    ) {
        validateArtifactTypeFilter(artifactType);
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(100, size));
        return tenantExecution.run(tenant, () -> {
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("artifactType", blankToNull(artifactType), Types.VARCHAR)
                    .addValue("otherArtifacts", "OTHER_AI_ARTIFACT".equalsIgnoreCase(artifactType), Types.BOOLEAN)
                    .addValue("nativeKind", blankToNull(nativeKind), Types.VARCHAR)
                    .addValue("provider", normalizedProvider(provider), Types.VARCHAR)
                    .addValue("subscription", blankToNull(subscription), Types.VARCHAR)
                    .addValue("severity", blankToNull(severity), Types.VARCHAR)
                    .addValue("limit", safeSize, Types.INTEGER)
                    .addValue("offset", safePage * safeSize, Types.INTEGER);
            String severityFilter = """
                       and (:severity is null or exists (
                           select 1 from findings f
                             join finding_subjects fs on fs.finding_id = f.id
                              and fs.subject_type = 'ARTIFACT' and fs.subject_role in ('PRIMARY','ROOT_CAUSE')
                            where fs.subject_id = ai_security_artifacts.id
                              and f.status = 'OPEN' and f.finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                              and coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                                  when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) = :severity
                       ))
                    """;
            List<ArtifactResponse> items = jdbc.query("select " + ARTIFACT_SELECT_FIELDS + """
                      from ai_security_artifacts
                     where (:artifactType is null
                        or (:otherArtifacts = true and artifact_type = 'OTHER_AI_ARTIFACT')
                        or (:otherArtifacts = false and artifact_type = :artifactType))
                       and (:nativeKind is null or native_kind = any(string_to_array(:nativeKind, ',')))
                       and (:provider is null or provider = :provider)
                       and (:subscription is null or account_id = :subscription)
                    """ + severityFilter + """
                     order by active desc, last_observed_at desc, id
                     limit :limit offset :offset
                    """, params, this::artifact);
            long total = count("""
                    select count(*) from ai_security_artifacts
                     where (:artifactType is null
                        or (:otherArtifacts = true and artifact_type = 'OTHER_AI_ARTIFACT')
                        or (:otherArtifacts = false and artifact_type = :artifactType))
                       and (:nativeKind is null or native_kind = any(string_to_array(:nativeKind, ',')))
                       and (:provider is null or provider = :provider)
                       and (:subscription is null or account_id = :subscription)
                    """ + severityFilter, params);
            return new PageResponse<>(items, safePage, safeSize, total);
        });
    }

    /** A leaner, list-view-shaped sibling of {@link #artifacts}: per-artifact open-finding
     * severity counts and policy pass/fail counts via LATERAL joins, computed only for the
     * current page of rows. Kept as its own endpoint/type rather than growing
     * {@link ArtifactResponse} — that type is also used by the graph/detail/candidate-picker
     * call sites, which don't need (and shouldn't pay the query cost for) these counts. */
    public PageResponse<ArtifactSummaryResponse> artifactSummaries(
            Tenant tenant,
            String artifactType,
            String nativeKind,
            String provider,
            String subscription,
            String severity,
            String excludeNativeKinds,
            String excludeArtifactTypes,
            int page,
            int size
    ) {
        return artifactSummaries(tenant, artifactType, nativeKind, provider, subscription, severity,
                excludeNativeKinds, excludeArtifactTypes, null, null, page, size);
    }

    public PageResponse<ArtifactSummaryResponse> artifactSummaries(
            Tenant tenant,
            String artifactType,
            String nativeKind,
            String provider,
            String subscription,
            String severity,
            String excludeNativeKinds,
            String excludeArtifactTypes,
            String inventoryView,
            String search,
            int page,
            int size
    ) {
        validateArtifactTypeFilter(artifactType);
        if (inventoryView != null && !Set.of("AGENTS", "OTHERS").contains(inventoryView)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown AI inventory view");
        }
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(100, size));
        return tenantExecution.run(tenant, () -> {
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("search", blankToNull(search), Types.VARCHAR)
                    .addValue("artifactType", blankToNull(artifactType), Types.VARCHAR)
                    .addValue("otherArtifacts", "OTHER_AI_ARTIFACT".equalsIgnoreCase(artifactType), Types.BOOLEAN)
                    .addValue("nativeKind", blankToNull(nativeKind), Types.VARCHAR)
                    .addValue("provider", normalizedProvider(provider), Types.VARCHAR)
                    .addValue("subscription", blankToNull(subscription), Types.VARCHAR)
                    .addValue("severity", blankToNull(severity), Types.VARCHAR)
                    .addValue("excludeNativeKinds", blankToNull(excludeNativeKinds), Types.VARCHAR)
                    .addValue("excludeArtifactTypes", blankToNull(excludeArtifactTypes), Types.VARCHAR)
                    .addValue("limit", safeSize, Types.INTEGER)
                    .addValue("offset", safePage * safeSize, Types.INTEGER);
            String severityFilter = """
                       and (:severity is null or exists (
                           select 1 from findings f
                             join finding_subjects fs on fs.finding_id = f.id
                              and fs.subject_type = 'ARTIFACT' and fs.subject_role in ('PRIMARY','ROOT_CAUSE')
                            where fs.subject_id = a.id
                              and f.status = 'OPEN' and f.finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                              and coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                                  when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) = :severity
                       ))
                    """;
            String baseFilter = """
                     where (:artifactType is null
                        or (:otherArtifacts = true and a.artifact_type = 'OTHER_AI_ARTIFACT')
                        or (:otherArtifacts = false and a.artifact_type = :artifactType))
                       and (:nativeKind is null or a.native_kind = any(string_to_array(:nativeKind, ',')))
                       and (:excludeNativeKinds is null or not (a.native_kind = any(string_to_array(:excludeNativeKinds, ','))))
                       and (:excludeArtifactTypes is null or not (a.artifact_type = any(string_to_array(:excludeArtifactTypes, ','))))
                       and (:provider is null or a.provider = :provider)
                       and (:subscription is null or a.account_id = :subscription)
                    """ + severityFilter
                    + ("AGENTS".equals(inventoryView) ? " and a.active = true and " + AiAgentInventoryClassification.agentSql("a") : "")
                    + ("OTHERS".equals(inventoryView) ? " and not " + AiAgentInventoryClassification.versionSql("a")
                            + " and not " + AiAgentInventoryClassification.agentSql("a") : "")
                    + " and (:search is null or position(lower(:search) in lower(a.name)) > 0)"
                    + (artifactType == null && nativeKind == null ? " and not " + AiAgentInventoryClassification.versionSql("a") : "");
            List<ArtifactSummaryResponse> items = jdbc.query("with roster_page as (select a.* from ai_security_artifacts a "
                    + baseFilter + " order by a.active desc, a.last_observed_at desc, a.id limit :limit offset :offset) " + """
                    select a.id, a.name, a.native_kind, a.provider, a.account_id, a.region,
                           coalesce(cf.total, 0) as critical_findings,
                           coalesce(hf.total, 0) as high_findings,
                           coalesce(tf.total, 0) as total_findings,
                           coalesce(pt.total, 0) as policies_total,
                           coalesce(pf.total, 0) as policies_failed
                      from roster_page a
                      left join lateral (
                          select count(*) as total from findings f
                            join finding_subjects fs on fs.finding_id = f.id
                             and fs.subject_type = 'ARTIFACT' and fs.subject_role in ('PRIMARY','ROOT_CAUSE')
                           where fs.subject_id = a.id and f.status = 'OPEN' and f.finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                             and coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                                 when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) = 'CRITICAL'
                      ) cf on true
                      left join lateral (
                          select count(*) as total from findings f
                            join finding_subjects fs on fs.finding_id = f.id
                             and fs.subject_type = 'ARTIFACT' and fs.subject_role in ('PRIMARY','ROOT_CAUSE')
                           where fs.subject_id = a.id and f.status = 'OPEN' and f.finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                             and coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                                 when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) = 'HIGH'
                      ) hf on true
                      left join lateral (
                          select count(*) as total from findings f
                            join finding_subjects fs on fs.finding_id = f.id
                             and fs.subject_type = 'ARTIFACT' and fs.subject_role in ('PRIMARY','ROOT_CAUSE')
                           where fs.subject_id = a.id and f.status = 'OPEN' and f.finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                      ) tf on true
                      left join lateral (
                          select count(*) as total from ai_grid_current_expected_candidates c where c.artifact_id = a.id
                      ) pt on true
                      left join lateral (
                          select count(*) as total from ai_grid_current_expected_candidates c
                           where c.artifact_id = a.id and c.decision = 'FAIL'
                      ) pf on true
                     order by a.active desc, a.last_observed_at desc, a.id
                    """, params, this::artifactSummary);
            long total = count("""
                    select count(*) from ai_security_artifacts a
                    """ + baseFilter, params);
            if (deploymentService != null) {
                Map<UUID, AiAgentDeploymentService.Metadata> metadata = deploymentService.resolve(items.stream()
                        .map(a -> new AiAgentDeploymentService.Agent(a.id(), a.nativeKind())).toList(), Instant.now());
                items = items.stream().map(a -> a.withDeployment(metadata.get(a.id()))).toList();
            }
            return new PageResponse<>(items, safePage, safeSize, total);
        });
    }

    private ArtifactSummaryResponse artifactSummary(ResultSet rs, int rowNum) throws SQLException {
        return new ArtifactSummaryResponse(
                rs.getObject("id", UUID.class),
                rs.getString("name"),
                rs.getString("native_kind"),
                rs.getString("provider"),
                rs.getString("account_id"),
                rs.getString("region"),
                rs.getLong("critical_findings"),
                rs.getLong("high_findings"),
                rs.getLong("total_findings"),
                rs.getLong("policies_failed"),
                rs.getLong("policies_total"), null
        );
    }

    public ArtifactResponse artifact(Tenant tenant, UUID artifactId) {
        return tenantExecution.run(tenant, () -> {
            List<ArtifactResponse> rows = jdbc.query("select " + ARTIFACT_SELECT_FIELDS
                    + " from ai_security_artifacts where id = :id", Map.of("id", artifactId), this::artifact);
            if (rows.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security artifact not found");
            }
            ArtifactResponse row = rows.get(0);
            return deploymentService == null ? row : row.withDeployment(deploymentService.resolve(
                    List.of(new AiAgentDeploymentService.Agent(row.id(), row.nativeKind())), Instant.now()).get(row.id()));
        });
    }

    public record AgentVersionResponse(UUID id, String name, String nativeKind, boolean definitionVersion,
                                       boolean servedVersion, Instant lastObservedAt) { }

    public PageResponse<AgentVersionResponse> agentVersions(Tenant tenant, UUID agentId, int page, int size) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(100, size));
        return tenantExecution.run(tenant, () -> {
            ArtifactResponse agent = artifact(tenant, agentId);
            MapSqlParameterSource params = new MapSqlParameterSource().addValue("agentId", agentId)
                    .addValue("limit", safeSize).addValue("offset", safePage * safeSize)
                    .addValue("runId", agent.deployment() == null || agent.deployment().status() != AiAgentDeploymentService.Status.SERVED
                            || agent.deployment().evidenceReferences().isEmpty() ? null
                            : agent.deployment().evidenceReferences().get(0).runId(), Types.OTHER);
            String filter = """
                    from ai_security_artifacts v
                    where exists (select 1 from ai_security_relationships r
                        where r.source_artifact_id = v.id and r.target_artifact_id = :agentId
                          and r.relationship_type = 'VERSION_OF')
                    """;
            List<AgentVersionResponse> versions = jdbc.query("""
                    select v.id, v.name, v.native_kind, v.last_observed_at,
                        exists (select 1 from ai_security_relationships d where d.source_artifact_id=:agentId
                            and d.target_artifact_id=v.id and d.relationship_type='ACTIVE_VERSION' and d.active)
                        or (v.active and v.native_kind='AWS_BEDROCK_AGENT_VERSION' and v.attributes_json->>'version'='DRAFT')
                        or (v.active and v.native_kind='AWS_AGENTCORE_RUNTIME_VERSION' and v.attributes_json->>'version'=
                            (select attributes_json->>'version' from ai_security_artifacts where id=:agentId)) definition_version,
                        exists (select 1 from ai_grid_relationship_snapshots r
                            join ai_grid_relationship_snapshots parent on parent.run_id=r.run_id
                                and parent.target_artifact_id=r.source_artifact_id
                                and parent.source_artifact_id=:agentId
                                and parent.relationship_type in ('HAS_COMPONENT','HAS_DEPLOYMENT','HAS_ENDPOINT')
                            join ai_grid_snapshot_manifests m on m.artifact_id=r.source_artifact_id and m.run_id=r.run_id
                            join ai_grid_snapshot_bodies b on b.id=m.body_id
                            where r.run_id=:runId and r.target_artifact_id=v.id and r.relationship_type='SERVES_VERSION'
                                and b.content_json->'attributes'->>'status' in ('PREPARED','READY')
                                and coalesce(b.content_json->'attributes'->>'aliasId','') <> 'TSTALIASID'
                                and (b.content_json->>'nativeKind' <> 'AWS_BEDROCK_AGENT_ALIAS'
                                    or b.content_json->'attributes'->>'invocationState'='ACCEPT_INVOCATIONS')) served_version
                    """ + filter + " order by v.last_observed_at desc, v.id limit :limit offset :offset", params,
                    (rs, n) -> new AgentVersionResponse(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3),
                            rs.getBoolean("definition_version"), rs.getBoolean("served_version"), rs.getTimestamp(4).toInstant()));
            return new PageResponse<>(versions, safePage, safeSize, count("select count(*) " + filter, params));
        });
    }

    public record DeploymentSettings(int freshnessHours) { }
    public DeploymentSettings deploymentSettings(Tenant tenant) {
        return tenantExecution.run(tenant, () -> new DeploymentSettings(jdbc.queryForObject(
                "select coalesce(max(freshness_hours), 24) from ai_agent_deployment_settings", Map.of(), Integer.class)));
    }
    public DeploymentSettings updateDeploymentSettings(Tenant tenant, DeploymentSettings settings) {
        if (settings == null || settings.freshnessHours() < 1 || settings.freshnessHours() > 8760) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Freshness hours must be between 1 and 8760");
        }
        return tenantExecution.run(tenant, () -> {
            jdbc.update("""
                    insert into ai_agent_deployment_settings (tenant_id, freshness_hours) values (:tenantId,:hours)
                    on conflict (tenant_id) do update set freshness_hours=excluded.freshness_hours
                    """, Map.of("tenantId", tenant.getId(), "hours", settings.freshnessHours()));
            return settings;
        });
    }

    public List<ActivityEvidenceResponse> activityEvidence(Tenant tenant, UUID artifactId) {
        AiRuntimeScope.requireInScope();
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select fact_key,value_json::text,state,evidence_reference,observed_at,valid_from,valid_until,
                       confidence,producer_id,(valid_until is not null and valid_until <= now()) expired
                  from ai_grid_host_context_facts
                 where artifact_id=:artifactId and fact_key like 'activity.%'
                 order by observed_at desc,fact_key
                 limit 100
                """, Map.of("artifactId", artifactId), (rs, row) -> new ActivityEvidenceResponse(
                rs.getString(1), rs.getString(2), rs.getString(3), rs.getString(4),
                rs.getTimestamp(5).toInstant(), rs.getTimestamp(6).toInstant(),
                rs.getTimestamp(7) == null ? null : rs.getTimestamp(7).toInstant(),
                (Double) rs.getObject(8), rs.getString(9), rs.getBoolean(10))));
    }

    public String exportArtifacts(Tenant tenant) {
        return tenantExecution.run(tenant, () -> {
            StringBuilder csv = new StringBuilder("id,name,provider,artifactType,nativeKind,accountId,region,active,metadata\n");
            jdbc.query("""
                    select id,name,provider,artifact_type,native_kind,account_id,region,active,attributes_json::text
                      from ai_security_artifacts order by name,id limit 50000
                    """, rs -> {
                while (rs.next()) {
                    Map<String, Object> metadata = AiSecurityFieldContract.responseSafe(readMap(rs.getString("attributes_json")));
                    csv.append(csv(rs.getObject("id"))).append(',').append(csv(rs.getString("name"))).append(',')
                            .append(csv(rs.getString("provider"))).append(',').append(csv(rs.getString("artifact_type"))).append(',')
                            .append(csv(rs.getString("native_kind"))).append(',').append(csv(rs.getString("account_id"))).append(',')
                            .append(csv(rs.getString("region"))).append(',').append(csv(rs.getBoolean("active"))).append(',')
                            .append(csv(json(metadata))).append('\n');
                }
                return null;
            });
            return csv.toString();
        });
    }

    static String csv(Object value) {
        String text = value == null ? "" : value.toString();
        int firstMeaningful = 0;
        while (firstMeaningful < text.length()
                && isSpreadsheetIgnorablePrefix(text.charAt(firstMeaningful))) {
            firstMeaningful++;
        }
        boolean controlPrefix = !text.isEmpty() && (text.charAt(0) == '\t'
                || text.charAt(0) == '\r' || text.charAt(0) == '\n');
        boolean formulaPrefix = firstMeaningful < text.length()
                && "=+-@".indexOf(text.charAt(firstMeaningful)) >= 0;
        if (controlPrefix || formulaPrefix) {
            text = "'" + text;
        }
        return "\"" + text.replace("\"", "\"\"") + "\"";
    }

    private static boolean isSpreadsheetIgnorablePrefix(char value) {
        return Character.isWhitespace(value) || Character.isSpaceChar(value)
                || Character.isISOControl(value) || value == '\uFEFF' || value == '\u200B';
    }

    private String filterValue(String field, String value) {
        if (!AiSecurityFieldContract.allows(field, AiSecurityFieldContract.Tier.FILTER_ALLOWED)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Metadata field is not filterable");
        }
        return blankToNull(value);
    }

    public List<RelationshipResponse> relationships(Tenant tenant, UUID artifactId) {
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select r.id, r.relationship_type, r.source_artifact_id, source.name as source_name,
                       r.target_artifact_id, target.name as target_name, r.attributes_json::text
                  from ai_security_relationships r
                  join ai_security_artifacts source on source.id = r.source_artifact_id
                  join ai_security_artifacts target on target.id = r.target_artifact_id
                 where r.active = true
                   and (r.source_artifact_id = :id or r.target_artifact_id = :id)
                 order by r.relationship_type, r.id
                 limit 1000
                """, Map.of("id", artifactId), (rs, rowNum) -> new RelationshipResponse(
                rs.getObject("id", UUID.class),
                rs.getString("relationship_type"),
                rs.getObject("source_artifact_id", UUID.class),
                rs.getString("source_name"),
                rs.getObject("target_artifact_id", UUID.class),
                rs.getString("target_name"),
                AiSecurityFieldContract.responseSafe(readMap(rs.getString("attributes_json"))))));
    }

    /** Bounded above the exposure-correlation engine's HARD_MAX_DEPTH (6) — this is a live,
     * per-request read path (AiGridExposureService's bound is for an offline batch job). */
    private static final int MAX_GRAPH_DEPTH = 3;

    public GraphResponse graph(Tenant tenant, UUID rootArtifactId) {
        return graph(tenant, rootArtifactId, 1);
    }

    public GraphResponse graph(Tenant tenant, UUID rootArtifactId, int depth) {
        return graph(tenant, rootArtifactId, depth, false, null, null);
    }

    public GraphResponse graph(Tenant tenant, UUID rootArtifactId, int depth, boolean includeRuntime,
                               Instant runtimeFrom, Instant runtimeTo) {
        if (includeRuntime) AiRuntimeScope.requireInScope();
        RuntimeWindow runtimeWindow = null;
        int boundedDepth = Math.max(1, Math.min(depth, MAX_GRAPH_DEPTH));
        return tenantExecution.run(tenant, () -> {
            List<ArtifactResponse> nodes;
            List<RelationshipResponse> edges;
            if (rootArtifactId == null) {
                nodes = jdbc.query("select " + ARTIFACT_SELECT_FIELDS + """
                          from ai_security_artifacts where active = true
                         order by last_observed_at desc limit 500
                        """, this::artifact);
                edges = graphEdges(null, 1001);
            } else {
                artifact(tenant, rootArtifactId);
                edges = boundedGraphEdges(rootArtifactId, boundedDepth, 1001);
                java.util.LinkedHashSet<UUID> ids = new java.util.LinkedHashSet<>();
                ids.add(rootArtifactId);
                edges.forEach(edge -> {
                    ids.add(edge.sourceArtifactId());
                    ids.add(edge.targetArtifactId());
                });
                nodes = artifactsByIds(ids.stream().limit(500).toList());
            }
            AiAgentExecutionRelationshipProjectionService.RuntimeOverlay runtimeOverlay = null;
            if (runtimeWindow != null) {
                try {
                    runtimeOverlay = runtimeRelationships.aggregate(tenant.getId(), rootArtifactId,
                            runtimeWindow.from(), runtimeWindow.to());
                    Set<UUID> present = nodes.stream().map(ArtifactResponse::id)
                            .collect(java.util.stream.Collectors.toCollection(java.util.LinkedHashSet::new));
                    List<UUID> missing = AiAgentExecutionRelationshipProjectionService.referencedArtifactIds(runtimeOverlay)
                            .stream().filter(id -> !present.contains(id)).toList();
                    if (!missing.isEmpty()) {
                        List<ArtifactResponse> enriched = new ArrayList<>(nodes);
                        enriched.addAll(artifactsByIds(missing));
                        nodes = enriched;
                    }
                } catch (RuntimeException error) {
                    LOG.warn("AI runtime relationship overlay is unavailable: {}",
                            error.getClass().getSimpleName());
                    runtimeOverlay = AiAgentExecutionRelationshipProjectionService.unavailable(
                            runtimeWindow.from(), runtimeWindow.to());
                }
            }
            boolean truncated = nodes.size() >= 500 || edges.size() > 1000;
            List<GraphFindingSummary> findingSummaries = graphFindingSummaries(nodes.stream()
                    .map(ArtifactResponse::id).toList());
            return new GraphResponse(nodes.stream().limit(500).toList(), edges.stream().limit(1000).toList(),
                    truncated, runtimeOverlay, findingSummaries);
        });
    }

    /**
     * Graph highlighting must not depend on the paginated findings list.  The graph is scoped to
     * the current tenant and reports findings that are still actionable: OPEN findings plus
     * SUPPRESSED findings, which are the product's deferred/accepted-risk state. Resolved and
     * auto-closed findings deliberately do not make a dependency appear risky.
     */
    private List<GraphFindingSummary> graphFindingSummaries(List<UUID> artifactIds) {
        if (artifactIds.isEmpty()) return List.of();
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("ids", artifactIds)
                .addValue("provider", null, Types.VARCHAR)
                .addValue("subscription", null, Types.VARCHAR)
                .addValue("nativeKind", null, Types.VARCHAR);
        return jdbc.query("""
                select fs.artifact_id,
                       count(*) as total_findings,
                       count(*) filter (where f.status = 'OPEN') as open_findings,
                       count(*) filter (where f.status = 'SUPPRESSED') as deferred_findings,
                       count(*) filter (where coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                           when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) = 'CRITICAL') as critical_findings,
                       count(*) filter (where coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                           when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) = 'HIGH') as high_findings,
                       count(*) filter (where coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                           when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) = 'MEDIUM') as medium_findings,
                       count(*) filter (where coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                           when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) = 'LOW') as low_findings
                  from findings f
                  """ + FINDING_CONTEXT + """
                 where fs.artifact_id in (:ids)
                   and f.finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                   and f.status in ('OPEN', 'SUPPRESSED')
                 group by fs.artifact_id
                 order by fs.artifact_id
                """, params, (rs, rowNum) -> new GraphFindingSummary(
                rs.getObject("artifact_id", UUID.class),
                rs.getLong("total_findings"),
                rs.getLong("open_findings"),
                rs.getLong("deferred_findings"),
                rs.getLong("critical_findings"),
                rs.getLong("high_findings"),
                rs.getLong("medium_findings"),
                rs.getLong("low_findings")));
    }

    static RuntimeWindow runtimeWindow(UUID rootArtifactId, boolean includeRuntime,
                                       Instant runtimeFrom, Instant runtimeTo) {
        if (!includeRuntime) return null;
        if (rootArtifactId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Runtime graph requires rootArtifactId");
        }
        Instant now = Instant.now();
        Instant to = runtimeTo == null ? now : runtimeTo;
        Instant from = runtimeFrom == null ? to.minus(7, ChronoUnit.DAYS) : runtimeFrom;
        if (!from.isBefore(to)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "runtimeFrom must be before runtimeTo");
        }
        if (!from.isBefore(now)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Runtime graph window cannot be future-only");
        }
        if (Duration.between(from, to).compareTo(Duration.ofDays(90)) > 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Runtime graph window cannot exceed 90 days");
        }
        return new RuntimeWindow(from, to);
    }

    record RuntimeWindow(Instant from, Instant to) { }

    /** BFS over ai_security_relationships from root, up to `depth` hops. Runs inside the caller's
     * tenantExecution.run(...) lambda (see graph() above) — search_path is already pinned to the
     * caller's tenant schema, so this can never traverse into another tenant's rows regardless of
     * how many hops it takes. */
    private List<RelationshipResponse> boundedGraphEdges(UUID root, int depth, int limit) {
        Set<UUID> frontier = new java.util.LinkedHashSet<>(List.of(root));
        Set<UUID> visited = new java.util.LinkedHashSet<>(frontier);
        Map<UUID, RelationshipResponse> collected = new LinkedHashMap<>();
        for (int hop = 0; hop < depth && !frontier.isEmpty() && collected.size() < limit; hop++) {
            List<RelationshipResponse> hopEdges = jdbc.query("""
                    select r.id, r.relationship_type, r.source_artifact_id, source.name as source_name,
                           r.target_artifact_id, target.name as target_name, r.attributes_json::text
                      from ai_security_relationships r
                      join ai_security_artifacts source on source.id = r.source_artifact_id
                      join ai_security_artifacts target on target.id = r.target_artifact_id
                     where r.active = true
                       and (r.source_artifact_id in (:frontier) or r.target_artifact_id in (:frontier))
                     order by r.relationship_type, r.id
                     limit :limit
                    """, new MapSqlParameterSource()
                            .addValue("frontier", new ArrayList<>(frontier))
                            .addValue("limit", limit - collected.size()),
                    (rs, rowNum) -> new RelationshipResponse(
                            rs.getObject("id", UUID.class),
                            rs.getString("relationship_type"),
                            rs.getObject("source_artifact_id", UUID.class),
                            rs.getString("source_name"),
                            rs.getObject("target_artifact_id", UUID.class),
                            rs.getString("target_name"),
                            AiSecurityFieldContract.responseSafe(readMap(rs.getString("attributes_json")))));
            Set<UUID> nextFrontier = new java.util.LinkedHashSet<>();
            for (RelationshipResponse edge : hopEdges) {
                collected.putIfAbsent(edge.id(), edge);
                if (visited.add(edge.sourceArtifactId())) {
                    nextFrontier.add(edge.sourceArtifactId());
                }
                if (visited.add(edge.targetArtifactId())) {
                    nextFrontier.add(edge.targetArtifactId());
                }
            }
            frontier = nextFrontier;
        }
        return new ArrayList<>(collected.values());
    }

    private List<ArtifactResponse> artifactsByIds(List<UUID> ids) {
        if (ids.isEmpty()) {
            return List.of();
        }
        return jdbc.query("select " + ARTIFACT_SELECT_FIELDS
                + " from ai_security_artifacts where id in (:ids)", Map.of("ids", ids), this::artifact);
    }

    public PageResponse<FindingResponse> findings(Tenant tenant, String policyId, String status, int page, int size) {
        return findings(tenant, policyId, status, null, null, null, null, page, size);
    }

    public PageResponse<FindingResponse> findings(
            Tenant tenant,
            String policyId,
            String status,
            String provider,
            String subscription,
            String severity,
            String nativeKind,
            int page,
            int size
    ) {
        int safePage = Math.max(0, page);
        int safeSize = Math.max(1, Math.min(100, size));
        return tenantExecution.run(tenant, () -> {
            MapSqlParameterSource params = new MapSqlParameterSource()
                    .addValue("policyId", blankToNull(policyId), Types.VARCHAR)
                    .addValue("status", blankToNull(status), Types.VARCHAR)
                    .addValue("provider", normalizedProvider(provider), Types.VARCHAR)
                    .addValue("subscription", blankToNull(subscription), Types.VARCHAR)
                    .addValue("severity", blankToNull(severity), Types.VARCHAR)
                    .addValue("nativeKind", blankToNull(nativeKind), Types.VARCHAR)
                    .addValue("limit", safeSize, Types.INTEGER)
                    .addValue("offset", safePage * safeSize, Types.INTEGER);
            String filter = """
                     where (:policyId is null or f.policy_id = :policyId)
                       and (:status is null or f.status = :status)
                       and (:provider is null or a.provider = :provider)
                       and (:subscription is null or a.account_id = :subscription)
                       and (:nativeKind is null or a.native_kind = any(string_to_array(:nativeKind, ',')))
                       and (:severity is null or coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                           when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) = :severity)
                    """;
            List<FindingResponse> items = jdbc.query("""
                    select f.id, f.display_id, f.policy_id, f.policy_version,
                           fs.artifact_id,
                           null::uuid execution_id,
                           fs.subject_type,
                           coalesce(a.name,'Exposure path') artifact_name,
                           null::text evidence_source, null::text evidence_class, f.finding_kind, paths.path_summaries,
                           coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                               when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) severity,
                           f.status, f.title, f.evidence::text evidence_json,
                           f.first_observed_at, f.last_observed_at, f.closed_at resolved_at,
                           f.closed_reason,
                           coalesce(review.disposition, 'UNREVIEWED') as disposition
                      from findings f
                      """ + FINDING_CONTEXT + FINDING_PATHS + """
                      left join lateral (
                          select disposition from finding_reviews r
                           where r.finding_id = f.id order by reviewed_at desc limit 1
                      ) review on true
                    """ + filter + " and f.finding_kind in ('AI_POSTURE','AI_EXPOSURE') order by f.last_observed_at desc, f.id limit :limit offset :offset",
                    params, this::finding);
            long total = count("""
                    select count(distinct f.id) from findings f
                    """ + FINDING_CONTEXT + FINDING_PATHS + """
                    """ + filter + " and f.finding_kind in ('AI_POSTURE','AI_EXPOSURE')", params);
            return new PageResponse<>(items, safePage, safeSize, total);
        });
    }

    public FindingResponse finding(Tenant tenant, UUID findingId) {
        return tenantExecution.run(tenant, () -> findingsById(findingId).stream().findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security finding not found")));
    }

    public FindingResponse review(
            Tenant tenant, UUID findingId, ReviewDisposition disposition, String reason, String actor) {
        if (disposition == null || disposition == ReviewDisposition.UNREVIEWED) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "A review disposition is required");
        }
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            FindingResponse finding = findingsById(findingId).stream().findFirst()
                    .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security finding not found"));
            jdbc.update("""
                    insert into finding_reviews (
                        id, tenant_id, finding_id, disposition, reason, policy_version, reviewed_by
                    ) values (
                        :id, :tenantId, :findingId, :disposition, :reason, :policyVersion, :reviewedBy
                    )
                    """, new MapSqlParameterSource()
                    .addValue("id", UUID.randomUUID())
                    .addValue("tenantId", tenant.getId())
                    .addValue("findingId", findingId)
                    .addValue("disposition", disposition.name())
                    .addValue("reason", blankToNull(reason))
                    .addValue("policyVersion", finding.policyVersion())
                    .addValue("reviewedBy", actor));
            auditEventService.record("ai_security.finding.reviewed", "finding",
                    findingId.toString(), "{\"disposition\":\"" + disposition.name() + "\"}");
            return findingsById(findingId).get(0);
        }));
    }

    public List<PolicyResponse> policies(Tenant tenant) {
        policyDefaults.ensureDefaults(tenant);
        return tenantExecution.run(tenant, () -> catalogPolicies(tenant).stream()
                .map(this::policy)
                .toList());
    }

    public PolicyResponse policy(Tenant tenant, String policyId) {
        policyDefaults.ensureDefaults(tenant);
        return tenantExecution.run(tenant, () -> catalogPolicies(tenant).stream()
                .filter(definition -> definition.id().equals(policyId))
                .map(this::policy)
                .findFirst()
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security policy not found")));
    }

    public PolicyResponse updatePolicy(Tenant tenant, String policyId, boolean enabled, String actor) {
        PolicyDefinition definition = catalogPolicies(tenant).stream().filter(policy -> policy.id().equals(policyId))
                .findFirst().orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security policy not found"));
        if (!policy(definition).available()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security policy not found");
        }
        aiGridApi.updateSelection(
                tenant,
                policyId,
                enabled ? "ENABLED" : "DISABLED",
                actor,
                "Updated through the AI Security policy compatibility API");
        if (!enabled) {
            canonicalFindings.closeForPolicy(tenant, policyId,
                    com.prototype.vulnwatch.domain.FindingCloseReason.AUTO_POLICY_TENANT_DISABLED);
        }
        auditEventService.record("ai_security.policy.updated", "ai_security_policy",
                policyId, "{\"enabled\":" + enabled + "}");
        return policy(definition);
    }

    private static final Set<String> VALID_SCOPE_MODES = Set.of(
            AiSecurityPolicyScopeMatcher.MODE_ALL,
            AiSecurityPolicyScopeMatcher.MODE_MATCH_RULES,
            AiSecurityPolicyScopeMatcher.MODE_CUSTOM_LIST);
    private static final Set<String> VALID_SCOPE_FIELDS =
            Set.of("PROVIDER", "REGION", "ACCOUNT_ID", "ARTIFACT_TYPE", "NATIVE_KIND", "NAME");
    private static final Set<String> VALID_SCOPE_OPERATORS =
            Set.of("EQUALS", "NOT_EQUALS", "CONTAINS", "NOT_CONTAINS");
    private static final Set<String> VALID_OVERRIDES = Set.of(
            AiSecurityPolicyScopeMatcher.OVERRIDE_INCLUDED, AiSecurityPolicyScopeMatcher.OVERRIDE_EXCLUDED);
    public PolicyConfigurationResponse policyConfiguration(Tenant tenant, String policyId) {
        PolicyDefinition definition = requirePolicy(tenant, policyId);
        policyDefaults.ensureDefaults(tenant);
        return tenantExecution.run(tenant, () -> buildConfiguration(definition));
    }

    public PolicyConfigurationResponse updatePolicyScope(
            Tenant tenant, String policyId, String rawMode, String rawConditionLogic,
            List<PolicyScopeConditionResponse> rawConditions, String actor) {
        PolicyDefinition definition = requirePolicy(tenant, policyId);
        ensureTenantConfigurable(policyId);
        String mode = rawMode == null ? null : rawMode.toUpperCase(Locale.ROOT);
        if (!VALID_SCOPE_MODES.contains(mode)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported scope mode");
        }
        String conditionLogic = "OR".equalsIgnoreCase(rawConditionLogic) ? "OR" : "AND";
        List<PolicyScopeConditionResponse> conditions = rawConditions == null ? List.of() : rawConditions;
        for (PolicyScopeConditionResponse condition : conditions) {
            if (!VALID_SCOPE_FIELDS.contains(condition.field())
                    || !VALID_SCOPE_OPERATORS.contains(condition.operator())) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported scope condition");
            }
        }
        reevaluationService.preflight(tenant, policyId, null);
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.query("select pg_advisory_xact_lock(hashtextextended(cast(:tenantId as text),0))", Map.of("tenantId",tenant.getId()), rs -> null);
            jdbc.update("""
                    insert into ai_grid_policy_scopes (
                        policy_id, tenant_id, mode, condition_logic, conditions_json, updated_by
                    ) values (
                        :policyId, :tenantId, :mode, :conditionLogic, cast(:conditions as jsonb), :actor
                    ) on conflict (policy_id) do update
                        set mode = excluded.mode,
                            condition_logic = excluded.condition_logic,
                            conditions_json = excluded.conditions_json,
                            updated_by = excluded.updated_by,
                            updated_at = now()
                    """, new MapSqlParameterSource()
                    .addValue("policyId", policyId)
                    .addValue("tenantId", tenant.getId())
                    .addValue("mode", mode)
                    .addValue("conditionLogic", conditionLogic)
                    .addValue("conditions", json(conditions))
                    .addValue("actor", actor));
            auditEventService.record("ai_security.policy.scope_updated", "ai_security_policy", policyId,
                    "{\"mode\":\"" + mode + "\"}");
            reevaluationService.reevaluatePolicy(tenant, policyId);
            return buildConfiguration(definition);
        }));
    }

    public PolicyConfigurationResponse addPolicyException(
            Tenant tenant, String policyId, UUID artifactId, String rawOverride, String reason, String actor) {
        PolicyDefinition definition = requirePolicy(tenant, policyId);
        ensureTenantConfigurable(policyId);
        if (artifactId == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "An artifact is required");
        }
        String override = rawOverride == null ? null : rawOverride.toUpperCase(Locale.ROOT);
        if (!VALID_OVERRIDES.contains(override)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported exception override");
        }
        reevaluationService.preflight(tenant, policyId, null);
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.query("select pg_advisory_xact_lock(hashtextextended(cast(:tenantId as text),0))", Map.of("tenantId",tenant.getId()), rs -> null);
            jdbc.update("""
                    insert into ai_grid_policy_artifact_overrides (
                        id, tenant_id, policy_id, artifact_id, override, reason, created_by
                    ) values (
                        :id, :tenantId, :policyId, :artifactId, :override, :reason, :actor
                    ) on conflict (tenant_id, policy_id, artifact_id) do update
                        set override = excluded.override, reason = excluded.reason, updated_at = now()
                    """, new MapSqlParameterSource()
                    .addValue("id", UUID.randomUUID())
                    .addValue("tenantId", tenant.getId())
                    .addValue("policyId", policyId)
                    .addValue("artifactId", artifactId)
                    .addValue("override", override)
                    .addValue("reason", blankToNull(reason))
                    .addValue("actor", actor));
            auditEventService.record("ai_security.policy.exception_added", "ai_security_policy", policyId,
                    "{\"artifactId\":\"" + artifactId + "\",\"override\":\"" + override + "\"}");
            reevaluationService.reevaluatePolicy(tenant, policyId);
            return buildConfiguration(definition);
        }));
    }

    public PolicyConfigurationResponse addPolicyExceptionRule(
            Tenant tenant, String policyId, String conditionLogic,
            List<PolicyScopeConditionResponse> conditions, String rawOverride, String reason, String actor) {
        PolicyDefinition definition = requirePolicy(tenant, policyId);
        ensureTenantConfigurable(policyId);
        String override = rawOverride == null ? null : rawOverride.toUpperCase(Locale.ROOT);
        if (!VALID_OVERRIDES.contains(override)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported exception override");
        }
        List<ScopeCondition> ruleConditions = (conditions == null ? List.<PolicyScopeConditionResponse>of() : conditions).stream()
                .filter(condition -> condition != null && condition.field() != null && condition.operator() != null)
                .map(condition -> new ScopeCondition(condition.field(), condition.operator(), condition.value() == null ? "" : condition.value()))
                .toList();
        if (ruleConditions.isEmpty() || ruleConditions.stream().anyMatch(condition -> condition.value().isBlank())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "At least one complete exception condition is required");
        }
        String logic = "OR".equalsIgnoreCase(conditionLogic) ? "OR" : "AND";
        ScopeConfig exceptionScope = new ScopeConfig(AiSecurityPolicyScopeMatcher.MODE_MATCH_RULES, logic, ruleConditions);
        reevaluationService.preflight(tenant, policyId, null);
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.query("select pg_advisory_xact_lock(hashtextextended(cast(:tenantId as text),0))", Map.of("tenantId",tenant.getId()), rs -> null);
            List<ArtifactScopeRow> artifacts = jdbc.query("""
                    select id, provider, region, account_id, artifact_type, native_kind, name
                      from ai_security_artifacts where active = true
                    """, Map.of(), (rs, rowNum) -> new ArtifactScopeRow(
                    rs.getObject("id", UUID.class), rs.getString("provider"), rs.getString("region"),
                    rs.getString("account_id"), rs.getString("artifact_type"), rs.getString("native_kind"), rs.getString("name")));
            List<ArtifactScopeRow> matches = artifacts.stream()
                    .filter(artifact -> definition.artifactTypes().isEmpty() || definition.artifactTypes().contains(artifact.artifactType()))
                    .filter(artifact -> AiSecurityPolicyScopeMatcher.matchesRules(exceptionScope,
                            new ArtifactScopeFacts(artifact.provider(), artifact.region(), artifact.accountId(),
                                    artifact.artifactType(), artifact.nativeKind(), artifact.name())))
                    .toList();
            for (ArtifactScopeRow artifact : matches) {
                jdbc.update("""
                        insert into ai_grid_policy_artifact_overrides (
                            id, tenant_id, policy_id, artifact_id, override, reason, created_by
                        ) values (
                            :id, :tenantId, :policyId, :artifactId, :override, :reason, :actor
                        ) on conflict (tenant_id, policy_id, artifact_id) do update
                            set override = excluded.override, reason = excluded.reason, updated_at = now()
                        """, new MapSqlParameterSource()
                        .addValue("id", UUID.randomUUID())
                        .addValue("tenantId", tenant.getId())
                        .addValue("policyId", policyId)
                        .addValue("artifactId", artifact.id())
                        .addValue("override", override)
                        .addValue("reason", blankToNull(reason))
                        .addValue("actor", actor));
            }
            auditEventService.record("ai_security.policy.exception_rule_added", "ai_security_policy", policyId,
                    "{\"override\":\"" + override + "\",\"matchedArtifacts\":" + matches.size() + "}");
            reevaluationService.reevaluatePolicy(tenant, policyId);
            return buildConfiguration(definition);
        }));
    }

    public PolicyConfigurationResponse removePolicyException(
            Tenant tenant, String policyId, UUID artifactId, String actor) {
        PolicyDefinition definition = requirePolicy(tenant, policyId);
        ensureTenantConfigurable(policyId);
        reevaluationService.preflight(tenant, policyId, null);
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.query("select pg_advisory_xact_lock(hashtextextended(cast(:tenantId as text),0))", Map.of("tenantId",tenant.getId()), rs -> null);
            jdbc.update("""
                    delete from ai_grid_policy_artifact_overrides
                     where policy_id = :policyId and artifact_id = :artifactId
                    """, Map.of("policyId", policyId, "artifactId", artifactId));
            auditEventService.record("ai_security.policy.exception_removed", "ai_security_policy", policyId,
                    "{\"artifactId\":\"" + artifactId + "\"}");
            reevaluationService.reevaluatePolicy(tenant, policyId);
            return buildConfiguration(definition);
        }));
    }

    public PolicyConfigurationResponse updatePolicyParameters(
            Tenant tenant, String policyId, Map<String, String> parameters, String actor) {
        PolicyDefinition definition = requirePolicy(tenant, policyId);
        List<PolicyParameterSpec> specs = policyParameterSpecs(policyId);
        Map<String, String> validated = new LinkedHashMap<>();
        for (PolicyParameterSpec spec : specs) {
            String value = parameters == null ? null : parameters.get(spec.key());
            if (value == null || value.isBlank()) {
                validated.put(spec.key(), spec.defaultValue());
                continue;
            }
            if ("ENUM".equals(spec.type()) && !spec.options().contains(value.toUpperCase(Locale.ROOT))) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Unsupported value for parameter " + spec.key());
            }
            validated.put(spec.key(), value.toUpperCase(Locale.ROOT));
        }
        reevaluationService.preflight(tenant, policyId, new LinkedHashMap<>(validated));
        return tenantExecution.run(tenant, () -> transactionTemplate.execute(status -> {
            jdbc.query("select pg_advisory_xact_lock(hashtextextended(cast(:tenantId as text),0))", Map.of("tenantId",tenant.getId()), rs -> null);
            jdbc.update("""
                    insert into ai_grid_policy_parameters (policy_id, tenant_id, parameters_json, updated_by)
                    values (:policyId, :tenantId, cast(:parameters as jsonb), :actor)
                    on conflict (policy_id) do update
                        set parameters_json = excluded.parameters_json,
                            updated_by = excluded.updated_by,
                            updated_at = now()
                    """, new MapSqlParameterSource()
                    .addValue("policyId", policyId)
                    .addValue("tenantId", tenant.getId())
                    .addValue("parameters", json(validated))
                    .addValue("actor", actor));
            auditEventService.record("ai_security.policy.parameters_updated", "ai_security_policy", policyId,
                    json(validated));
            reevaluationService.reevaluatePolicy(tenant, policyId);
            return buildConfiguration(definition);
        }));
    }

    public PolicyAssistExplanationResponse explainPolicy(Tenant tenant, String policyId) {
        PolicyDefinition definition = requirePolicy(tenant, policyId);
        return tenantExecution.run(tenant, () -> {
            PolicyConfigurationResponse configuration = buildConfiguration(definition);
            long openOnMatched = count("""
                    select count(*) from findings
                     where policy_id = :policyId
                       and finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                       and status = 'OPEN'
                    """, Map.of("policyId", policyId));
            StringBuilder text = new StringBuilder();
            if (configuration.totalArtifactCount() == 0) {
                text.append("No ").append(String.join(" or ", definition.artifactTypes()))
                        .append(" artifacts have been discovered yet, so this policy has nothing to evaluate.");
            } else if (configuration.matchedArtifactCount() == 0) {
                text.append("The current scope excludes all ").append(configuration.totalArtifactCount())
                        .append(" eligible artifact(s) in your inventory — this policy will not produce findings until scope is widened.");
            } else {
                text.append(configuration.matchedArtifactCount()).append(" of ")
                        .append(configuration.totalArtifactCount())
                        .append(" eligible artifact(s) are currently in scope for this policy. ");
                if (openOnMatched == 0) {
                    text.append("None of them currently violate it.");
                } else {
                    text.append(openOnMatched).append(" of them currently violate it and have an open finding.");
                }
                if (!configuration.parameters().isEmpty()) {
                    PolicyParameterValueResponse param = configuration.parameters().get(0);
                    text.append(" The policy is evaluated against your configured \"")
                            .append(param.label()).append("\" of ").append(param.value()).append(".");
                }
            }
            if (!configuration.exceptions().isEmpty()) {
                long excludedCount = configuration.exceptions().stream()
                        .filter(exception -> AiSecurityPolicyScopeMatcher.OVERRIDE_EXCLUDED.equals(exception.override()))
                        .count();
                if (excludedCount > 0) {
                    text.append(" ").append(excludedCount).append(" artifact(s) are explicitly excepted from this policy.");
                }
            }
            return new PolicyAssistExplanationResponse(text.toString(), Instant.now());
        });
    }

    private PolicyDefinition requirePolicy(Tenant tenant, String policyId) {
        return catalogDefinition(tenant, policyId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AI Security policy not found"));
    }

    private void ensureTenantConfigurable(String policyId) {
        Boolean configurable = jdbc.query("""
                select p.tenant_configurable
                  from platform.ai_grid_policy_versions p
                  join platform.ai_grid_policy_distribution d on d.policy_id = p.policy_id
                   and (d.pinned_version is null or d.pinned_version = p.version)
                 where p.policy_id = :policyId
                 order by p.published_at desc nulls last, p.version desc limit 1
                """, Map.of("policyId", policyId), rs -> rs.next() ? rs.getBoolean(1) : null);
        if (Boolean.FALSE.equals(configurable)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "This policy is governed by the platform and cannot be configured by a tenant");
        }
    }

    /** Tenant policy projections are populated exclusively from the governed catalog. */
    private List<PolicyDefinition> catalogPolicies(Tenant tenant) {
        return jdbc.query("""
                select distinct on (p.policy_id) p.policy_id,p.version,p.name,p.severity,p.artifact_types_json::text,
                       p.required_resource_families_json::text,p.description,p.remediation,p.framework_mappings_json::text
                  from %s p
                  join platform.ai_grid_policy_distribution d on d.policy_id=p.policy_id
                 where coalesce(p.evaluation_mode, '') not like 'RUNTIME_%%' and p.policy_id not like 'AGCF-RT-%%'
                   and p.lifecycle in ('VALIDATED','APPROVED','PUBLISHED','CANARY','DEPRECATED')
                   and platform.ai_grid_policy_visible_to_tenant(
                           d.available or p.lifecycle='DEPRECATED', d.rollout_stage,
                           d.canary_tenant_ids_json, cast(:tenantId as uuid))
                 order by p.policy_id,p.version
                """.formatted(AiGridPolicyResolution.versions(":tenantId")), Map.of("tenantId", tenant.getId().toString()), (rs, n) -> catalogDefinition(rs));
    }

    private java.util.Optional<PolicyDefinition> catalogDefinition(Tenant tenant, String policyId) {
        List<PolicyDefinition> definitions = jdbc.query("""
                select p.policy_id,p.version,p.name,p.severity,p.artifact_types_json::text,
                       p.required_resource_families_json::text,p.description,p.remediation,p.framework_mappings_json::text
                  from %s p
                  join platform.ai_grid_policy_distribution d on d.policy_id=p.policy_id
                 where p.policy_id=:id and coalesce(p.evaluation_mode, '') not like 'RUNTIME_%%' and p.policy_id not like 'AGCF-RT-%%'
                   and p.lifecycle in ('VALIDATED','APPROVED','PUBLISHED','CANARY','DEPRECATED')
                   and platform.ai_grid_policy_visible_to_tenant(
                           d.available or p.lifecycle='DEPRECATED', d.rollout_stage,
                           d.canary_tenant_ids_json, cast(:tenantId as uuid))
                 order by p.version limit 1
                """.formatted(AiGridPolicyResolution.versions(":tenantId")), Map.of("id", policyId, "tenantId", tenant.getId().toString()), (rs, n) -> catalogDefinition(rs));
        return definitions.stream().findFirst();
    }

    /** Parameter definitions are populated exclusively from the governed catalog. */
    private List<PolicyParameterSpec> policyParameterSpecs(String policyId) {
        List<String> definitions = jdbc.query("""
                select parameter_definitions_json::text from %s
                 where policy_id=:id and lifecycle in ('VALIDATED','APPROVED','PUBLISHED','CANARY')
                 order by published_at desc nulls last, version desc limit 1
                """.formatted(AiGridPolicyResolution.currentVersions()), Map.of("id", policyId), (rs, n) -> rs.getString(1));
        List<PolicyParameterSpec> catalogSpecs = definitions.isEmpty() ? List.of() : parameterSpecs(definitions.get(0));
        return catalogSpecs;
    }

    private List<PolicyParameterSpec> parameterSpecs(String json) {
        try {
            List<Map<String, Object>> definitions = objectMapper.readValue(json, new TypeReference<>() {});
            return definitions.stream().map(definition -> new PolicyParameterSpec(
                    String.valueOf(definition.get("key")),
                    String.valueOf(definition.getOrDefault("label", definition.get("key"))),
                    String.valueOf(definition.get("type")),
                    ((List<?>) definition.getOrDefault("options", List.of())).stream().map(String::valueOf).toList(),
                    String.valueOf(definition.get("defaultValue")),
                    String.valueOf(definition.getOrDefault("helpText", "")))).toList();
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Invalid published policy parameter definitions");
        }
    }

    private PolicyDefinition catalogDefinition(ResultSet rs) throws SQLException {
        return new PolicyDefinition(rs.getString("policy_id"), rs.getString("version"), rs.getString("name"),
                rs.getString("severity"), readStringList(rs.getString("artifact_types_json")),
                readStringList(rs.getString("required_resource_families_json")), rs.getString("description"),
                rs.getString("remediation"), readStringMap(rs.getString("framework_mappings_json")));
    }

    private PolicyConfigurationResponse buildConfiguration(PolicyDefinition definition) {
        Map<String, Object> scopeRow = jdbc.query("""
                select mode, condition_logic, conditions_json::text, updated_by, updated_at
                  from ai_grid_policy_scopes where policy_id = :policyId
                """, Map.of("policyId", definition.id()), rs -> rs.next()
                ? Map.of(
                        "mode", rs.getString("mode"),
                        "conditionLogic", rs.getString("condition_logic"),
                        "conditionsJson", rs.getString("conditions_json"),
                        "updatedBy", (Object) rs.getString("updated_by"),
                        "updatedAt", (Object) rs.getTimestamp("updated_at"))
                : Map.of());
        String mode = (String) scopeRow.getOrDefault("mode", AiSecurityPolicyScopeMatcher.MODE_ALL);
        String conditionLogic = (String) scopeRow.getOrDefault("conditionLogic", "AND");
        List<PolicyScopeConditionResponse> conditions = readConditions((String) scopeRow.get("conditionsJson"));
        PolicyScopeResponse scope = new PolicyScopeResponse(
                mode, conditionLogic, conditions,
                (String) scopeRow.get("updatedBy"),
                scopeRow.get("updatedAt") instanceof java.sql.Timestamp timestamp ? timestamp.toInstant() : null);

        List<PolicyExceptionResponse> exceptions = jdbc.query("""
                select o.artifact_id, a.name as artifact_name, o.override, o.reason, o.created_by, o.created_at
                  from ai_grid_policy_artifact_overrides o
                  join ai_security_artifacts a on a.id = o.artifact_id
                 where o.policy_id = :policyId
                 order by o.created_at desc
                """, Map.of("policyId", definition.id()), (rs, rowNum) -> new PolicyExceptionResponse(
                rs.getObject("artifact_id", UUID.class),
                rs.getString("artifact_name"),
                rs.getString("override"),
                rs.getString("reason"),
                rs.getString("created_by"),
                instant(rs, "created_at")));
        Map<String, String> overridesByArtifact = new LinkedHashMap<>();
        exceptions.forEach(exception -> overridesByArtifact.put(exception.artifactId().toString(), exception.override()));

        List<ArtifactScopeRow> artifacts = definition.artifactTypes().isEmpty()
                ? List.of()
                : jdbc.query("""
                    select id, provider, region, account_id, artifact_type, native_kind, name
                      from ai_security_artifacts
                     where active = true and artifact_type in (:types)
                    """, Map.of("types", definition.artifactTypes()),
                    (rs, rowNum) -> new ArtifactScopeRow(
                            rs.getObject("id", UUID.class), rs.getString("provider"), rs.getString("region"),
                            rs.getString("account_id"), rs.getString("artifact_type"), rs.getString("native_kind"),
                            rs.getString("name")));
        ScopeConfig scopeConfig = new ScopeConfig(mode, conditionLogic, conditions.stream()
                .map(condition -> new ScopeCondition(condition.field(), condition.operator(), condition.value()))
                .toList());
        long matched = artifacts.stream()
                .filter(artifact -> AiSecurityPolicyScopeMatcher.isInScope(
                        scopeConfig,
                        new ArtifactScopeFacts(artifact.provider(), artifact.region(), artifact.accountId(),
                                artifact.artifactType(), artifact.nativeKind(), artifact.name()),
                        overridesByArtifact.get(artifact.id().toString())))
                .count();

        List<PolicyParameterValueResponse> parameters = buildParameterValues(definition.id());
        Map<String, Object> governance = jdbc.query("""
                select p.version, p.lifecycle, p.governance_owner, p.governance_status,
                       p.tenant_configurable, d.default_selection,
                       coalesce(s.configuration_source, 'PLATFORM_DEFAULT') configuration_source,
                       s.updated_at
                  from %s p
                  join platform.ai_grid_policy_distribution d on d.policy_id = p.policy_id
                   and (d.pinned_version is null or d.pinned_version = p.version)
                  left join ai_grid_policy_selections s on s.policy_id = p.policy_id
                 where p.policy_id = :policyId
                 order by p.published_at desc nulls last, p.version desc limit 1
                """.formatted(AiGridPolicyResolution.currentVersions()), Map.of("policyId", definition.id()), rs -> {
                    if (!rs.next()) return Map.of();
                    Map<String, Object> values = new LinkedHashMap<>();
                    values.put("version", rs.getString("version"));
                    values.put("lifecycle", rs.getString("lifecycle"));
                    values.put("owner", rs.getString("governance_owner"));
                    values.put("status", rs.getString("governance_status"));
                    values.put("tenantConfigurable", rs.getBoolean("tenant_configurable"));
                    values.put("platformDefaultSelection", rs.getString("default_selection"));
                    values.put("configurationSource", rs.getString("configuration_source"));
                    values.put("updatedAt", rs.getTimestamp("updated_at"));
                    return values;
                });
        PolicyGovernanceResponse policyGovernance = new PolicyGovernanceResponse(
                (String) governance.get("version"), (String) governance.get("lifecycle"),
                (String) governance.get("owner"), (String) governance.get("status"),
                Boolean.TRUE.equals(governance.get("tenantConfigurable")),
                (String) governance.get("platformDefaultSelection"),
                (String) governance.get("configurationSource"),
                governance.get("updatedAt") instanceof java.sql.Timestamp timestamp ? timestamp.toInstant() : null);
        Tenant tenant=new Tenant(); tenant.setId(com.prototype.vulnwatch.service.TenantContext.getCurrentTenantId());
        tenant.setSchemaName(com.prototype.vulnwatch.service.TenantContext.getCurrentSchemaName());
        var processing=aiGridApi.policyAssessmentStatus(tenant,definition.id());
        return new PolicyConfigurationResponse(policyGovernance, scope, exceptions, parameters, matched, artifacts.size(),
                "COMPLETE",processing.assessmentStatus(),processing.assessedSubjects(),processing.failedPolicies(),processing.failureSummaries());
    }

    private List<PolicyParameterValueResponse> buildParameterValues(String policyId) {
        List<PolicyParameterSpec> specs = policyParameterSpecs(policyId);
        if (specs.isEmpty()) {
            return List.of();
        }
        Map<String, Object> stored = jdbc.query("""
                select parameters_json::text from ai_grid_policy_parameters where policy_id = :policyId
                """, Map.of("policyId", policyId), rs -> rs.next() ? readMap(rs.getString("parameters_json")) : Map.of());
        return specs.stream()
                .map(spec -> new PolicyParameterValueResponse(
                        spec.key(), spec.label(), spec.type(), spec.options(), spec.defaultValue(), spec.helpText(),
                        String.valueOf(stored.getOrDefault(spec.key(), spec.defaultValue()))))
                .toList();
    }

    @SuppressWarnings("unchecked")
    private List<PolicyScopeConditionResponse> readConditions(String conditionsJson) {
        if (conditionsJson == null || conditionsJson.isBlank()) {
            return List.of();
        }
        List<Map<String, Object>> raw;
        try {
            raw = objectMapper.readValue(conditionsJson, new com.fasterxml.jackson.core.type.TypeReference<>() {});
        } catch (Exception ex) {
            return List.of();
        }
        return raw.stream()
                .map(row -> new PolicyScopeConditionResponse(
                        String.valueOf(row.get("field")), String.valueOf(row.get("operator")), String.valueOf(row.get("value"))))
                .toList();
    }

    private record ArtifactScopeRow(
            UUID id, String provider, String region, String accountId, String artifactType, String nativeKind, String name) {
    }

    public List<RunResponse> runs(Tenant tenant) {
        return runs(tenant, null);
    }

    public List<RunResponse> runs(Tenant tenant, String provider) {
        String normalized = normalizedProvider(provider);
        return syncRunFacade.listForTenant(tenant.getId()).stream()
                .filter(run -> normalized == null
                        || ("AWS".equals(normalized)
                                && AiSecuritySyncRunFacade.AWS_SYNC_TYPE.equals(run.getSyncType()))
                        || ("AZURE".equals(normalized)
                                && AiSecuritySyncRunFacade.AZURE_SYNC_TYPE.equals(run.getSyncType()))
                        || ("MICROSOFT_COPILOT".equals(normalized)
                                && AiSecuritySyncRunFacade.COPILOT_SYNC_TYPE.equals(run.getSyncType())))
                .map(run -> tenantExecution.run(tenant, () -> run(run)))
                .toList();
    }

    public List<ScopeResponse> scopes(Tenant tenant, UUID runId) {
        return scopes(tenant, runId, null, null);
    }

    public List<ScopeResponse> scopes(Tenant tenant, UUID runId, String resourceFamily, String status) {
        syncRunFacade.loadForTenant(tenant.getId(), runId);
        return tenantExecution.run(tenant, () -> jdbc.query("""
                select id, run_id, account_id, region, resource_family, scope_key, status,
                       expected_chunks, accepted_chunks, diagnostic_code, diagnostic_json::text,
                       started_at, completed_at
                  from ai_security_snapshot_scopes
                 where run_id = :runId
                   and (cast(:resourceFamily as varchar) is null or resource_family = :resourceFamily)
                   and (cast(:status as varchar) is null or status = :status)
                 order by account_id, region, resource_family
                """, new MapSqlParameterSource()
                .addValue("runId", runId)
                .addValue("resourceFamily", blankToNull(resourceFamily))
                .addValue("status", blankToNull(status)), (rs, rowNum) -> new ScopeResponse(
                rs.getObject("id", UUID.class),
                rs.getObject("run_id", UUID.class),
                rs.getString("account_id"),
                rs.getString("region"),
                rs.getString("resource_family"),
                rs.getString("scope_key"),
                rs.getString("status"),
                rs.getInt("accepted_chunks"),
                rs.getInt("expected_chunks"),
                rs.getString("diagnostic_code"),
                readMap(rs.getString("diagnostic_json")),
                instant(rs, "started_at"),
                instant(rs, "completed_at"))));
    }

    private String normalizedProvider(String provider) {
        String value = blankToNull(provider);
        if (value == null) return null;
        String normalized = value.toUpperCase(java.util.Locale.ROOT);
        if (!List.of("AWS", "AZURE", "MICROSOFT_COPILOT").contains(normalized)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported AI Security provider");
        }
        return normalized;
    }

    private PolicyResponse policy(PolicyDefinition definition) {
        Map<String, Object> row = jdbc.queryForMap("""
                select d.available,
                       case when s.configuration_source='TENANT_OVERRIDE' then s.selection else d.default_selection end as selection,
                       coalesce(open_counts.open_count, 0) as open_count,
                       coalesce(lifetime_counts.lifetime_count, 0) as lifetime_count,
                       quality.last_evaluated_at, quality.pass_count, quality.fail_count,
                       quality.no_decision_count,
                       (select lifecycle from platform.ai_grid_policy_versions where policy_id=d.policy_id
                         and version=d.pinned_version limit 1) as lifecycle
                  from platform.ai_grid_policy_distribution d
                  left join ai_grid_policy_selections s on s.policy_id = d.policy_id
                  left join (
                      select policy_id, count(*) as open_count from findings
                       where finding_kind in ('AI_POSTURE', 'AI_EXPOSURE')
                         and status = 'OPEN' group by policy_id
                  ) open_counts on open_counts.policy_id = d.policy_id
                  left join (
                      select policy_id, count(*) as lifetime_count from findings
                       where finding_kind in ('AI_POSTURE', 'AI_EXPOSURE') group by policy_id
                  ) lifetime_counts on lifetime_counts.policy_id = d.policy_id
                  left join (
                select policy_id, max(evaluated_at) as last_evaluated_at,
                             count(*) filter (where decision = 'PASS') as pass_count,
                             count(*) filter (where decision = 'FAIL') as fail_count,
                             count(*) filter (where decision not in ('PASS', 'FAIL')) as no_decision_count
                        from ai_grid_assessments group by policy_id
                  ) quality on quality.policy_id = d.policy_id
                 where d.policy_id = :policyId
                """, Map.of("policyId", definition.id()));
        boolean available = Boolean.TRUE.equals(row.get("available"));
        String lifecycle = (String) row.get("lifecycle");
        String selection = (String) row.get("selection");
        boolean enabled = available && !"DEPRECATED".equals(lifecycle)
                && ("REQUIRED".equals(selection) || "ENABLED".equals(selection));
        long pass = number(row.get("pass_count"));
        long fail = number(row.get("fail_count"));
        long noDecision = number(row.get("no_decision_count"));
        CoverageGate coverageGate = coverageGate(definition.severity(), pass, fail, noDecision);
        return new PolicyResponse(
                definition.id(), definition.version(), definition.name(), definition.severity(),
                definition.artifactTypes(), definition.requiredResourceFamilies(), definition.description(),
                definition.remediation(), definition.controlMappings(), available, enabled,
                number(row.get("open_count")), number(row.get("lifetime_count")),
                row.get("last_evaluated_at") instanceof java.sql.Timestamp timestamp ? timestamp.toInstant() : null,
                coverageGate.coverage(), coverageGate.threshold(), coverageGate.status(),
                coverageGate.evaluatedArtifacts(), coverageGate.noDecisionCount(), lifecycle,
                "DEPRECATED".equals(lifecycle) ? "PLATFORM_DEPRECATED" : null);
    }

    static CoverageGate coverageGate(String severity, long pass, long fail, long noDecision) {
        long evaluated = pass + fail + noDecision;
        double coverage = evaluated == 0 ? 0 : ((double) (pass + fail) / evaluated);
        double threshold = "CRITICAL".equals(severity) ? 1.0 : 0.95;
        String status = evaluated == 0 ? "NO_DATA" : coverage >= threshold ? "PASS" : "FAIL";
        return new CoverageGate(coverage, threshold, status, evaluated, noDecision);
    }

    private List<FindingResponse> findingsById(UUID findingId) {
        return jdbc.query("""
                select f.id, f.display_id, f.policy_id, f.policy_version,
                       fs.artifact_id,
                       null::uuid execution_id,
                       fs.subject_type,
                       coalesce(a.name,'Exposure path') artifact_name,
                       null::text evidence_source, null::text evidence_class, f.finding_kind, paths.path_summaries,
                       coalesce(f.severity_override, case when f.risk_score >= 9 then 'CRITICAL'
                           when f.risk_score >= 7 then 'HIGH' when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end) severity,
                       f.status, f.title, f.evidence::text evidence_json,
                       f.first_observed_at, f.last_observed_at, f.closed_at resolved_at,
                       f.closed_reason,
                       coalesce(review.disposition, 'UNREVIEWED') as disposition
                  from findings f
                  """ + FINDING_CONTEXT + FINDING_PATHS + """
                  left join lateral (
                      select disposition from finding_reviews r
                       where r.finding_id = f.id order by reviewed_at desc limit 1
                  ) review on true
                 where f.id = :id and f.finding_kind in ('AI_POSTURE','AI_EXPOSURE')
                """, new MapSqlParameterSource().addValue("id",findingId).addValue("provider",null,Types.VARCHAR)
                .addValue("subscription",null,Types.VARCHAR).addValue("nativeKind",null,Types.VARCHAR), this::finding);
    }

    private List<RelationshipResponse> graphEdges(UUID root, int limit) {
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("root", root)
                .addValue("limit", limit);
        return jdbc.query("""
                select r.id, r.relationship_type, r.source_artifact_id, source.name as source_name,
                       r.target_artifact_id, target.name as target_name, r.attributes_json::text
                  from ai_security_relationships r
                  join ai_security_artifacts source on source.id = r.source_artifact_id
                 join ai_security_artifacts target on target.id = r.target_artifact_id
                 where r.active = true
                   and (cast(:root as uuid) is null or r.source_artifact_id = :root or r.target_artifact_id = :root)
                 order by r.last_observed_at desc limit :limit
                """, params, (rs, rowNum) -> new RelationshipResponse(
                rs.getObject("id", UUID.class),
                rs.getString("relationship_type"),
                rs.getObject("source_artifact_id", UUID.class),
                rs.getString("source_name"),
                rs.getObject("target_artifact_id", UUID.class),
                rs.getString("target_name"),
                AiSecurityFieldContract.responseSafe(readMap(rs.getString("attributes_json")))));
    }

    private ArtifactResponse artifact(ResultSet rs, int rowNum) throws SQLException {
        String provider = rs.getString("provider");
        String nativeKind = rs.getString("native_kind");
        UUID artifactId = rs.getObject("id", UUID.class);
        String artifactType = rs.getString("artifact_type");
        List<UUID> systemIds = uuidArray(rs.getArray("system_ids"));
        Map<String, Object> rawAttributes = readMap(rs.getString("attributes_json"));
        AiGridRelationshipSemantics.AttachmentContract attachmentContract =
                AiGridRelationshipSemantics.attachmentContract(artifactType, nativeKind, rawAttributes);
        String attachmentState = switch (attachmentContract) {
            case ROOT -> "ROOT";
            case REQUIRED -> systemIds.isEmpty() ? "UNATTACHED_REQUIRED" : "ATTACHED";
            case OPTIONAL -> systemIds.isEmpty() ? "STANDALONE_OPTIONAL" : "ATTACHED";
        };
        return new ArtifactResponse(
                artifactId,
                provider,
                rs.getString("provider_resource_id"),
                artifactType,
                nativeKind,
                rs.getString("name"),
                rs.getString("account_id"),
                rs.getString("region"),
                rs.getBoolean("active"),
                AiSecurityFieldContract.responseSafe(
                        metadataSanitizer.sanitize(provider, nativeKind, rawAttributes).attributes()),
                rs.getString("owner_name"),
                rs.getString("owner_state"),
                rs.getString("owner_source"),
                (Double) rs.getObject("owner_confidence"),
                rs.getString("owner_confidence_method"),
                rs.getString("owner_confidence_method_version"),
                rs.getString("business_criticality"),
                rs.getString("environment"),
                instant(rs, "first_observed_at"),
                instant(rs, "last_observed_at"),
                rs.getString("pii_scan_status"),
                rs.getString("pii_source"),
                readStringList(rs.getString("pii_info_types")),
                rs.getInt("pii_finding_count"),
                instant(rs, "pii_last_scanned_at"),
                attachmentState,
                systemIds, null);
    }

    private List<UUID> uuidArray(java.sql.Array array) throws SQLException {
        if (array == null) return List.of();
        Object raw = array.getArray();
        if (raw instanceof UUID[] values) return List.of(values);
        if (raw instanceof Object[] values) {
            return java.util.Arrays.stream(values).map(value -> UUID.fromString(String.valueOf(value))).toList();
        }
        return List.of();
    }

    private void validateArtifactTypeFilter(String artifactType) {
        if (artifactType != null && !artifactType.isBlank()
                && !AiSecurityTaxonomy.isExplicitArtifactType(artifactType)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unsupported AI artifact category");
        }
    }

    private FindingResponse finding(ResultSet rs, int rowNum) throws SQLException {
        return new FindingResponse(
                rs.getObject("id", UUID.class),
                rs.getString("display_id"),
                rs.getString("policy_id"),
                rs.getString("policy_version"),
                rs.getObject("artifact_id", UUID.class),
                rs.getObject("execution_id", UUID.class),
                rs.getString("subject_type"),
                rs.getString("artifact_name"),
                rs.getString("evidence_source"),
                rs.getString("evidence_class"),
                rs.getString("severity"),
                rs.getString("status"),
                rs.getString("title"),
                readMap(rs.getString("evidence_json")),
                rs.getString("disposition"),
                instant(rs, "first_observed_at"),
                instant(rs, "last_observed_at"),
                instant(rs, "resolved_at"),
                rs.getString("closed_reason"),rs.getString("finding_kind"),readPathSummaries(rs.getString("path_summaries")));
    }

    private RunResponse run(SyncRun run) {
        Tenant tenant=new Tenant(); tenant.setId(com.prototype.vulnwatch.service.TenantContext.getCurrentTenantId());
        tenant.setSchemaName(com.prototype.vulnwatch.service.TenantContext.getCurrentSchemaName());
        var processing=aiGridApi.assessmentStatus(tenant,run.getId());
        return new RunResponse(
                run.getId(), run.getStatus(), run.getRecordsFetched(), run.getRecordsFailed(),
                run.getStartedAt(), run.getCompletedAt(), run.getErrorMessage(),run.getStatus(),processing.assessmentStatus(),
                processing.assessedSubjects(),processing.failedPolicies(),processing.failureSummaries());
    }

    private long count(String sql, org.springframework.jdbc.core.namedparam.SqlParameterSource params) {
        Long value = jdbc.queryForObject(sql, params, Long.class);
        return value == null ? 0 : value;
    }

    private long count(String sql, Map<String, ?> params) {
        Long value = jdbc.queryForObject(sql, params, Long.class);
        return value == null ? 0 : value;
    }

    private long number(Object value) {
        return value instanceof Number number ? number.longValue() : 0;
    }

    private Map<String, Object> readMap(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception ex) {
            return Map.of();
        }
    }

    private List<String> readStringList(String json) {
        if (json == null || json.isBlank()) return List.of();
        try { return objectMapper.readValue(json, new TypeReference<>() {}); } catch (Exception ex) { return List.of(); }
    }

    private Map<String, String> readStringMap(String json) {
        Map<String, Object> raw = readMap(json);
        Map<String, String> result = new LinkedHashMap<>();
        raw.forEach((key, value) -> result.put(key, value instanceof List<?> values
                ? values.stream().map(String::valueOf).collect(java.util.stream.Collectors.joining(", ")) : String.valueOf(value)));
        return result;
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Unable to serialize AI Security payload", ex);
        }
    }

    private String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private Instant instant(ResultSet rs, String column) throws SQLException {
        return rs.getTimestamp(column) == null ? null : rs.getTimestamp(column).toInstant();
    }

    public record SummaryResponse(
            Map<String, Long> artifactCounts,
            Map<String, Long> nativeKindCounts,
            Map<String, Long> providerCounts,
            long openFindings,
            long incompleteScopes,
            Instant lastCompleteSnapshotAt,
            long logicalAgentCount
    ) {
    }

    public record SeverityGridRow(
            String nativeKind, long critical, long high, long medium, long low, long total
    ) {
    }

    public record SeverityGridResponse(List<SeverityGridRow> rows) {
    }

    public record TopRiskArtifact(
            UUID id, String name, String nativeKind, String provider, String accountId,
            long criticalCount, long highCount, long mediumCount, long lowCount, long score
    ) {
    }

    public record PageResponse<T>(List<T> items, int page, int size, long total) {
    }

    public record ArtifactResponse(
            UUID id, String provider, String providerResourceId, String artifactType, String nativeKind,
            String name, String accountId, String region, boolean active, Map<String, Object> attributes,
            String ownerName, String ownerState, String ownerSource, Double ownerConfidence,
            String ownerConfidenceMethod, String ownerConfidenceMethodVersion,
            String businessCriticality, String environment,
            Instant firstObservedAt, Instant lastObservedAt,
            String piiScanStatus, String piiSource, List<String> piiInfoTypes,
            int piiFindingCount, Instant piiLastScannedAt,
            String attachmentState, List<UUID> systemIds, AiAgentDeploymentService.Metadata deployment
    ) {
        public ArtifactResponse withDeployment(AiAgentDeploymentService.Metadata value) {
            return new ArtifactResponse(id, provider, providerResourceId, artifactType, nativeKind, name,
                    accountId, region, active, attributes, ownerName, ownerState, ownerSource, ownerConfidence,
                    ownerConfidenceMethod, ownerConfidenceMethodVersion, businessCriticality, environment,
                    firstObservedAt, lastObservedAt, piiScanStatus, piiSource, piiInfoTypes, piiFindingCount,
                    piiLastScannedAt, attachmentState, systemIds, value);
        }
    }

    public record ArtifactSummaryResponse(
            UUID id, String name, String nativeKind, String provider, String accountId, String region,
            long criticalFindings, long highFindings, long totalFindings,
            long policiesFailed, long policiesTotal, AiAgentDeploymentService.Metadata deployment
    ) {
        public ArtifactSummaryResponse withDeployment(AiAgentDeploymentService.Metadata value) {
            return new ArtifactSummaryResponse(id, name, nativeKind, provider, accountId, region,
                    criticalFindings, highFindings, totalFindings, policiesFailed, policiesTotal, value);
        }
    }

    public record ActivityEvidenceResponse(
            String factKey, String valueJson, String state, String evidenceReference,
            Instant observedAt, Instant validFrom, Instant validUntil, Double confidence,
            String producerId, boolean expired
    ) {
    }

    public record RelationshipResponse(
            UUID id, String relationshipType, UUID sourceArtifactId, String sourceName,
            UUID targetArtifactId, String targetName, Map<String, Object> attributes
    ) {
    }

    public record GraphResponse(
            List<ArtifactResponse> nodes,
            List<RelationshipResponse> edges,
            boolean truncated,
            @JsonInclude(JsonInclude.Include.NON_NULL)
            AiAgentExecutionRelationshipProjectionService.RuntimeOverlay runtimeOverlay,
            @JsonInclude(JsonInclude.Include.NON_EMPTY)
            List<GraphFindingSummary> findingSummaries
    ) {
        public GraphResponse(List<ArtifactResponse> nodes, List<RelationshipResponse> edges, boolean truncated,
                             AiAgentExecutionRelationshipProjectionService.RuntimeOverlay runtimeOverlay) {
            this(nodes, edges, truncated, runtimeOverlay, List.of());
        }
    }

    public record GraphFindingSummary(
            UUID artifactId, long totalFindings, long openFindings, long deferredFindings,
            long criticalFindings, long highFindings, long mediumFindings, long lowFindings
    ) {
    }

    public record ExposurePathSummary(UUID id,String title,String state,String status) {}
    private List<ExposurePathSummary> readPathSummaries(String value) {
        try { return objectMapper.readValue(value,new TypeReference<List<ExposurePathSummary>>() {}); }
        catch (java.io.IOException error) { throw new IllegalStateException("Invalid exposure path summary",error); }
    }

    public record FindingResponse(
            UUID id, String displayId, String policyId, String policyVersion, UUID artifactId,
            UUID executionId, String subjectType,
            String artifactName, String evidenceSource, String evidenceClass,
            String severity, String status, String title, Map<String, Object> evidence,
            String reviewDisposition, Instant firstObservedAt, Instant lastObservedAt, Instant resolvedAt
            , String closedReason, String findingKind, List<ExposurePathSummary> exposurePaths
    ) {
    }

    public record PolicyResponse(
            String id, String version, String name, String severity, List<String> artifactTypes,
            List<String> requiredResourceFamilies, String description, String remediation,
            Map<String, String> controlMappings, boolean available, boolean enabled,
            long openFindings, long lifetimeFindings, Instant lastEvaluatedAt, double decisionCoverage,
            double decisionCoverageThreshold, String decisionCoverageStatus,
            long evaluatedArtifacts, long noDecisionCount, String lifecycle, String inactiveReason
    ) {
    }

    public record PolicyScopeConditionResponse(String field, String operator, String value) {
    }

    public record PolicyScopeResponse(
            String mode, String conditionLogic, List<PolicyScopeConditionResponse> conditions,
            String updatedBy, Instant updatedAt
    ) {
    }

    public record PolicyExceptionResponse(
            UUID artifactId, String artifactName, String override, String reason, String createdBy, Instant createdAt
    ) {
    }

    public record PolicyParameterValueResponse(
            String key, String label, String type, List<String> options, String defaultValue, String helpText,
            String value
    ) {
    }

    public record PolicyConfigurationResponse(
            PolicyGovernanceResponse governance, PolicyScopeResponse scope, List<PolicyExceptionResponse> exceptions,
            List<PolicyParameterValueResponse> parameters, long matchedArtifactCount, long totalArtifactCount,
            String collectionStatus,String assessmentStatus,int assessedSubjects,int failedPolicies,
            List<AiGridAssessmentService.PolicyFailure> failureSummaries
    ) {
    }

    public record PolicyGovernanceResponse(
            String platformPolicyVersion, String platformLifecycle, String platformOwner,
            String governanceStatus, boolean tenantConfigurable, String platformDefaultSelection,
            String configurationSource, Instant tenantConfigurationUpdatedAt
    ) {
    }

    public record PolicyAssistExplanationResponse(String summary, Instant generatedAt) {
    }

    record CoverageGate(
            double coverage,
            double threshold,
            String status,
            long evaluatedArtifacts,
            long noDecisionCount
    ) {
    }

    public record RunResponse(
            UUID id, String status, int recordsFetched, int recordsFailed,
            Instant startedAt, Instant completedAt, String errorMessage, String collectionStatus,String assessmentStatus,
            int assessedSubjects,int failedPolicies,List<AiGridAssessmentService.PolicyFailure> failureSummaries
    ) {
    }

    public record ScopeResponse(
            UUID id, UUID runId, String accountId, String region, String resourceFamily,
            String scopeKey, String status, int acceptedChunks, int expectedChunks,
            String diagnosticCode, Map<String, Object> diagnostics, Instant startedAt, Instant completedAt
    ) {
    }
}
