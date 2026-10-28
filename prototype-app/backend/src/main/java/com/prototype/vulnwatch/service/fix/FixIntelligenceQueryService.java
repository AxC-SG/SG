package com.prototype.vulnwatch.service.fix;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FixContextResponse;
import com.prototype.vulnwatch.dto.FixDetailResponse;
import com.prototype.vulnwatch.dto.FixListItemResponse;
import com.prototype.vulnwatch.dto.FixListPageResponse;
import com.prototype.vulnwatch.dto.FixSummaryResponse;
import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * Read side of Fix Intelligence.
 *
 * <p>Runs on the request's tenant connection (tenant schema, forced RLS) and additionally
 * filters every query on {@code tenant_id}, so a query bug cannot widen to another tenant.
 * Another tenant's fix id is indistinguishable from a missing one (404).
 */
@Service
public class FixIntelligenceQueryService {

    static final int MAX_PAGE_SIZE = 200;
    static final int MAX_DETAIL_ASSETS = 500;
    static final Set<String> SEVERITIES = Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE");
    static final Set<String> ECOSYSTEMS = Set.of("WINDOWS", "LINUX", "MACOS", "CROSS_PLATFORM");
    static final Set<String> STATUSES = Set.of("DRAFT", "PROPOSED", "APPROVED", "ACTIVE", "SUPERSEDED", "RETIRED");

    /** Route view to the fix types it shows. */
    static final Map<String, List<String>> VIEW_TYPES = Map.of(
            "all", List.of("PATCH", "UPGRADE", "WORKAROUND", "CONFIGURATION_CHANGE", "EOL_MIGRATION", "COMPENSATING_CONTROL"),
            "patches", List.of("PATCH", "UPGRADE"),
            "workarounds", List.of("WORKAROUND", "CONFIGURATION_CHANGE"),
            "compensating-controls", List.of("COMPENSATING_CONTROL"));

    private static final String COVERAGE = """
            (select count(distinct a.asset_id) from fix_assets a
              where a.fix_id = f.id and a.tenant_id = f.tenant_id
                and a.status not in ('NOT_APPLICABLE', 'SUPERSEDED')) as applicable,
            (select count(distinct a.asset_id) from fix_assets a
              where a.fix_id = f.id and a.tenant_id = f.tenant_id
                and a.status in ('INSTALLED', 'APPLIED')) as remediated
            """;

    private static final String HIGH_PRIORITY = """
            f.severity in ('CRITICAL', 'HIGH')
            and (exists (select 1 from fix_record_cves c join platform.vulnerabilities v on v.external_id = c.cve_id
                          where c.fix_id = f.id and c.tenant_id = f.tenant_id and v.in_kev)
                 or not exists (select 1 from fix_assets a where a.fix_id = f.id and a.tenant_id = f.tenant_id
                                 and a.status in ('INSTALLED', 'APPLIED')))
            """;

    private final NamedParameterJdbcTemplate jdbc;

    public FixIntelligenceQueryService(NamedParameterJdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public record ListFilter(String view, String severity, String ecosystem, String status, String search) {}

    @Transactional(readOnly = true)
    public FixSummaryResponse summary(Tenant tenant, String view) {
        MapSqlParameterSource params = base(tenant, view);
        String where = " where f.tenant_id = :tenantId and f.fix_type in (:types) and f.status <> 'RETIRED' ";
        long total = count("select count(*) from fix_records f" + where, params);
        long critical = count("select count(*) from fix_records f" + where + " and f.severity = 'CRITICAL'", params);
        long highPriority = count("select count(*) from fix_records f" + where + " and " + HIGH_PRIORITY, params);
        List<FixSummaryResponse.Bucket> severity = buckets(
                "select coalesce(f.severity, 'UNKNOWN') as k, count(*) as n from fix_records f" + where + " group by 1", params, total);
        List<FixSummaryResponse.Bucket> ecosystems = buckets(
                "select coalesce(f.ecosystem, 'CROSS_PLATFORM') as k, count(*) as n from fix_records f" + where + " group by 1", params, total);
        return new FixSummaryResponse(total, critical, highPriority, ecosystems.size(), severity, ecosystems);
    }

    @Transactional(readOnly = true)
    public FixListPageResponse list(Tenant tenant, ListFilter filter, int page, int size) {
        int safeSize = Math.min(MAX_PAGE_SIZE, Math.max(1, size));
        int safePage = Math.max(0, page);
        MapSqlParameterSource params = base(tenant, filter.view());
        StringBuilder where = new StringBuilder(" where f.tenant_id = :tenantId and f.fix_type in (:types) ");
        String status = upper(filter.status());
        if (status != null) {
            require(STATUSES, status, "status");
            where.append(" and f.status = :status ");
            params.addValue("status", status);
        } else {
            where.append(" and f.status <> 'RETIRED' ");
        }
        String severity = upper(filter.severity());
        if (severity != null) {
            require(SEVERITIES, severity, "severity");
            where.append(" and f.severity = :severity ");
            params.addValue("severity", severity);
        }
        String ecosystem = upper(filter.ecosystem());
        if (ecosystem != null) {
            require(ECOSYSTEMS, ecosystem, "ecosystem");
            where.append(" and f.ecosystem = :ecosystem ");
            params.addValue("ecosystem", ecosystem);
        }
        if (filter.search() != null && !filter.search().isBlank()) {
            String term = filter.search().trim().toLowerCase(Locale.ROOT);
            if (term.length() > 200) term = term.substring(0, 200);
            params.addValue("search", "%" + term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%");
            where.append("""
                     and (lower(coalesce(f.title, f.summary)) like :search escape '\\'
                          or lower(coalesce(f.external_key, '')) like :search escape '\\'
                          or lower(cast(f.id as varchar)) like :search escape '\\'
                          or exists (select 1 from fix_record_cves c where c.fix_id = f.id and c.tenant_id = f.tenant_id
                                       and lower(c.cve_id) like :search escape '\\'))
                    """);
        }
        long total = count("select count(*) from fix_records f" + where, params);
        params.addValue("limit", safeSize).addValue("offset", (long) safePage * safeSize);
        List<FixListItemResponse> items = jdbc.query("""
                select f.id, f.external_key, coalesce(f.title, f.summary) as title, f.fix_type, f.severity, f.ecosystem,
                       f.status, f.recommendation_source, f.updated_at,
                       array(select distinct p.provider from fix_patch_details p
                              where p.fix_id = f.id and p.tenant_id = f.tenant_id order by 1) as providers,
                       (select count(*) from fix_record_cves c where c.fix_id = f.id and c.tenant_id = f.tenant_id) as cve_count,
                """ + COVERAGE + " from fix_records f" + where + """
                 order by case f.severity when 'CRITICAL' then 0 when 'HIGH' then 1 when 'MEDIUM' then 2
                                          when 'LOW' then 3 else 4 end, f.updated_at desc, f.id
                 limit :limit offset :offset
                """, params, (rs, row) -> listItem(rs));
        int pages = (int) ((total + safeSize - 1) / safeSize);
        return new FixListPageResponse(items, safePage, safeSize, total, pages);
    }

    @Transactional(readOnly = true)
    public FixDetailResponse detail(Tenant tenant, UUID fixId) {
        MapSqlParameterSource params = new MapSqlParameterSource("tenantId", tenant.getId()).addValue("fixId", fixId);
        List<FixDetailResponse> found = jdbc.query("""
                select f.*, cd.control_type, cd.scope_description, cd.verification_method, cd.residual_risk,
                       (select count(*) from fix_assets a where a.fix_id = f.id and a.tenant_id = f.tenant_id) as asset_total,
                """ + COVERAGE + """
                  from fix_records f
                  left join fix_control_details cd on cd.fix_id = f.id and cd.tenant_id = f.tenant_id
                 where f.id = :fixId and f.tenant_id = :tenantId
                """, params, (rs, row) -> detailRow(rs, params));
        if (found.isEmpty()) {
            throw new ResponseStatusException(NOT_FOUND, "Fix not found");
        }
        return found.get(0);
    }

    /** Fixes for a CVE and/or an asset, with that asset's state. Context only. */
    @Transactional(readOnly = true)
    public FixContextResponse context(Tenant tenant, String cveId, UUID assetId) {
        String cve = cveId == null || cveId.isBlank() ? null : cveId.trim().toUpperCase(Locale.ROOT);
        if (cve == null && assetId == null) {
            throw new ResponseStatusException(BAD_REQUEST, "A cveId or assetId is required");
        }
        if (cve != null && !cve.matches("^CVE-\\d{4}-\\d{4,}$")) {
            throw new ResponseStatusException(BAD_REQUEST, "Invalid CVE id");
        }
        MapSqlParameterSource params = new MapSqlParameterSource("tenantId", tenant.getId())
                .addValue("cveId", cve).addValue("assetId", assetId == null ? null : assetId.toString());
        StringBuilder where = new StringBuilder(" where f.tenant_id = :tenantId and f.status not in ('RETIRED', 'DRAFT') ");
        if (cve != null) {
            where.append(" and exists (select 1 from fix_record_cves c where c.fix_id = f.id and c.tenant_id = f.tenant_id and c.cve_id = :cveId) ");
        }
        if (assetId != null) {
            where.append(" and exists (select 1 from fix_assets a where a.fix_id = f.id and a.tenant_id = f.tenant_id and a.asset_id = cast(:assetId as uuid)) ");
        }
        List<FixContextResponse.Item> items = jdbc.query("""
                select f.id, f.external_key, coalesce(f.title, f.summary) as title, f.fix_type, f.status, f.severity,
                       array(select c.cve_id from fix_record_cves c where c.fix_id = f.id and c.tenant_id = f.tenant_id
                              order by c.cve_id limit 20) as cves,
                       st.status as asset_status, st.provider as asset_provider, st.scheduled_at, st.deadline_at, st.installed_at,
                """ + COVERAGE + """
                  from fix_records f
                  left join lateral (
                        select a.status, a.provider, a.scheduled_at, a.deadline_at, a.installed_at
                          from fix_assets a
                         where a.fix_id = f.id and a.tenant_id = f.tenant_id and a.asset_id = cast(:assetId as uuid)
                         order by a.last_reported_at desc limit 1) st on true
                """ + where + """
                 order by case f.severity when 'CRITICAL' then 0 when 'HIGH' then 1 when 'MEDIUM' then 2 else 3 end, f.updated_at desc
                 limit 100
                """, params, (rs, row) -> new FixContextResponse.Item(
                rs.getObject("id", UUID.class),
                displayId(rs.getString("external_key"), rs.getObject("id", UUID.class)),
                rs.getString("title"),
                rs.getString("fix_type"),
                rs.getString("status"),
                rs.getString("severity"),
                strings(rs.getArray("cves")),
                rs.getString("asset_status"),
                rs.getString("asset_provider"),
                instant(rs, "scheduled_at"),
                instant(rs, "deadline_at"),
                instant(rs, "installed_at"),
                coverage(rs.getLong("applicable"), rs.getLong("remediated"))));
        return new FixContextResponse(cve, assetId, items);
    }

    // ── Row mapping ──────────────────────────────────────────────────────────────────────────

    private FixListItemResponse listItem(ResultSet rs) throws SQLException {
        UUID id = rs.getObject("id", UUID.class);
        List<String> providers = strings(rs.getArray("providers"));
        long applicable = rs.getLong("applicable");
        long remediated = rs.getLong("remediated");
        return new FixListItemResponse(
                id,
                displayId(rs.getString("external_key"), id),
                rs.getString("title"),
                rs.getString("fix_type"),
                rs.getString("severity"),
                rs.getString("ecosystem"),
                rs.getString("status"),
                providers.isEmpty() ? List.of(originLabel(rs.getString("recommendation_source"))) : providers,
                applicable,
                remediated,
                coverage(applicable, remediated),
                rs.getLong("cve_count"),
                instant(rs, "updated_at"));
    }

    private FixDetailResponse detailRow(ResultSet rs, MapSqlParameterSource params) throws SQLException {
        UUID id = rs.getObject("id", UUID.class);
        String origin = rs.getString("recommendation_source");
        String fixType = rs.getString("fix_type");
        long applicable = rs.getLong("applicable");
        long remediated = rs.getLong("remediated");
        boolean editable = rs.getBoolean("managed") && "ANALYST".equals(origin)
                && !"RETIRED".equals(rs.getString("status"));
        String controlType = rs.getString("control_type");
        FixDetailResponse.Control control = controlType == null && rs.getString("scope_description") == null
                && rs.getString("verification_method") == null && rs.getString("residual_risk") == null
                ? null
                : new FixDetailResponse.Control(controlType, rs.getString("scope_description"),
                        rs.getString("verification_method"), rs.getString("residual_risk"));
        return new FixDetailResponse(
                id,
                displayId(rs.getString("external_key"), id),
                coalesce(rs.getString("title"), rs.getString("summary")),
                rs.getString("description"),
                fixType,
                rs.getString("severity"),
                rs.getString("ecosystem"),
                rs.getString("status"),
                originLabel(origin),
                editable,
                rs.getString("owner"),
                rs.getString("proposed_by"),
                rs.getString("approved_by"),
                instant(rs, "approved_at"),
                instant(rs, "review_due_at"),
                rs.getString("installation_instructions"),
                rs.getString("rollback_instructions"),
                rs.getString("known_limitations"),
                (Boolean) rs.getObject("requires_reboot"),
                (Integer) rs.getObject("estimated_downtime_minutes"),
                rs.getLong("version"),
                cves(params),
                patchSources(params),
                control,
                applicable,
                remediated,
                coverage(applicable, remediated),
                rs.getLong("asset_total"),
                assets(params),
                instant(rs, "created_at"),
                instant(rs, "updated_at"));
    }

    private List<FixDetailResponse.Cve> cves(MapSqlParameterSource params) {
        return jdbc.query("""
                select c.cve_id, c.source, c.confidence, upper(v.severity) as severity, coalesce(v.in_kev, false) as in_kev
                  from fix_record_cves c
                  left join platform.vulnerabilities v on v.external_id = c.cve_id
                 where c.fix_id = :fixId and c.tenant_id = :tenantId
                 order by c.cve_id
                """, params, (rs, row) -> new FixDetailResponse.Cve(rs.getString("cve_id"), rs.getString("source"),
                rs.getString("confidence"), rs.getString("severity"), rs.getBoolean("in_kev")));
    }

    private List<FixDetailResponse.PatchSource> patchSources(MapSqlParameterSource params) {
        return jdbc.query("""
                select * from fix_patch_details p where p.fix_id = :fixId and p.tenant_id = :tenantId order by p.provider
                """, params, (rs, row) -> new FixDetailResponse.PatchSource(rs.getString("provider"), rs.getString("external_id"),
                rs.getString("kb_article"), rs.getString("bulletin_id"), rs.getString("vendor"), rs.getString("product"),
                rs.getString("classification"), rs.getString("vendor_severity"), instant(rs, "release_date"),
                rs.getBoolean("superseded"), rs.getString("info_url"), instant(rs, "last_seen_at")));
    }

    private List<FixDetailResponse.AssetState> assets(MapSqlParameterSource params) {
        MapSqlParameterSource withLimit = new MapSqlParameterSource(params.getValues()).addValue("limit", MAX_DETAIL_ASSETS);
        return jdbc.query("""
                select a.asset_id, s.name, s.identifier, a.provider, a.status, d.name as deployment_name,
                       a.scheduled_at, a.deadline_at, a.installed_at, a.error_code, a.last_reported_at
                  from fix_assets a
                  join assets s on s.id = a.asset_id
                  left join patch_deployments d on d.id = a.deployment_id and d.tenant_id = a.tenant_id
                 where a.fix_id = :fixId and a.tenant_id = :tenantId
                 order by case a.status when 'MISSING' then 0 when 'FAILED' then 1 when 'SCHEDULED' then 2
                                        when 'IN_PROGRESS' then 3 when 'PENDING_REBOOT' then 4 else 5 end, s.name
                 limit :limit
                """, withLimit, (rs, row) -> new FixDetailResponse.AssetState(rs.getObject("asset_id", UUID.class),
                rs.getString("name"), rs.getString("identifier"), rs.getString("provider"), rs.getString("status"),
                rs.getString("deployment_name"), instant(rs, "scheduled_at"), instant(rs, "deadline_at"),
                instant(rs, "installed_at"), rs.getString("error_code"), instant(rs, "last_reported_at")));
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    private MapSqlParameterSource base(Tenant tenant, String view) {
        String key = view == null || view.isBlank() ? "all" : view.trim().toLowerCase(Locale.ROOT);
        List<String> types = VIEW_TYPES.get(key);
        if (types == null) {
            throw new ResponseStatusException(BAD_REQUEST, "Unknown fix view: " + view);
        }
        return new MapSqlParameterSource("tenantId", tenant.getId()).addValue("types", types);
    }

    private long count(String sql, MapSqlParameterSource params) {
        Long value = jdbc.queryForObject(sql, params, Long.class);
        return value == null ? 0 : value;
    }

    private List<FixSummaryResponse.Bucket> buckets(String sql, MapSqlParameterSource params, long total) {
        List<FixSummaryResponse.Bucket> result = new ArrayList<>(jdbc.query(sql, params,
                (rs, row) -> new FixSummaryResponse.Bucket(rs.getString("k"), rs.getLong("n"), percent(rs.getLong("n"), total))));
        result.sort((a, b) -> Long.compare(b.count(), a.count()));
        return result;
    }

    static int percent(long count, long total) {
        return total <= 0 ? 0 : (int) Math.round(count * 100.0 / total);
    }

    /** Remediated over applicable assets, capped at 100; null when nothing applies. */
    static Integer coverage(long applicable, long remediated) {
        if (applicable <= 0) return null;
        return (int) Math.min(100, Math.round(remediated * 100.0 / applicable));
    }

    static String displayId(String externalKey, UUID id) {
        if (externalKey != null && !externalKey.isBlank()) {
            int colon = externalKey.lastIndexOf(':');
            return colon >= 0 ? externalKey.substring(colon + 1) : externalKey;
        }
        return "FIX-" + id.toString().substring(0, 8).toUpperCase(Locale.ROOT);
    }

    static String originLabel(String origin) {
        if (origin == null) return "Unknown";
        return switch (origin) {
            case "ANALYST" -> "Analyst";
            case "VENDOR_INTELLIGENCE" -> "Vendor";
            case "AI" -> "AI";
            case "REFERENCE" -> "Reference";
            case "PATCH_TOOL" -> "Patch tool";
            default -> origin;
        };
    }

    private static void require(Set<String> allowed, String value, String name) {
        if (!allowed.contains(value)) {
            throw new ResponseStatusException(BAD_REQUEST, "Unknown " + name + ": " + value);
        }
    }

    private static String upper(String value) {
        return value == null || value.isBlank() ? null : value.trim().toUpperCase(Locale.ROOT);
    }

    private static String coalesce(String a, String b) {
        return a != null ? a : b;
    }

    private static List<String> strings(Array array) throws SQLException {
        if (array == null) return List.of();
        Object raw = array.getArray();
        return raw instanceof String[] values ? Arrays.asList(values) : List.of();
    }

    private static Instant instant(ResultSet rs, String column) throws SQLException {
        Timestamp value = rs.getTimestamp(column);
        return value == null ? null : value.toInstant();
    }
}
