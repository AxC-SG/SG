package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.Domain;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.State;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Domain-aware ownership read envelope (plan §7.5, design §8). A row is CANONICAL only when its domain's authority is
 * CANONICAL <em>and</em> the consumer's read wave is enabled for the tenant; otherwise it is
 * LEGACY_PENDING_MIGRATION with the legacy free-text label, never UNOWNED. DARK is never shown to normal readers.
 * Owner names are joined from {@code team} at read time and never stored on assets or findings.
 */
@Component
public class OwnershipReadAdapter {

    public enum Consumer { INVENTORY, FINDINGS, CAMPAIGNS, TICKETS, AI }

    public record Summary(UUID objectId, String authorityDomain, String authorityState, UUID subjectId, UUID ownerTeamId,
                          String ownerTeamName, String ownershipStatus, UUID originSubjectId, UUID assignmentId, String sourceKind,
                          Instant resolvedAt, Boolean stale, Integer inheritanceDepth, String legacyOwnerLabel) { }

    /**
     * {@code refreshing} counts linked rows whose cached result is missing or awaiting refresh; it is always 0 when the
     * cache is off, because the live walk has no propagation delay.
     */
    public record Coverage(String authorityState, long owned, long unowned, long conflict, long unlinked, long refreshing) { }

    public static final int MAX_IDS = 200;

    private final JdbcTemplate jdbc;
    private final OwnershipAuthorityService authority;
    private final OwnershipEffectiveCacheService cache;
    private final Map<Consumer, Set<String>> readWaves;

    public OwnershipReadAdapter(JdbcTemplate jdbc, OwnershipAuthorityService authority, OwnershipEffectiveCacheService cache,
                                @Value("${app.ownership.read-waves.inventory:}") String inventory,
                                @Value("${app.ownership.read-waves.findings:}") String findings) {
        this.jdbc = jdbc;
        this.authority = authority;
        this.cache = cache;
        this.readWaves = Map.of(Consumer.INVENTORY, parse(inventory), Consumer.FINDINGS, parse(findings));
    }

    /** True when {@code consumer} reads canonical ownership for the current tenant. */
    public boolean canonical(Consumer consumer, Domain domain) {
        Set<String> wave = readWaves.getOrDefault(consumer, Set.of());
        UUID tenant = TenantContext.getCurrentTenantId();
        boolean enabled = wave.contains("*") || (tenant != null && wave.contains(tenant.toString()));
        return enabled && authority.stateFor(domain) == State.CANONICAL;
    }

    /** True when any domain is canonical for {@code consumer}; false without a DB call while the wave is off. */
    public boolean anyCanonical(Consumer consumer) {
        for (Domain domain : Domain.values()) {
            if (canonical(consumer, domain)) return true;
        }
        return false;
    }

    /** Domain-aware asset envelope: each row is canonical only when its own asset type's domain is canonical. */
    @Transactional(readOnly = true)
    public List<Summary> forAssets(List<UUID> assetIds) {
        List<UUID> ids = bounded(assetIds);
        if (ids.isEmpty()) return List.of();
        Map<Domain, Boolean> canonicalByDomain = canonicalByDomain(Consumer.INVENTORY);
        List<Summary> rows = jdbc.query("""
                SELECT a.id, a.type, a.ownership_subject_id, e.owner_team_id, t.name, e.ownership_status, e.ownership_origin_subject_id,
                       e.ownership_assignment_id, e.ownership_source_kind, e.ownership_resolved_at, e.ownership_stale, e.inheritance_depth,
                       COALESCE(a.owner_team, a.support_group)
                  FROM assets a
                  LEFT JOIN ownership_effective_assignment e ON e.subject_id = a.ownership_subject_id
                  LEFT JOIN team t ON t.id = e.owner_team_id
                 WHERE a.id = ANY (?::uuid[])
                """, (rs, row) -> assetSummary(rs, canonicalByDomain), array(ids));
        return order(ids, rows);
    }

    /**
     * Every asset's envelope in one statement, for the unpaginated asset list. Empty while no domain is canonical for
     * inventory (callers render legacy values). With the effective cache on it joins the cache, so a row may lag a
     * change by the propagation delay, and a linked asset whose cache row does not exist yet has a null status
     * (still refreshing) rather than UNOWNED; staleness is not cached and is null. Without the cache it walks live.
     */
    @Transactional(readOnly = true)
    public Map<UUID, Summary> forAllAssets() {
        Map<Domain, Boolean> canonicalByDomain = canonicalByDomain(Consumer.INVENTORY);
        if (!canonicalByDomain.containsValue(true)) return Map.of();
        String sql = cache.enabled() ? """
                SELECT a.id, a.type, a.ownership_subject_id, c.owner_team_id, t.name, c.ownership_status, c.origin_subject_id,
                       c.assignment_id, oa.winning_source_kind, oa.resolved_at, NULL::boolean, c.inheritance_depth,
                       COALESCE(a.owner_team, a.support_group)
                  FROM assets a
                  LEFT JOIN ownership_effective_cache c ON c.subject_id = a.ownership_subject_id AND c.role = 'TECHNICAL_OWNER'
                  LEFT JOIN ownership_assignment oa ON oa.id = c.assignment_id
                  LEFT JOIN team t ON t.id = c.owner_team_id
                """ : """
                SELECT a.id, a.type, a.ownership_subject_id, e.owner_team_id, t.name, e.ownership_status, e.ownership_origin_subject_id,
                       e.ownership_assignment_id, e.ownership_source_kind, e.ownership_resolved_at, e.ownership_stale, e.inheritance_depth,
                       COALESCE(a.owner_team, a.support_group)
                  FROM assets a
                  LEFT JOIN ownership_effective_assignment e ON e.subject_id = a.ownership_subject_id
                  LEFT JOIN team t ON t.id = e.owner_team_id
                """;
        Map<UUID, Summary> byId = new LinkedHashMap<>();
        jdbc.query(sql, rs -> {
            Summary summary = assetSummary(rs, canonicalByDomain);
            byId.put(summary.objectId(), summary);
        });
        return byId;
    }

    private Map<Domain, Boolean> canonicalByDomain(Consumer consumer) {
        Map<Domain, Boolean> map = new java.util.EnumMap<>(Domain.class);
        for (Domain domain : Domain.values()) map.put(domain, canonical(consumer, domain));
        return map;
    }

    private static Summary assetSummary(java.sql.ResultSet rs, Map<Domain, Boolean> canonicalByDomain) throws java.sql.SQLException {
        Domain domain = OwnershipAuthorityService.domainFor(rs.getString(2));
        return summary(rs, canonicalByDomain.get(domain), domain.name());
    }

    /**
     * The migration domain that owns a finding kind (plan §15.3). Vulnerability adapter v1 (Release 1) derives a
     * VULNERABILITY finding from its affected asset, so it is CORE; CRYPTO derives through a cryptographic component
     * occurrence (Release 2) and AI findings through AI targets (Release 3), so they stay legacy until those switch.
     */
    public static Domain domainForFindingKind(String findingKind) {
        if ("VULNERABILITY".equals(findingKind)) return Domain.CORE;
        if ("CRYPTO".equals(findingKind)) return Domain.CLOUD_BOM;
        return Domain.AI_GRID;
    }

    /** Domain-aware finding envelope: each row is canonical only when its own kind's domain is canonical. */
    @Transactional(readOnly = true)
    public List<Summary> forFindings(List<UUID> findingIds) {
        List<UUID> ids = bounded(findingIds);
        if (ids.isEmpty()) return List.of();
        Map<Domain, Boolean> canonicalByDomain = canonicalByDomain(Consumer.FINDINGS);
        if (!canonicalByDomain.containsValue(true)) {
            // Nothing canonical yet: skip the effective walk and return the legacy labels only.
            return order(ids, jdbc.query("SELECT id, finding_kind, owner_group FROM findings WHERE id = ANY (?::uuid[])",
                    (rs, row) -> legacy(rs.getObject(1, UUID.class), domainForFindingKind(rs.getString(2)).name(), rs.getString(3)),
                    array(ids)));
        }
        List<Summary> rows = jdbc.query("""
                SELECT f.id, f.finding_kind, f.ownership_subject_id, e.owner_team_id, t.name, e.ownership_status, e.ownership_origin_subject_id,
                       e.ownership_assignment_id, e.ownership_source_kind, e.ownership_resolved_at, e.ownership_stale, e.inheritance_depth,
                       f.owner_group
                  FROM findings f
                  LEFT JOIN ownership_effective_assignment e ON e.subject_id = f.ownership_subject_id
                  LEFT JOIN team t ON t.id = e.owner_team_id
                 WHERE f.id = ANY (?::uuid[])
                """, (rs, row) -> {
                    Domain domain = domainForFindingKind(rs.getString(2));
                    return summary(rs, canonicalByDomain.get(domain), domain.name());
                }, array(ids));
        return order(ids, rows);
    }

    /**
     * Owner-team / status filter for the inventory or findings consumer (stable team IDs only). Returns an empty
     * page while the consumer is not canonical, because legacy rows cannot be filtered by canonical team. An unlinked
     * row counts as UNOWNED. With the effective cache on, a row matches on its cached result, which may lag a change
     * by the propagation delay; a linked row whose cache entry does not exist yet matches no team or status.
     */
    @Transactional(readOnly = true)
    public List<UUID> filter(Consumer consumer, UUID teamId, String status, int limit, UUID after) {
        if (!canonical(consumer, Domain.CORE)) return List.of();
        String table = consumer == Consumer.INVENTORY ? "assets" : "findings";
        // Release 1 filters CORE rows only; later-domain findings are pending migration and never canonical-filterable.
        String openOnly = consumer == Consumer.FINDINGS ? " AND x.status = 'OPEN' AND x.finding_kind = 'VULNERABILITY'"
                : " AND x.type IN ('APPLICATION','HOST')";
        int page = Math.max(1, Math.min(limit, MAX_IDS));
        if (cache.enabled()) {
            // Team filter drives from the cache's team index; status filter from the base table's order.
            String sql = "SELECT x.id FROM " + table + " x LEFT JOIN ownership_effective_cache c"
                    + " ON c.subject_id = x.ownership_subject_id AND c.role = 'TECHNICAL_OWNER'"
                    + " WHERE (?::uuid IS NULL OR c.owner_team_id = ?)"
                    + " AND (?::text IS NULL OR CASE WHEN x.ownership_subject_id IS NULL THEN 'UNOWNED' ELSE c.ownership_status END = ?)"
                    + " AND (?::uuid IS NULL OR x.id > ?)" + openOnly + " ORDER BY x.id LIMIT ?";
            return jdbc.queryForList(sql, UUID.class, teamId, teamId, status, status, after, after, page);
        }
        String sql = "SELECT x.id FROM " + table + " x LEFT JOIN ownership_effective_assignment e ON e.subject_id = x.ownership_subject_id"
                + " WHERE (?::uuid IS NULL OR e.owner_team_id = ?) AND (?::text IS NULL OR COALESCE(e.ownership_status, 'UNOWNED') = ?)"
                + " AND (?::uuid IS NULL OR x.id > ?)" + openOnly + " ORDER BY x.id LIMIT ?";
        return jdbc.queryForList(sql, UUID.class, teamId, teamId, status, status, after, after, page);
    }

    @Transactional(readOnly = true)
    public Coverage coverage(Consumer consumer) {
        boolean canonical = canonical(consumer, Domain.CORE);
        String table = consumer == Consumer.INVENTORY ? "assets" : "findings";
        // Release 1 counts CORE rows only: VULNERABILITY findings, APPLICATION/HOST assets.
        String openOnly = consumer == Consumer.FINDINGS ? " WHERE x.status = 'OPEN' AND x.finding_kind = 'VULNERABILITY'"
                : " WHERE x.type IN ('APPLICATION','HOST')";
        String sql;
        if (cache.enabled()) {
            sql = "SELECT count(*) FILTER (WHERE c.ownership_status = 'OWNED') AS owned,"
                    + " count(*) FILTER (WHERE c.ownership_status = 'UNOWNED') AS unowned,"
                    + " count(*) FILTER (WHERE c.ownership_status = 'CONFLICT') AS conflict,"
                    + " count(*) FILTER (WHERE x.ownership_subject_id IS NULL) AS unlinked,"
                    + " count(*) FILTER (WHERE x.ownership_subject_id IS NOT NULL AND (c.subject_id IS NULL OR c.invalidated_at IS NOT NULL)) AS refreshing"
                    + " FROM " + table + " x LEFT JOIN ownership_effective_cache c"
                    + " ON c.subject_id = x.ownership_subject_id AND c.role = 'TECHNICAL_OWNER'" + openOnly;
        } else {
            sql = "SELECT count(*) FILTER (WHERE e.ownership_status = 'OWNED') AS owned,"
                    + " count(*) FILTER (WHERE x.ownership_subject_id IS NOT NULL AND (e.ownership_status = 'UNOWNED' OR e.ownership_status IS NULL)) AS unowned,"
                    + " count(*) FILTER (WHERE e.ownership_status = 'CONFLICT') AS conflict,"
                    + " count(*) FILTER (WHERE x.ownership_subject_id IS NULL) AS unlinked,"
                    + " 0 AS refreshing"
                    + " FROM " + table + " x LEFT JOIN ownership_effective_assignment e ON e.subject_id = x.ownership_subject_id" + openOnly;
        }
        Map<String, Object> row = jdbc.queryForMap(sql);
        return new Coverage(canonical ? "CANONICAL" : "LEGACY_PENDING_MIGRATION", num(row.get("owned")), num(row.get("unowned")),
                num(row.get("conflict")), num(row.get("unlinked")), num(row.get("refreshing")));
    }

    private static Summary summary(java.sql.ResultSet rs, boolean canonical, String domain) throws java.sql.SQLException {
        UUID id = rs.getObject(1, UUID.class);
        UUID subject = rs.getObject(3, UUID.class);
        if (!canonical) return legacy(id, domain, rs.getString(13));
        Timestamp resolved = rs.getTimestamp(10);
        // Unlinked means no canonical subject, which is UNOWNED; a linked row with no result yet keeps a null status.
        String status = subject == null ? "UNOWNED" : rs.getString(6);
        return new Summary(id, domain, "CANONICAL", subject, rs.getObject(4, UUID.class), rs.getString(5), status,
                rs.getObject(7, UUID.class), rs.getObject(8, UUID.class), rs.getString(9), resolved == null ? null : resolved.toInstant(),
                (Boolean) rs.getObject(11), rs.getObject(12) == null ? null : rs.getInt(12), null);
    }

    private static Summary legacy(UUID id, String domain, String legacyLabel) {
        return new Summary(id, domain, "LEGACY_PENDING_MIGRATION", null, null, null, null, null, null, null, null, null, null, legacyLabel);
    }

    private static List<UUID> bounded(List<UUID> ids) {
        if (ids == null) return List.of();
        if (ids.size() > MAX_IDS) throw new org.springframework.web.server.ResponseStatusException(
                org.springframework.http.HttpStatus.BAD_REQUEST, "At most " + MAX_IDS + " ids per request");
        return ids.stream().distinct().toList();
    }

    private static List<Summary> order(List<UUID> ids, List<Summary> rows) {
        Map<UUID, Summary> byId = new LinkedHashMap<>();
        rows.forEach(r -> byId.put(r.objectId(), r));
        return ids.stream().map(byId::get).filter(java.util.Objects::nonNull).toList();
    }

    private static String array(List<UUID> ids) {
        return "{" + ids.stream().map(UUID::toString).collect(Collectors.joining(",")) + "}";
    }

    private static Set<String> parse(String csv) {
        if (csv == null || csv.isBlank()) return Set.of();
        return Arrays.stream(csv.split(",")).map(String::strip).filter(s -> !s.isEmpty()).collect(Collectors.toUnmodifiableSet());
    }

    private static long num(Object value) {
        return value == null ? 0 : ((Number) value).longValue();
    }
}
