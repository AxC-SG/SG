package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.Domain;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.State;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Per-tenant, per-domain authority switch (plan §15.2–15.3, design §8). Transitions: LEGACY→DARK (start dark
 * qualification), DARK→LEGACY (no-go), DARK→CANONICAL (go). CANONICAL is terminal here: after the go decision the
 * automatic rollback window is closed and recovery is source pause plus forward fix.
 *
 * <p>The go decision must quote the {@code reportHash} of a qualification report that passed, so the acceptance is
 * bound to the evidence the approver saw; any change in the evidence invalidates it. Release 1 switches CORE only.
 */
@Service
public class OwnershipCutoverService {

    public record Comparison(long match, long mismatch, long legacyOnly, long canonicalOnly, long bothEmpty) { }

    public record Qualification(String domain, String state, boolean passed, List<String> blockers, Map<String, Long> checks,
                                Comparison comparison, String reportHash) { }

    private final JdbcTemplate jdbc;
    private final OwnershipAuthorityService authority;
    private final AuditEventService audit;
    private final OwnershipEffectiveCacheService cache;

    public OwnershipCutoverService(JdbcTemplate jdbc, OwnershipAuthorityService authority, AuditEventService audit,
                                   OwnershipEffectiveCacheService cache) {
        this.jdbc = jdbc;
        this.authority = authority;
        this.audit = audit;
        this.cache = cache;
    }

    /** Dark reconciliation and impact report (§15.3 step 2). Differences from legacy are reported, not treated as defects. */
    public Qualification qualify(Domain domain) {
        requireCore(domain);
        State state = authority.stateFor(domain);
        Map<String, Long> checks = new LinkedHashMap<>();
        checks.put("unlinkedAssets", count("""
                SELECT count(*) FROM assets WHERE ownership_subject_id IS NULL AND type IN ('APPLICATION','HOST','CONTAINER_IMAGE','CLOUD_RESOURCE')"""));
        checks.put("unlinkedFindings", count("""
                SELECT count(*) FROM findings f JOIN assets a ON a.id = f.asset_id
                 WHERE f.ownership_subject_id IS NULL AND f.finding_kind = 'VULNERABILITY'"""));
        checks.put("queuedResolutions", count("SELECT count(*) FROM ownership_resolution_queue"));
        checks.put("unsweptExpiredClaims", count("SELECT count(*) FROM ownership_claim WHERE status = 'ACTIVE' AND expires_at <= now()"));
        checks.put("staleResolverVersions", count("SELECT count(*) FROM ownership_assignment WHERE resolver_version <> "
                + OwnershipResolver.RESOLVER_VERSION));
        checks.put("inheritanceErrors", count("""
                SELECT count(*) FROM ownership_effective_assignment WHERE resolution IN ('CYCLE','MISSING_PARENT','DEPTH_EXCEEDED')"""));
        checks.put("openProducerAnomalies", count("SELECT count(*) FROM ownership_review_item WHERE state = 'OPEN' AND item_type = 'PRODUCER_ANOMALY'"));
        checks.put("openConflicts", count("SELECT count(*) FROM ownership_review_item WHERE state = 'OPEN' AND item_type = 'CONFLICT'"));
        checks.put("openUnmappedValues", count("SELECT count(*) FROM ownership_review_item WHERE state = 'OPEN' AND item_type = 'UNMAPPED_VALUE'"));
        List<String> gates = new ArrayList<>(List.of("unlinkedAssets", "unlinkedFindings", "queuedResolutions", "unsweptExpiredClaims",
                "staleResolverVersions", "inheritanceErrors", "openProducerAnomalies"));
        if (cache.enabled()) {
            // Filters and coverage read the cache, so the switch waits until it reflects every recorded change.
            checks.put("effectiveCacheBacklog", cache.backlog().total());
            gates.add("effectiveCacheBacklog");
        }

        List<String> blockers = new ArrayList<>();
        if (state != State.DARK) blockers.add("Domain must be DARK to qualify (is " + state + ")");
        for (String gate : gates) {
            if (checks.get(gate) > 0) blockers.add(gate + " must be 0 (is " + checks.get(gate) + ")");
        }
        Comparison comparison = compare();
        String hash = hash(domain, state, checks, comparison);
        return new Qualification(domain.name(), state.name(), blockers.isEmpty(), List.copyOf(blockers), Map.copyOf(checks), comparison, hash);
    }

    /**
     * Moves the domain. {@code reportHash} is required for DARK→CANONICAL and must match a fresh, passing report.
     * The acceptance (who, when) is recorded on the authority row and in the audit log.
     */
    public Qualification transition(Domain domain, State target, String reportHash, String actor) {
        requireCore(domain);
        UUID tenant = TenantContext.getCurrentTenantId();
        State current = authority.stateFor(domain);
        boolean allowed = (current == State.LEGACY && target == State.DARK) || (current == State.DARK && target == State.LEGACY)
                || (current == State.DARK && target == State.CANONICAL);
        if (!allowed) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, current == State.CANONICAL
                    ? "The domain is canonical; the rollback window is closed. Pause sources and forward-fix instead"
                    : "Cannot move " + domain + " from " + current + " to " + target);
        }
        Qualification report = qualify(domain);
        if (target == State.CANONICAL) {
            if (!report.passed()) throw new ResponseStatusException(HttpStatus.CONFLICT, "Qualification has blockers: " + report.blockers());
            if (reportHash == null || !reportHash.equals(report.reportHash())) {
                throw new ResponseStatusException(HttpStatus.CONFLICT, "The qualification evidence changed since it was reviewed; review it again");
            }
        }
        boolean canonical = target == State.CANONICAL;
        TenantContext.runAsPlatform(() -> jdbc.update("""
                INSERT INTO platform.ownership_domain_authority (tenant_id, domain, state, accepted_by, accepted_at, updated_by, updated_at)
                VALUES (?, ?, ?, ?, CASE WHEN ? THEN now() END, ?, now())
                ON CONFLICT (tenant_id, domain) DO UPDATE SET state = EXCLUDED.state, accepted_by = EXCLUDED.accepted_by,
                       accepted_at = EXCLUDED.accepted_at, updated_by = EXCLUDED.updated_by, updated_at = now()
                 WHERE platform.ownership_domain_authority.state = ?
                """, tenant, domain.name(), target.name(), canonical ? actor : null, canonical, actor, current.name()));
        audit.record("ownership.authority.transition", "tenant", tenant.toString(), OwnershipEvents.json(Map.of(
                "domain", domain.name(), "from", current.name(), "to", target.name(), "reportHash", report.reportHash(),
                "passed", report.passed())));
        return qualify(domain);
    }

    /** Legacy owner label (asset owner_team, else support_group) versus canonical effective team name, per asset. */
    private Comparison compare() {
        Map<String, Object> row = jdbc.queryForMap("""
                WITH pairs AS (
                    SELECT lower(btrim(COALESCE(a.owner_team, a.support_group))) AS legacy, lower(t.name) AS canonical,
                           (SELECT array_agg(ta.alias_key) FROM team_alias ta WHERE ta.team_id = t.id) AS aliases
                      FROM assets a
                      LEFT JOIN ownership_effective_assignment e ON e.subject_id = a.ownership_subject_id AND e.ownership_status = 'OWNED'
                      LEFT JOIN team t ON t.id = e.owner_team_id
                )
                SELECT count(*) FILTER (WHERE legacy <> '' AND canonical IS NOT NULL AND (legacy = canonical OR legacy = ANY (aliases))) AS match,
                       count(*) FILTER (WHERE legacy <> '' AND canonical IS NOT NULL AND legacy <> canonical
                                        AND NOT (legacy = ANY (COALESCE(aliases, '{}')))) AS mismatch,
                       count(*) FILTER (WHERE legacy <> '' AND canonical IS NULL) AS legacy_only,
                       count(*) FILTER (WHERE COALESCE(legacy, '') = '' AND canonical IS NOT NULL) AS canonical_only,
                       count(*) FILTER (WHERE COALESCE(legacy, '') = '' AND canonical IS NULL) AS both_empty
                  FROM pairs
                """);
        return new Comparison(num(row.get("match")), num(row.get("mismatch")), num(row.get("legacy_only")),
                num(row.get("canonical_only")), num(row.get("both_empty")));
    }

    private static void requireCore(Domain domain) {
        if (domain != Domain.CORE) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, domain + " switches in a later release; only CORE is switchable in Release 1");
        }
    }

    private long count(String sql) {
        Long value = jdbc.queryForObject(sql, Long.class);
        return value == null ? 0 : value;
    }

    private static String hash(Domain domain, State state, Map<String, Long> checks, Comparison comparison) {
        String material = domain + "|" + state + "|" + new java.util.TreeMap<>(checks) + "|" + comparison;
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(material.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static long num(Object value) {
        return value == null ? 0 : ((Number) value).longValue();
    }
}
