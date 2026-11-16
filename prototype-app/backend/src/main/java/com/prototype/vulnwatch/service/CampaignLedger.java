package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.CampaignDtos.CampaignOwnerBucket;
import com.prototype.vulnwatch.dto.CampaignDtos.OwnerAtAdd;
import com.prototype.vulnwatch.service.CampaignOutcomeClassifier.Outcome;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.Domain;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.State;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Consumer;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * The campaign membership ledger (Phase 0B §4.2–§4.5, §4.8). The only writer of {@code campaign_findings}; every
 * insert is set-based, idempotent ({@code ON CONFLICT DO NOTHING}) and records the owner at add, read live from
 * {@code ownership_effective_assignment} in the inserting transaction and gated by domain authority (never by read
 * wave, never from the effective cache). Nothing updates or deletes a member. Every read here is SQL over the ledger;
 * outcomes come from {@link CampaignOutcomeClassifier#sql}.
 *
 * <p>Callers own the transaction and the tenant context.
 */
@Component
public class CampaignLedger {

    /** §4.2: members materialized in the create transaction; the reconciler adds the rest. */
    public static final int CREATE_BOUND = 5_000;
    /** §4.3: members the reconciler adds per campaign per run. */
    public static final int RECONCILE_BATCH = 1_000;
    /** Findings updated within this window are left for the next run, so a transaction still in flight is not skipped. */
    static final String RECONCILE_LAG = "interval '1 minute'";

    public enum AddSource { CREATE, RECONCILER, MANUAL, BACKFILL }

    public enum Grouping { CURRENT, AT_ADD }

    private static final String NIL_UUID = "00000000-0000-0000-0000-000000000000";
    private static final String EXCEPTED_ELIGIBLE = "'SUPPRESSED','FALSE_POSITIVE','ACCEPTED_RISK'";

    private final JdbcTemplate jdbc;
    private final OwnershipAuthorityService authority;
    private final OwnershipReadAdapter reads;

    public CampaignLedger(JdbcTemplate jdbc, OwnershipAuthorityService authority, OwnershipReadAdapter reads) {
        this.jdbc = jdbc;
        this.authority = authority;
        this.reads = reads;
    }

    // ------------------------------------------------------------------ writes

    /**
     * Adds up to {@code limit} in-scope findings of a CVE campaign (ordered by {@code (updated_at, id)}) and returns
     * how many were added. Findings must be OPEN, or excepted when {@code includeExcepted}.
     */
    public int materializeCve(UUID campaignId, boolean includeExcepted, String actor, int limit) {
        return materializeScope(campaignId, includeExcepted, actor, limit, AddSource.CREATE);
    }

    /**
     * As {@link #materializeCve}, recording how the members arrived. A scope is the campaign's CVEs plus the software a
     * user added to it ({@code campaign_software}); members already in the ledger are skipped.
     */
    public int materializeScope(UUID campaignId, boolean includeExcepted, String actor, int limit, AddSource source) {
        Snapshot snapshot = snapshot();
        String sql = "WITH c AS (SELECT f.id FROM findings f WHERE " + scope("f") + " AND " + eligible("f", includeExcepted)
                + " AND NOT EXISTS (SELECT 1 FROM campaign_findings m WHERE m.campaign_id = ? AND m.finding_id = f.id)"
                + " ORDER BY f.updated_at, f.id LIMIT ?) " + insertFrom("c", snapshot);
        return jdbc.update(sql, campaignId, campaignId, campaignId, limit, campaignId, actor, source.name());
    }

    /** True when an eligible in-scope finding is not yet a member (the create bound was reached). */
    public boolean hasUnmaterialized(UUID campaignId, boolean includeExcepted) {
        return Boolean.TRUE.equals(jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM findings f WHERE " + scope("f") + " AND "
                + eligible("f", includeExcepted) + " AND NOT EXISTS (SELECT 1 FROM campaign_findings m WHERE m.campaign_id = ?"
                + " AND m.finding_id = f.id))", Boolean.class, campaignId, campaignId, campaignId));
    }

    /** Adds the given findings (any status) as members; returns how many were new. Unknown IDs are ignored. */
    public int addFindings(UUID campaignId, List<UUID> findingIds, String actor, AddSource source) {
        if (findingIds.isEmpty()) return 0;
        String sql = "WITH c AS (SELECT f.id FROM findings f WHERE f.id = ANY (?::uuid[])) " + insertFrom("c", snapshot());
        return jdbc.update(sql, array(findingIds), campaignId, actor, source.name());
    }

    public int countExisting(List<UUID> findingIds) {
        if (findingIds.isEmpty()) return 0;
        Integer n = jdbc.queryForObject("SELECT count(*) FROM findings WHERE id = ANY (?::uuid[])", Integer.class, array(findingIds));
        return n == null ? 0 : n;
    }

    public record ReconcileResult(int added, int scanned, boolean caughtUp) { }

    /**
     * One reconciler batch (§4.3): scans the next {@code limit} in-scope findings after the stored watermark, adds the
     * eligible non-members with {@code add_source = 'RECONCILER'} and advances the watermark in the same transaction.
     * A reopened member is already present and is not touched.
     */
    public ReconcileResult reconcileBatch(UUID campaignId, boolean includeExcepted, int limit) {
        Snapshot snapshot = snapshot();
        String sql = "WITH w AS (SELECT COALESCE((reconcile_watermark ->> 'updatedAt')::timestamptz, '-infinity'::timestamptz) AS ts,"
                + " COALESCE((reconcile_watermark ->> 'id')::uuid, '" + NIL_UUID + "'::uuid) AS id FROM campaigns WHERE id = ?),"
                + " b AS (SELECT f.id, f.updated_at FROM findings f, w WHERE " + scope("f")
                + " AND (f.updated_at, f.id) > (w.ts, w.id) AND f.updated_at < now() - " + RECONCILE_LAG
                + " ORDER BY f.updated_at, f.id LIMIT ?),"
                + " c AS (SELECT b.id FROM b JOIN findings f ON f.id = b.id WHERE " + eligible("f", includeExcepted) + "),"
                + " ins AS (" + insertFrom("c", snapshot) + " RETURNING 1),"
                + " last AS (SELECT updated_at, id FROM b ORDER BY updated_at DESC, id DESC LIMIT 1)"
                + " SELECT (SELECT count(*) FROM ins), (SELECT count(*) FROM b), (SELECT updated_at::text FROM last), (SELECT id FROM last)";
        Object[] row = jdbc.queryForObject(sql, (rs, n) -> new Object[] { rs.getInt(1), rs.getInt(2), rs.getString(3), rs.getObject(4, UUID.class) },
                campaignId, campaignId, campaignId, limit, campaignId, "system", AddSource.RECONCILER.name());
        int added = (Integer) row[0];
        int scanned = (Integer) row[1];
        if (row[2] != null) {
            jdbc.update("UPDATE campaigns SET reconcile_watermark = jsonb_build_object('updatedAt', ?::timestamptz, 'id', ?::uuid) WHERE id = ?",
                    row[2], row[3], campaignId);
        }
        return new ReconcileResult(added, scanned, scanned < limit);
    }

    /**
     * Sets the reconciler's starting point after create (§4.3). A materializing campaign continues after its last
     * materialized member, because every in-scope finding before it was either added or not eligible at create. A
     * complete campaign starts after the newest in-scope finding outside the in-flight window.
     */
    public void initializeWatermark(UUID campaignId, boolean materializing) {
        String last = materializing
                ? "SELECT f.updated_at, f.id FROM campaign_findings m JOIN findings f ON f.id = m.finding_id WHERE m.campaign_id = ?"
                : "SELECT f.updated_at, f.id FROM findings f WHERE " + scope("f") + " AND f.updated_at < now() - " + RECONCILE_LAG;
        Object[] args = materializing ? new Object[] { campaignId, campaignId } : new Object[] { campaignId, campaignId, campaignId };
        jdbc.update("UPDATE campaigns SET reconcile_watermark = (SELECT jsonb_build_object('updatedAt', x.updated_at, 'id', x.id) FROM ("
                + last + " ORDER BY f.updated_at DESC, f.id DESC LIMIT 1) x) WHERE id = ?", args);
    }

    /**
     * The result of materializing a grown scope: how many members were added and, when the bound was reached, the
     * {@code (updated_at, id)} of the last finding taken, which is where the reconciler must resume.
     */
    public record Extension(int added, boolean boundReached, Instant lastUpdatedAt, UUID lastId) { }

    /**
     * Adds up to {@code limit} not-yet-member in-scope findings, oldest first, as {@code source} members. Everything in the
     * scope at or before the returned key is a member or ineligible, so a caller that hit the bound moves the reconciler
     * watermark there (see {@link #setWatermark}) rather than rescanning the whole scope.
     */
    public Extension materializeExtension(UUID campaignId, boolean includeExcepted, String actor, int limit, AddSource source) {
        Snapshot snapshot = snapshot();
        String sql = "WITH c AS (SELECT f.id, f.updated_at FROM findings f WHERE " + scope("f") + " AND " + eligible("f", includeExcepted)
                + " AND NOT EXISTS (SELECT 1 FROM campaign_findings m WHERE m.campaign_id = ? AND m.finding_id = f.id)"
                + " ORDER BY f.updated_at, f.id LIMIT ?),"
                + " ins AS (" + insertFrom("c", snapshot) + " RETURNING 1),"
                + " last AS (SELECT updated_at, id FROM c ORDER BY updated_at DESC, id DESC LIMIT 1)"
                + " SELECT (SELECT count(*) FROM ins), (SELECT count(*) FROM c), (SELECT updated_at FROM last), (SELECT id FROM last)";
        return jdbc.queryForObject(sql, (rs, n) -> {
            Timestamp lastAt = rs.getTimestamp(3);
            return new Extension(rs.getInt(1), rs.getInt(2) >= limit, lastAt == null ? null : lastAt.toInstant(), rs.getObject(4, UUID.class));
        }, campaignId, campaignId, campaignId, limit, campaignId, actor, source.name());
    }

    /** Sets the reconciler's resume point; the next batch scans findings after this key. */
    public void setWatermark(UUID campaignId, Instant updatedAt, UUID id) {
        jdbc.update("UPDATE campaigns SET reconcile_watermark = jsonb_build_object('updatedAt', ?::timestamptz, 'id', ?::uuid) WHERE id = ?",
                updatedAt.toString(), id, campaignId);
    }

    /** Number of the given software identities that exist. */
    public int countSoftwareIdentities(List<UUID> ids) {
        if (ids.isEmpty()) return 0;
        Integer n = jdbc.queryForObject("SELECT count(*) FROM platform.software_identities WHERE id = ANY (?::uuid[])", Integer.class, array(ids));
        return n == null ? 0 : n;
    }

    /** Adds software identities to the campaign's scope; returns how many were new. */
    public int addSoftware(UUID campaignId, List<UUID> identityIds, String actor) {
        return jdbc.update("INSERT INTO campaign_software (tenant_id, campaign_id, software_identity_id, added_by)"
                + " SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, si.id, ?"
                + " FROM platform.software_identities si WHERE si.id = ANY (?::uuid[]) ON CONFLICT DO NOTHING",
                campaignId, actor, array(identityIds));
    }

    /** IDs of the software already in the campaign's scope. */
    public List<UUID> softwareIds(UUID campaignId) {
        return jdbc.queryForList("SELECT software_identity_id FROM campaign_software WHERE campaign_id = ?", UUID.class, campaignId);
    }

    public record SoftwareItem(UUID id, String displayName, String vendor, long assetCount, long openFindingCount) { }

    /** The campaign's software scope with how many assets and open member findings each identity accounts for. */
    public List<SoftwareItem> softwareItems(UUID campaignId) {
        return jdbc.query("""
                SELECT si.id, si.display_name, si.vendor,
                       (SELECT count(DISTINCT f.asset_id) FROM campaign_findings cf JOIN findings f ON f.id = cf.finding_id
                          JOIN inventory_components ic ON ic.id = f.component_id
                         WHERE cf.campaign_id = cs.campaign_id AND ic.software_identity_id = si.id) AS assets,
                       (SELECT count(*) FROM campaign_findings cf JOIN findings f ON f.id = cf.finding_id
                          JOIN inventory_components ic ON ic.id = f.component_id
                         WHERE cf.campaign_id = cs.campaign_id AND ic.software_identity_id = si.id AND f.status = 'OPEN') AS open_findings
                  FROM campaign_software cs JOIN platform.software_identities si ON si.id = cs.software_identity_id
                 WHERE cs.campaign_id = ? ORDER BY lower(si.display_name), si.id
                """, (rs, n) -> new SoftwareItem(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getLong(4), rs.getLong(5)), campaignId);
    }

    public void setMembershipState(UUID campaignId, String state) {
        jdbc.update("UPDATE campaigns SET membership_state = ? WHERE id = ?", state, campaignId);
    }

    /** Live owner of one finding, as the §4.7 exception snapshot. */
    public OwnerAtAdd ownerNow(UUID findingId) {
        Snapshot s = snapshot();
        String sql = "SELECT " + s.team + ", " + s.assignment + ", " + s.status + " FROM findings f" + s.join + " WHERE f.id = ?";
        return jdbc.query(sql, rs -> rs.next() ? new OwnerAtAdd(rs.getObject(1, UUID.class), null, rs.getString(3), rs.getObject(2, UUID.class)) : null,
                findingId);
    }

    public boolean isMember(UUID campaignId, UUID findingId) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "SELECT EXISTS (SELECT 1 FROM campaign_findings WHERE campaign_id = ? AND finding_id = ?)", Boolean.class, campaignId, findingId));
    }

    // ------------------------------------------------------------------ reads

    public record Totals(long members, long assets, Map<Outcome, Long> outcomes, long overdueActive) {
        public long count(Outcome outcome) { return outcomes.getOrDefault(outcome, 0L); }
    }

    /** §4.8 counts in SQL: members by outcome, overdue active members and distinct assets. */
    public Totals totals(UUID campaignId) {
        Map<Outcome, Long> outcomes = new EnumMap<>(Outcome.class);
        long[] overdue = { 0 };
        jdbc.query("SELECT m.outcome, count(*), count(*) FILTER (WHERE m.due_at < now()) FROM (" + members() + ") m GROUP BY m.outcome",
                rs -> {
                    Outcome outcome = Outcome.valueOf(rs.getString(1));
                    outcomes.put(outcome, rs.getLong(2));
                    if (CampaignOutcomeClassifier.ACTIVE.contains(outcome)) overdue[0] += rs.getLong(3);
                }, campaignId);
        long members = outcomes.values().stream().mapToLong(Long::longValue).sum();
        Long assets = jdbc.queryForObject("SELECT count(DISTINCT f.asset_id) FROM campaign_findings cf JOIN findings f ON f.id = cf.finding_id"
                + " WHERE cf.campaign_id = ?", Long.class, campaignId);
        return new Totals(members, assets == null ? 0 : assets, outcomes, overdue[0]);
    }

    public static Map<String, Long> outcomeMap(Map<Outcome, Long> counts) {
        Map<String, Long> map = new LinkedHashMap<>();
        for (Outcome outcome : Outcome.values()) map.put(outcome.name(), counts.getOrDefault(outcome, 0L));
        return map;
    }

    /**
     * Owner buckets (§4.5) by stable team ID plus UNOWNED, CONFLICT, PENDING_MIGRATION and, for owner-at-add only,
     * NOT_RECORDED. Current grouping reads under {@link Consumer#CAMPAIGNS}: with that read wave off every member is
     * PENDING_MIGRATION and no ownership query runs.
     */
    public List<CampaignOwnerBucket> buckets(UUID campaignId, Grouping grouping) {
        Bucket b = bucket(grouping);
        Map<String, BucketAcc> byKey = new LinkedHashMap<>();
        jdbc.query("SELECT m.bucket, m.bucket_team, t.name, m.outcome, count(*) FROM (" + members(b) + ") m"
                + " LEFT JOIN team t ON t.id = m.bucket_team GROUP BY m.bucket, m.bucket_team, t.name, m.outcome"
                + " ORDER BY count(*) DESC", rs -> {
                    String key = rs.getString(1) + "|" + rs.getString(2);
                    BucketAcc acc = byKey.computeIfAbsent(key, k -> {
                        try { return new BucketAcc(rs.getString(1), rs.getObject(2, UUID.class), rs.getString(3)); }
                        catch (SQLException e) { throw new IllegalStateException(e); }
                    });
                    acc.outcomes.merge(Outcome.valueOf(rs.getString(4)), rs.getLong(5), Long::sum);
                }, campaignId);
        return byKey.values().stream().map(BucketAcc::toBucket)
                .sorted((x, y) -> Long.compare(y.members(), x.members())).toList();
    }

    public record MemberRow(UUID findingId, String displayId, String title, String findingKind, String severity, String status,
                            String closedReason, String outcome, Instant suppressedUntil, Instant dueAt, UUID assetId, String assetName,
                            String assetIdentifier, String environment, String packageName, String cveId, String incidentId,
                            Instant addedAt, String addedBy, String addSource, OwnerAtAdd ownerAtAdd, String campaignExceptionStatus) { }

    public record MemberFilter(List<Outcome> outcomes, boolean includeHidden, Grouping grouping, String bucket, UUID teamId) {
        public static MemberFilter all() { return new MemberFilter(List.of(), true, Grouping.CURRENT, null, null); }
    }

    /** Cursor-paged members ordered by {@code (added_at, finding_id)} (§4.5). */
    public List<MemberRow> page(UUID campaignId, MemberFilter filter, Instant afterAddedAt, UUID afterFindingId, int limit) {
        Bucket b = bucket(filter.grouping());
        List<Object> args = new ArrayList<>();
        args.add(campaignId);
        StringBuilder where = new StringBuilder(" WHERE 1 = 1");
        if (afterAddedAt != null) {
            where.append(" AND (m.added_at, m.finding_id) > (?, ?)");
            args.add(Timestamp.from(afterAddedAt));
            args.add(afterFindingId);
        }
        appendFilter(where, args, filter);
        args.add(limit);
        return jdbc.query("SELECT m.* FROM (" + members(b) + ") m" + where + " ORDER BY m.added_at, m.finding_id LIMIT ?",
                (rs, n) -> memberRow(rs), args.toArray());
    }

    /** The most recently updated members, for the detail page's capped finding and evidence rows. */
    public List<MemberRow> recent(UUID campaignId, int limit) {
        return jdbc.query("SELECT m.* FROM (" + members() + ") m ORDER BY m.updated_at DESC, m.finding_id LIMIT ?",
                (rs, n) -> memberRow(rs), campaignId, limit);
    }

    /** One campaign's progress over a kind of finding: outcomes, overdue active members and current owner buckets. */
    public record KindProgress(UUID campaignId, Map<Outcome, Long> outcomes, long overdueActive, List<CampaignOwnerBucket> owners) {
        public long members() { return outcomes.values().stream().mapToLong(Long::longValue).sum(); }
        public long count(Outcome outcome) { return outcomes.getOrDefault(outcome, 0L); }
    }

    /**
     * Per-campaign progress of the members matching {@code findingFilter}, a trusted SQL fragment over {@code f}, for
     * example {@code f.finding_kind = 'CRYPTO'} (Phase 0B §4.8, §4.12). Counts use the shared outcome rules; owners are
     * the current owner buckets, so with the campaigns read wave off every member is PENDING_MIGRATION.
     */
    public Map<UUID, KindProgress> progressByCampaign(String findingFilter) {
        Bucket b = bucket(Grouping.CURRENT);
        Map<UUID, Map<Outcome, Long>> outcomes = new LinkedHashMap<>();
        Map<UUID, Long> overdue = new LinkedHashMap<>();
        Map<UUID, Map<String, BucketAcc>> owners = new LinkedHashMap<>();
        jdbc.query("SELECT m.campaign_id, m.bucket, m.bucket_team, t.name, m.outcome, count(*), count(*) FILTER (WHERE m.due_at < now())"
                + " FROM (" + members(b, findingFilter) + ") m LEFT JOIN team t ON t.id = m.bucket_team"
                + " GROUP BY m.campaign_id, m.bucket, m.bucket_team, t.name, m.outcome", rs -> {
                    UUID campaign = rs.getObject(1, UUID.class);
                    Outcome outcome = Outcome.valueOf(rs.getString(5));
                    long count = rs.getLong(6);
                    outcomes.computeIfAbsent(campaign, k -> new EnumMap<>(Outcome.class)).merge(outcome, count, Long::sum);
                    if (CampaignOutcomeClassifier.ACTIVE.contains(outcome)) overdue.merge(campaign, rs.getLong(7), Long::sum);
                    owners.computeIfAbsent(campaign, k -> new LinkedHashMap<>())
                            .computeIfAbsent(rs.getString(2) + "|" + rs.getString(3), k -> {
                                try { return new BucketAcc(rs.getString(2), rs.getObject(3, UUID.class), rs.getString(4)); }
                                catch (SQLException e) { throw new IllegalStateException(e); }
                            }).outcomes.merge(outcome, count, Long::sum);
                });
        Map<UUID, KindProgress> result = new LinkedHashMap<>();
        outcomes.forEach((campaign, counts) -> result.put(campaign, new KindProgress(campaign, counts, overdue.getOrDefault(campaign, 0L),
                owners.get(campaign).values().stream().map(BucketAcc::toBucket)
                        .sorted((x, y) -> Long.compare(y.members(), x.members())).toList())));
        return result;
    }

    public record AssetRow(UUID assetId, String name, String identifier, String environment, long active, long remediated, long members) { }

    /** Members grouped by asset ID (§4.5); never reads {@code assets.support_group}. */
    public List<AssetRow> assets(UUID campaignId, int limit) {
        return jdbc.query("SELECT a.id, a.name, a.identifier, a.environment,"
                        + " count(*) FILTER (WHERE m.outcome IN ('OPEN','REOPENED')), count(*) FILTER (WHERE m.outcome = 'REMEDIATED'), count(*)"
                        + " FROM (" + members() + ") m JOIN assets a ON a.id = m.asset_id"
                        + " GROUP BY a.id, a.name, a.identifier, a.environment ORDER BY 5 DESC, 7 DESC, a.name LIMIT ?",
                (rs, n) -> new AssetRow(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4), rs.getLong(5),
                        rs.getLong(6), rs.getLong(7)), campaignId, limit);
    }

    // ------------------------------------------------------------------ preview

    public record PreviewCounts(long eligible, Map<String, Long> excluded, List<CampaignOwnerBucket> distribution, List<UUID> ownerTeams) { }

    /**
     * §4.2 preview: what a create would add (by owner at add, as the snapshot would record it) and what it would
     * exclude. Writes nothing. {@code cveIds} are vulnerability IDs; {@code findingIds} select a finding-scoped campaign.
     */
    public PreviewCounts preview(List<UUID> vulnerabilityIds, List<UUID> findingIds, boolean includeExcepted) {
        Snapshot s = snapshot();
        boolean cve = findingIds == null;
        String scope = cve ? "f.vulnerability_id = ANY (?::uuid[])" : "f.id = ANY (?::uuid[])";
        String outcome = CampaignOutcomeClassifier.sql("f.status", "f.closed_reason", "false", "false");
        String eligible = cve ? "(x.outcome = 'OPEN'" + (includeExcepted ? " OR x.outcome IN (" + EXCEPTED_ELIGIBLE + ")" : "") + ")" : "true";
        Map<String, Long> excluded = new LinkedHashMap<>();
        Map<String, BucketAcc> buckets = new LinkedHashMap<>();
        long[] total = { 0 };
        jdbc.query("SELECT o.eligible, o.outcome, o.bucket, o.team, t.name, count(*) FROM ("
                + "SELECT x.*, " + eligible + " AS eligible FROM (SELECT " + outcome + " AS outcome, "
                + snapshotBucket(s) + " AS bucket, " + s.team + " AS team FROM findings f" + s.join + " WHERE " + scope + ") x) o"
                + " LEFT JOIN team t ON t.id = o.team GROUP BY o.eligible, o.outcome, o.bucket, o.team, t.name", rs -> {
                    long n = rs.getLong(6);
                    if (!rs.getBoolean(1)) {
                        String reason = rs.getString(2);
                        excluded.merge(Outcome.REMEDIATED.name().equals(reason) || Outcome.CLOSED_OTHER.name().equals(reason) ? "CLOSED" : reason,
                                n, Long::sum);
                        return;
                    }
                    total[0] += n;
                    String key = rs.getString(3) + "|" + rs.getString(4);
                    BucketAcc acc = buckets.computeIfAbsent(key, k -> {
                        try { return new BucketAcc(rs.getString(3), rs.getObject(4, UUID.class), rs.getString(5)); }
                        catch (SQLException e) { throw new IllegalStateException(e); }
                    });
                    acc.outcomes.merge(Outcome.valueOf(rs.getString(2)), n, Long::sum);
                }, array(cve ? vulnerabilityIds : findingIds));
        List<CampaignOwnerBucket> distribution = buckets.values().stream().map(BucketAcc::toBucket)
                .sorted((x, y) -> Long.compare(y.members(), x.members())).toList();
        List<UUID> teams = distribution.stream().map(CampaignOwnerBucket::teamId).filter(java.util.Objects::nonNull).toList();
        return new PreviewCounts(total[0], excluded, distribution, teams);
    }

    // ------------------------------------------------------------------ SQL building

    /** Owner-at-add expressions over findings {@code f}, gated by each finding kind's domain authority (§4.4). */
    private record Snapshot(String team, String assignment, String status, String join) { }

    private Snapshot snapshot() {
        Map<Domain, Boolean> canonical = new EnumMap<>(Domain.class);
        for (Domain domain : Domain.values()) canonical.put(domain, authority.stateFor(domain) == State.CANONICAL);
        if (!canonical.containsValue(true)) {
            return new Snapshot("NULL::uuid", "NULL::uuid", "'LEGACY_PENDING_MIGRATION'", "");
        }
        String canon = canonicalKind(canonical, "f.finding_kind");
        return new Snapshot(
                "CASE WHEN " + canon + " AND f.ownership_subject_id IS NOT NULL AND e.ownership_status = 'OWNED' THEN e.owner_team_id END",
                "CASE WHEN " + canon + " AND f.ownership_subject_id IS NOT NULL THEN e.ownership_assignment_id END",
                "CASE WHEN " + canon + " THEN (CASE WHEN f.ownership_subject_id IS NULL THEN 'UNOWNED' ELSE COALESCE(e.ownership_status, 'UNOWNED') END)"
                        + " ELSE 'LEGACY_PENDING_MIGRATION' END",
                " LEFT JOIN ownership_effective_assignment e ON e.subject_id = f.ownership_subject_id");
    }

    private static String snapshotBucket(Snapshot s) {
        return "(CASE (" + s.status + ") WHEN 'OWNED' THEN 'TEAM' WHEN 'LEGACY_PENDING_MIGRATION' THEN 'PENDING_MIGRATION' ELSE (" + s.status + ") END)";
    }

    /** {@code INSERT … SELECT} over a CTE {@code cte(id)}; binds campaign ID, actor and add source. */
    private static String insertFrom(String cte, Snapshot s) {
        // tenant_id comes from the session, never the column default (schema repair copies defaults from tenant_default).
        return "INSERT INTO campaign_findings (tenant_id, campaign_id, finding_id, added_by, add_source, owner_team_id_at_add,"
                + " ownership_assignment_id_at_add, ownership_status_at_add)"
                + " SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, f.id, ?, ?, " + s.team + ", " + s.assignment + ", " + s.status
                + " FROM " + cte + " JOIN findings f ON f.id = " + cte + ".id" + s.join
                + " ON CONFLICT DO NOTHING";
    }

    /** The scope of a CVE campaign: findings of its CVEs, or on components of the software added to it. Binds the campaign twice. */
    private static String scope(String f) {
        return "(" + f + ".vulnerability_id IN (SELECT cv.vulnerability_id FROM campaign_vulnerabilities cv WHERE cv.campaign_id = ?)"
                + " OR " + f + ".component_id IN (SELECT ic.id FROM inventory_components ic"
                + " JOIN campaign_software cs ON cs.software_identity_id = ic.software_identity_id WHERE cs.campaign_id = ?))";
    }

    /** OPEN, plus suppressed, false-positive and accepted-risk findings when {@code includeExcepted} (§4.2). */
    private static String eligible(String f, boolean includeExcepted) {
        String outcome = CampaignOutcomeClassifier.sql(f + ".status", f + ".closed_reason", "false", "false");
        return includeExcepted ? outcome + " IN ('OPEN'," + EXCEPTED_ELIGIBLE + ")" : f + ".status = 'OPEN'";
    }

    private static String canonicalKind(Map<Domain, Boolean> canonical, String kind) {
        return "(CASE " + kind + " WHEN 'VULNERABILITY' THEN " + canonical.get(Domain.CORE) + " WHEN 'CRYPTO' THEN "
                + canonical.get(Domain.CLOUD_BOM) + " ELSE " + canonical.get(Domain.AI_GRID) + " END)";
    }

    private record Bucket(String bucket, String team, String join) { }

    private Bucket bucket(Grouping grouping) {
        if (grouping == Grouping.AT_ADD) {
            return new Bucket("CASE WHEN cf.ownership_status_at_add IS NULL THEN 'NOT_RECORDED'"
                    + " WHEN cf.ownership_status_at_add = 'OWNED' THEN 'TEAM'"
                    + " WHEN cf.ownership_status_at_add = 'LEGACY_PENDING_MIGRATION' THEN 'PENDING_MIGRATION'"
                    + " ELSE cf.ownership_status_at_add END", "cf.owner_team_id_at_add", "");
        }
        Map<Domain, Boolean> canonical = reads.canonicalDomains(Consumer.CAMPAIGNS);
        if (!canonical.containsValue(true)) return new Bucket("'PENDING_MIGRATION'", "NULL::uuid", "");
        String canon = canonicalKind(canonical, "f.finding_kind");
        return new Bucket("CASE WHEN NOT " + canon + " THEN 'PENDING_MIGRATION' WHEN f.ownership_subject_id IS NULL THEN 'UNOWNED'"
                + " WHEN e.ownership_status = 'OWNED' THEN 'TEAM' ELSE COALESCE(e.ownership_status, 'UNOWNED') END",
                "CASE WHEN " + canon + " AND f.ownership_subject_id IS NOT NULL AND e.ownership_status = 'OWNED' THEN e.owner_team_id END",
                " LEFT JOIN ownership_effective_assignment e ON e.subject_id = f.ownership_subject_id");
    }

    private String members() {
        return members(new Bucket("NULL::text", "NULL::uuid", ""));
    }

    /** One row per member of campaign {@code ?} with its outcome and the chosen bucket. */
    private static String members(Bucket b) {
        return members(b, "cf.campaign_id = ?");
    }

    /**
     * One row per member matching {@code where} (a trusted SQL fragment over {@code cf} and {@code f}, never request
     * input) with its outcome and the chosen bucket.
     */
    private static String members(Bucket b, String where) {
        String excepted = "EXISTS (SELECT 1 FROM campaign_exceptions x WHERE x.campaign_id = cf.campaign_id AND x.finding_id = cf.finding_id"
                + " AND x.status = 'APPROVED')";
        String reopened = "EXISTS (SELECT 1 FROM finding_events ev WHERE ev.finding_id = cf.finding_id AND ev.created_at > cf.added_at"
                + " AND (ev.event_type LIKE '%REOPEN%' OR (ev.event_type = 'STATUS_CHANGED' AND ev.details_json ->> 'to' = 'OPEN'"
                + " AND COALESCE(ev.details_json ->> 'from', 'OPEN') <> 'OPEN')))";
        return "SELECT cf.campaign_id, cf.finding_id, f.display_id, f.title, f.finding_kind, COALESCE(f.severity_override, v.severity) AS severity,"
                + " f.status, f.closed_reason, " + CampaignOutcomeClassifier.sql("f.status", "f.closed_reason", excepted, reopened) + " AS outcome,"
                + " f.suppressed_until, f.due_at, f.asset_id, a.name AS asset_name, a.identifier AS asset_identifier, a.environment,"
                + " ic.package_name, v.external_id AS cve_id, f.incident_id, cf.added_at, cf.added_by, cf.add_source,"
                + " cf.owner_team_id_at_add, ta.name AS team_at_add_name, cf.ownership_status_at_add, cf.ownership_assignment_id_at_add,"
                + " (SELECT x.status FROM campaign_exceptions x WHERE x.campaign_id = cf.campaign_id AND x.finding_id = cf.finding_id"
                + " ORDER BY x.requested_at DESC LIMIT 1) AS exception_status, f.updated_at,"
                + " " + b.bucket + " AS bucket, " + b.team + " AS bucket_team"
                + " FROM campaign_findings cf JOIN findings f ON f.id = cf.finding_id"
                + " LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id"
                + " LEFT JOIN assets a ON a.id = f.asset_id"
                + " LEFT JOIN inventory_components ic ON ic.id = f.component_id"
                + " LEFT JOIN team ta ON ta.id = cf.owner_team_id_at_add" + b.join
                + " WHERE " + where;
    }

    private static void appendFilter(StringBuilder where, List<Object> args, MemberFilter filter) {
        if (!filter.outcomes().isEmpty()) {
            where.append(" AND m.outcome IN (").append(filter.outcomes().stream().map(o -> "'" + o.name() + "'").collect(Collectors.joining(","))).append(")");
        } else if (!filter.includeHidden()) {
            where.append(" AND m.outcome NOT IN (" + EXCEPTED_ELIGIBLE + ")");
        }
        if (filter.teamId() != null) {
            where.append(" AND m.bucket = 'TEAM' AND m.bucket_team = ?");
            args.add(filter.teamId());
        } else if (filter.bucket() != null) {
            where.append(" AND m.bucket = ?");
            args.add(filter.bucket());
        }
    }

    private static MemberRow memberRow(ResultSet rs) throws SQLException {
        return new MemberRow(rs.getObject("finding_id", UUID.class), rs.getString("display_id"), rs.getString("title"),
                rs.getString("finding_kind"), rs.getString("severity"), rs.getString("status"), rs.getString("closed_reason"),
                rs.getString("outcome"), instant(rs.getTimestamp("suppressed_until")), instant(rs.getTimestamp("due_at")),
                rs.getObject("asset_id", UUID.class), rs.getString("asset_name"), rs.getString("asset_identifier"), rs.getString("environment"),
                rs.getString("package_name"), rs.getString("cve_id"), rs.getString("incident_id"), instant(rs.getTimestamp("added_at")),
                rs.getString("added_by"), rs.getString("add_source"),
                new OwnerAtAdd(rs.getObject("owner_team_id_at_add", UUID.class), rs.getString("team_at_add_name"),
                        rs.getString("ownership_status_at_add"), rs.getObject("ownership_assignment_id_at_add", UUID.class)),
                rs.getString("exception_status"));
    }

    private static final class BucketAcc {
        final String bucket;
        final UUID teamId;
        final String teamName;
        final Map<Outcome, Long> outcomes = new EnumMap<>(Outcome.class);

        BucketAcc(String bucket, UUID teamId, String teamName) {
            this.bucket = bucket;
            this.teamId = teamId;
            this.teamName = teamName;
        }

        CampaignOwnerBucket toBucket() {
            long members = outcomes.values().stream().mapToLong(Long::longValue).sum();
            long active = outcomes.entrySet().stream().filter(e -> CampaignOutcomeClassifier.ACTIVE.contains(e.getKey()))
                    .mapToLong(Map.Entry::getValue).sum();
            return new CampaignOwnerBucket(bucket, teamId, teamName, members, active, outcomeMap(outcomes));
        }
    }

    private static Instant instant(Timestamp value) {
        return value == null ? null : value.toInstant();
    }

    private static String array(List<UUID> ids) {
        return "{" + ids.stream().map(UUID::toString).collect(Collectors.joining(",")) + "}";
    }
}
