package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.service.TenantWorkRunner;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * ServiceNow CMDB ownership producer (plan §6.4, §6.8; design §5–6). Runs after a successful CMDB sync and reads
 * the CIs that sync just wrote, so it never needs its own ServiceNow credentials. For each CI it emits a SERVICENOW
 * claim from the approved {@code support_group} field (and {@code department} when enabled), resolved only by exact
 * team name or alias. Unmapped values become review items and never create teams.
 *
 * <p>Two passes: a read-only plan counts changes; if a run would end or change more than the anomaly threshold of
 * this source's active claims it is paused with a review item and writes nothing. Absent CIs end their claims only
 * after a complete scan. Unchanged claims are re-observed (timestamps only) so they cause no assignment writes.
 *
 * <p>Only ServiceNow CIs are read. {@code cis} has no source column, and the AWS, GCP, Azure, SCCM and patch syncs
 * also write rows with {@code last_cmdb_sync_at}, so a scan by time alone would count their CIs during an overlapping
 * window (contract 0B §2.10). Their {@code sys_id}s are ARNs, resource names, numeric IDs or prefixed keys; a
 * ServiceNow {@code sys_id} is always 32 hex characters.
 */
@Component
public class ServiceNowOwnershipProducer {

    public record Result(int scanned, int created, int reobserved, int changed, int unmapped, int ended, boolean paused, String pauseReason) { }

    static final String PRODUCER_VERSION = "servicenow-cmdb-1";
    static final String SOURCE = "SERVICENOW";
    private static final Logger LOG = LoggerFactory.getLogger(ServiceNowOwnershipProducer.class);
    private static final int PAGE = 500;

    private record Ci(String sysId, UUID assetId, String supportGroup, String supportGroupSysId, String department, String ownerEmail) { }

    private record Desired(Ci ci, String field, String value) {
        String sourceRef() {
            return "servicenow:cmdb_ci:" + ci.sysId() + ":" + field;
        }
    }

    private enum Action { CREATE, REOBSERVE, CHANGE, UNMAPPED, END }

    private record Planned(Action action, Desired desired, UUID teamId, UUID existingClaimId) { }

    private final JdbcTemplate jdbc;
    private final TenantWorkRunner runner;
    private final TeamNamespaceService teams;
    private final OwnershipClaimService claims;
    private final OwnershipReviewService reviews;
    private final InventorySubjectAdapter subjects;
    private final DirectoryService directory;
    private final OwnershipAuthorityService authority;
    private final TenantDataCipher cipher;
    private final Clock clock;
    private final boolean departmentClaims;
    private final Duration syncInterval;
    private final GroupMappingResolver mappings;

    public ServiceNowOwnershipProducer(JdbcTemplate jdbc, TenantWorkRunner runner, TeamNamespaceService teams, OwnershipClaimService claims,
                                       OwnershipReviewService reviews, InventorySubjectAdapter subjects, DirectoryService directory,
                                       OwnershipAuthorityService authority, TenantDataCipher cipher, ObjectProvider<Clock> clock,
                                       GroupMappingResolver mappings,
                                       @Value("${app.ownership.servicenow.department-claims:false}") boolean departmentClaims,
                                       @Value("${app.ownership.servicenow.sync-interval:PT24H}") Duration syncInterval) {
        this.mappings = mappings;
        this.jdbc = jdbc;
        this.runner = runner;
        this.teams = teams;
        this.claims = claims;
        this.reviews = reviews;
        this.subjects = subjects;
        this.directory = directory;
        this.authority = authority;
        this.cipher = cipher;
        this.clock = clock.getIfAvailable(Clock::systemUTC);
        this.departmentClaims = departmentClaims;
        this.syncInterval = OwnershipSourcePolicy.requireValidInterval(syncInterval);
    }

    /** Called by the CMDB sync after ingestion succeeded. Never throws: a producer failure must not fail inventory sync. */
    public Optional<Result> publishAfterSync(UUID tenantId, Instant runStartedAt) {
        try {
            return Optional.of(publish(tenantId, runStartedAt, true, false));
        } catch (RuntimeException ex) {
            LOG.warn("ServiceNow ownership producer failed for tenant {}: {}", tenantId, ex.getMessage(), ex);
            return Optional.empty();
        }
    }

    /**
     * @param runStartedAt   CIs with {@code last_cmdb_sync_at} at or after this instant were seen by the run
     * @param completeScan   true only when the run read every approved CI; enables ending claims of absent CIs
     * @param allowAnomaly   admin override after reviewing a paused run
     */
    public Result publish(UUID tenantId, Instant runStartedAt, boolean completeScan, boolean allowAnomaly) {
        boolean legacy = runner.runScoped(tenantId, () -> !authority.producersMayPublish(OwnershipAuthorityService.Domain.CORE));
        if (legacy) return new Result(0, 0, 0, 0, 0, 0, true, "DOMAIN_LEGACY");
        boolean paused = runner.runScoped(tenantId, () -> claims.sourcePaused(SOURCE));
        if (paused) return new Result(0, 0, 0, 0, 0, 0, true, "SOURCE_PAUSED");

        // Pass 1: read-only plan of every change, for the anomaly gate.
        String instance = runner.runScoped(tenantId, mappings::cmdbInstance);
        List<Planned> plan = new ArrayList<>();
        int[] scanned = {0};
        forEachPage(tenantId, runStartedAt, page -> runner.runScoped(tenantId, () -> {
            scanned[0] += page.size();
            for (Ci ci : page) plan.addAll(planCi(ci, instance));
            return null;
        }));
        List<UUID> absent = completeScan ? runner.runScoped(tenantId, () -> absentClaims(runStartedAt)) : List.of();
        int active = runner.runScoped(tenantId, () -> jdbc.queryForObject(
                "SELECT count(*) FROM ownership_claim WHERE source_kind = ? AND status = 'ACTIVE'", Integer.class, SOURCE));
        long destructive = plan.stream().filter(p -> p.action() == Action.CHANGE || p.action() == Action.END).count() + absent.size();
        if (!allowAnomaly && OwnershipSourcePolicy.anomalous(destructive, active)) {
            runner.runScoped(tenantId, () -> reviews.raise("PRODUCER_ANOMALY", "PRODUCER_ANOMALY|" + SOURCE, null, SOURCE,
                    Map.of("activeClaims", active, "wouldChangeOrEnd", destructive,
                            "minChanges", OwnershipSourcePolicy.ANOMALY_MIN_CHANGES,
                            "fraction", OwnershipSourcePolicy.ANOMALY_FRACTION,
                            "absoluteChanges", OwnershipSourcePolicy.ANOMALY_ABSOLUTE_CHANGES)));
            return new Result(scanned[0], 0, 0, 0, 0, 0, true, "ANOMALY");
        }

        // Pass 2: apply in bounded batches, one transaction each.
        int[] counts = apply(tenantId, plan);
        for (int from = 0; from < absent.size(); from += PAGE) {
            List<UUID> batch = absent.subList(from, Math.min(absent.size(), from + PAGE));
            runner.runScoped(tenantId, () -> claims.endAbsent(batch, "servicenow-producer"));
        }
        return new Result(scanned[0], counts[Action.CREATE.ordinal()], counts[Action.REOBSERVE.ordinal()], counts[Action.CHANGE.ordinal()],
                counts[Action.UNMAPPED.ordinal()], counts[Action.END.ordinal()] + absent.size(), false, null);
    }

    /**
     * Re-evaluates the named CIs after an admin confirmed a group-to-team mapping change (§1.8), so their claims follow
     * the mapping without waiting for the next CMDB sync. The admin's impact confirmation stands in for the anomaly
     * gate. Ends no claims: a CI whose group no longer maps keeps its claim until the value maps, expires or is cleared,
     * as with any unmapped value.
     */
    public Result republish(UUID tenantId, List<String> sysIds) {
        boolean legacy = runner.runScoped(tenantId, () -> !authority.producersMayPublish(OwnershipAuthorityService.Domain.CORE));
        if (legacy) return new Result(0, 0, 0, 0, 0, 0, true, "DOMAIN_LEGACY");
        boolean paused = runner.runScoped(tenantId, () -> claims.sourcePaused(SOURCE));
        if (paused) return new Result(0, 0, 0, 0, 0, 0, true, "SOURCE_PAUSED");
        String instance = runner.runScoped(tenantId, mappings::cmdbInstance);
        List<Planned> plan = new ArrayList<>();
        for (int from = 0; from < sysIds.size(); from += PAGE) {
            List<String> batch = sysIds.subList(from, Math.min(sysIds.size(), from + PAGE));
            runner.runScoped(tenantId, () -> {
                for (String sysId : batch) {
                    jdbc.query("SELECT sys_id, asset_id, support_group, support_group_sys_id, department, owner_email FROM cis WHERE sys_id = ?",
                            (rs, row) -> new Ci(rs.getString(1), rs.getObject(2, UUID.class), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6)), sysId)
                            .forEach(ci -> planCi(ci, instance).stream().filter(p -> p.action() != Action.END).forEach(plan::add));
                }
                return null;
            });
        }
        int[] counts = apply(tenantId, plan);
        return new Result(sysIds.size(), counts[Action.CREATE.ordinal()], counts[Action.REOBSERVE.ordinal()], counts[Action.CHANGE.ordinal()],
                counts[Action.UNMAPPED.ordinal()], 0, false, null);
    }

    private int[] apply(UUID tenantId, List<Planned> plan) {
        Instant now = clock.instant();
        Instant staleAfter = OwnershipSourcePolicy.staleAfter(now, syncInterval);
        Instant expiresAt = OwnershipSourcePolicy.expiresAt(now, syncInterval);
        int[] counts = new int[5];
        for (int from = 0; from < plan.size(); from += PAGE) {
            List<Planned> batch = plan.subList(from, Math.min(plan.size(), from + PAGE));
            runner.runScoped(tenantId, () -> {
                List<UUID> reobserve = new ArrayList<>();
                List<UUID> end = new ArrayList<>();
                for (Planned p : batch) {
                    switch (p.action()) {
                        case REOBSERVE -> reobserve.add(p.existingClaimId());
                        case CREATE, CHANGE -> record(p, now, staleAfter, expiresAt);
                        case UNMAPPED -> unmapped(p);
                        case END -> end.add(p.existingClaimId());
                    }
                    counts[p.action().ordinal()]++;
                }
                claims.reobserve(reobserve, now, staleAfter, expiresAt);
                claims.endAbsent(end, "servicenow-producer");
                return null;
            });
        }
        return counts;
    }

    private List<Planned> planCi(Ci ci, String instance) {
        List<Planned> out = new ArrayList<>();
        // A CI read without display values has only the reference; it still maps through step (1).
        String group = ci.supportGroup() != null && !ci.supportGroup().isBlank() ? ci.supportGroup() : ci.supportGroupSysId();
        out.add(planField(new Desired(ci, "support_group", group), ci.supportGroupSysId(), instance));
        if (departmentClaims) out.add(planField(new Desired(ci, "department", ci.department()), null, null));
        return out.stream().filter(p -> p != null).toList();
    }

    /**
     * Contract §1.8 resolution order for {@code support_group}: (1) the stored {@code sys_user_group} {@code sys_id}
     * ({@code cis.support_group_sys_id}) through an active mapping of a ServiceNow source on the CMDB's instance, then
     * (2) exact team name or alias of the display name. No fuzzy matching and no team creation. {@code department}
     * resolves by (2) only.
     */
    private Planned planField(Desired d, String groupSysId, String instance) {
        List<Map<String, Object>> existing = jdbc.queryForList("""
                SELECT id, team_id FROM ownership_claim WHERE source_kind = ? AND source_ref = ? AND status = 'ACTIVE'
                """, SOURCE, d.sourceRef());
        UUID existingId = existing.isEmpty() ? null : (UUID) existing.get(0).get("id");
        UUID existingTeam = existing.isEmpty() ? null : (UUID) existing.get(0).get("team_id");
        if (d.value() == null || d.value().isBlank()) {
            return existingId == null ? null : new Planned(Action.END, d, null, existingId);
        }
        Optional<UUID> team = mappings.teamForGroup(groupSysId, instance);
        if (team.isEmpty() && !d.value().equals(groupSysId)) team = teams.resolve(d.value());
        if (team.isEmpty()) return new Planned(Action.UNMAPPED, d, null, existingId);
        if (existingId == null) return new Planned(Action.CREATE, d, team.get(), null);
        if (existingTeam.equals(team.get())) return new Planned(Action.REOBSERVE, d, team.get(), existingId);
        return new Planned(Action.CHANGE, d, team.get(), existingId);
    }

    private void record(Planned p, Instant now, Instant staleAfter, Instant expiresAt) {
        Optional<UUID> subject = subjects.subjectForAsset(p.desired().ci().assetId());
        if (subject.isEmpty()) return;
        claims.recordClaim(new ClaimRequest(subject.get(), p.teamId(), personEvidence(p.desired().ci().ownerEmail()), SOURCE, "SERVICENOW",
                null, p.desired().sourceRef(), p.teamId() + "@" + now.toEpochMilli(), PRODUCER_VERSION, now, staleAfter, expiresAt,
                null, "servicenow-producer"));
    }

    /**
     * An unmapped value never becomes a claim. A previous claim from the same field stays until the value maps,
     * expires or is cleared, so a typo in the CMDB cannot silently remove an owner.
     */
    private void unmapped(Planned p) {
        UUID tenant = com.prototype.vulnwatch.service.TenantContext.getCurrentTenantId();
        String normalized = p.desired().value().strip().toLowerCase(Locale.ROOT);
        String encrypted = null;
        byte[] index = null;
        String dedupe = "UNMAPPED_VALUE|" + SOURCE + "|" + p.desired().field() + "|";
        if (cipher.readiness(tenant).ready()) {
            encrypted = cipher.encrypt(tenant, "ownership.unresolved_value", p.desired().value().strip());
            index = cipher.blindIndex(tenant, "ownership.unresolved_value", normalized);
            dedupe += HexFormat.of().formatHex(index);
        } else {
            dedupe += Integer.toHexString(normalized.hashCode()) + "|" + p.desired().ci().sysId();
        }
        Optional<UUID> subject = subjects.subjectForAsset(p.desired().ci().assetId());
        reviews.raiseWithValue("UNMAPPED_VALUE", dedupe, subject.orElse(null), SOURCE, encrypted, index,
                Map.of("field", p.desired().field()));
    }

    private UUID personEvidence(String email) {
        if (email == null || email.isBlank() || !email.contains("@")) return null;
        try {
            return directory.userIdByEmail(email).orElse(null);
        } catch (RuntimeException ex) {
            return null; // person evidence is optional; tenant encryption may not be ready
        }
    }

    private List<UUID> absentClaims(Instant runStartedAt) {
        return jdbc.queryForList("""
                SELECT c.id FROM ownership_claim c
                 WHERE c.source_kind = ? AND c.status = 'ACTIVE' AND c.source_ref LIKE 'servicenow:cmdb_ci:%'
                   AND NOT EXISTS (SELECT 1 FROM cis ci WHERE ci.sys_id = split_part(c.source_ref, ':', 3)
                                                        AND ci.last_cmdb_sync_at >= ?)
                """, UUID.class, SOURCE, java.sql.Timestamp.from(runStartedAt));
    }

    private void forEachPage(UUID tenantId, Instant runStartedAt, java.util.function.Consumer<List<Ci>> consumer) {
        String after = "";
        while (true) {
            String cursor = after;
            List<Ci> page = runner.runScoped(tenantId, () -> jdbc.query("""
                    SELECT sys_id, asset_id, support_group, support_group_sys_id, department, owner_email FROM cis
                     WHERE last_cmdb_sync_at >= ? AND sys_id > ? AND sys_id ~* '^[0-9a-f]{32}$'
                     ORDER BY sys_id LIMIT ?
                    """, (rs, row) -> new Ci(rs.getString(1), rs.getObject(2, UUID.class), rs.getString(3), rs.getString(4), rs.getString(5), rs.getString(6)),
                    java.sql.Timestamp.from(runStartedAt), cursor, PAGE));
            if (page.isEmpty()) return;
            consumer.accept(page);
            if (page.size() < PAGE) return;
            after = page.get(page.size() - 1).sysId();
        }
    }
}
