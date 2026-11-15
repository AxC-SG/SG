package com.prototype.vulnwatch.service.ownership;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantWorkRunner;
import com.prototype.vulnwatch.service.ownership.OwnershipClaimService.ClaimRequest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
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
 * AWS and GCP ownership producer (Phase 0B §2). Runs after a discovery sync and reads the assets that sync just wrote;
 * it holds no cloud credentials and calls no cloud API (GCP project labels and AWS account tags are read by the sync
 * and passed in). For every observed resource it emits a {@code CLOUD_TAG} claim per enabled {@code owner}/{@code team}
 * key, and for every account or project whose labels or tags were read a {@code CLOUD_STRUCTURED} claim on its
 * {@code CLOUD_ACCOUNT} subject. Values resolve only by exact team name or alias; unmapped values become review items.
 *
 * <p>Two passes, as in {@link ServiceNowOwnershipProducer}: a read-only plan feeds the per-class anomaly gate (§2.8);
 * a tripped run writes nothing, raises a review item and pauses the tenant's producer through the kill switch. Claims
 * of absent resources end only inside scopes the run listed completely (§2.5). Every claim belongs to the
 * {@code CLOUD_BOM} domain: {@link OwnershipResolutionService} treats it as ineligible until that domain is CANONICAL.
 */
@Component
public class CloudOwnershipProducer {

    private static final Logger LOG = LoggerFactory.getLogger(CloudOwnershipProducer.class);
    static final String ACTOR = "cloud-producer";
    static final List<String> KEYS = List.of("owner", "team");
    static final int MAX_VALUE_LENGTH = 256;
    private static final int PAGE = 500;
    private static final String TAG_CLASS = "CLOUD_TAG";
    private static final String ACCOUNT_CLASS = "CLOUD_STRUCTURED";

    public enum Provider {
        AWS("aws", "aws-ownership-1", "tag", "account", "aws_discovery_configs"),
        GCP("gcp", "gcp-ownership-1", "label", "project", "gcp_discovery_configs");

        final String assetProvider;
        final String producerVersion;
        final String keyWord;
        final String accountWord;
        final String configTable;

        Provider(String assetProvider, String producerVersion, String keyWord, String accountWord, String configTable) {
            this.assetProvider = assetProvider;
            this.producerVersion = producerVersion;
            this.keyWord = keyWord;
            this.accountWord = accountWord;
            this.configTable = configTable;
        }

        public String kind() {
            return name();
        }

        String accountObjectId(String accountId) {
            return assetProvider + ":" + accountId;
        }
    }

    /**
     * A scope the run listed completely: AWS by account, resource type and region; GCP by project and resource type
     * (region {@code null}). Values compare as the connectors compare them, trimmed and upper case.
     */
    public record Scope(String accountId, String resourceType, String region) {
        public Scope {
            accountId = norm(accountId);
            resourceType = norm(resourceType);
            region = region == null ? null : norm(region);
        }

        boolean covers(String account, String type, String assetRegion) {
            return accountId.equals(norm(account)) && resourceType.equals(norm(type))
                    && (region == null || region.equals(norm(assetRegion)));
        }

        private static String norm(String value) {
            return value == null ? "" : value.strip().toUpperCase(Locale.ROOT);
        }
    }

    /** Account tags or project labels read in the run; {@code values} is null when the read failed or was skipped. */
    public record AccountRead(String accountId, Map<String, String> values) { }

    public record Run(Provider provider, Instant startedAt, List<Scope> completeScopes, List<AccountRead> accountReads) { }

    public record Settings(boolean ownerKey, boolean teamKey, boolean accountInput, Integer intervalMinutes) {
        boolean keyEnabled(String key) {
            return "owner".equals(key) ? ownerKey : teamKey;
        }
    }

    public record Result(int scanned, int created, int reobserved, int changed, int unmapped, int ended, boolean paused,
                         String pauseReason) {
        static Result skipped(String reason) {
            return new Result(0, 0, 0, 0, 0, 0, true, reason);
        }
    }

    private enum Action { CREATE, REOBSERVE, CHANGE, UNMAPPED, END }

    /** One desired claim: on a resource ({@code assetId}) or on an account subject ({@code accountId}). */
    private record Desired(UUID assetId, String accountId, String key, String value, String priorityClass, String sourceRef) { }

    private record Planned(Action action, Desired desired, UUID teamId, UUID existingClaimId) { }

    private record Resource(UUID assetId, String accountId, String resourceType, String region, String tagsJson) { }

    private final JdbcTemplate jdbc;
    private final TenantWorkRunner runner;
    private final TeamNamespaceService teams;
    private final OwnershipClaimService claims;
    private final OwnershipReviewService reviews;
    private final InventorySubjectAdapter assetSubjects;
    private final OwnershipSubjectService subjects;
    private final OwnershipAuthorityService authority;
    private final CloudOwnershipSourceService sources;
    private final TenantDataCipher cipher;
    private final ObjectMapper json;
    private final Clock clock;
    private final boolean enabled;

    public CloudOwnershipProducer(JdbcTemplate jdbc, TenantWorkRunner runner, TeamNamespaceService teams, OwnershipClaimService claims,
                                  OwnershipReviewService reviews, InventorySubjectAdapter assetSubjects, OwnershipSubjectService subjects,
                                  OwnershipAuthorityService authority, CloudOwnershipSourceService sources, TenantDataCipher cipher,
                                  ObjectMapper json, ObjectProvider<Clock> clock,
                                  @Value("${app.ownership.cloud.producer-enabled:false}") boolean enabled) {
        this.jdbc = jdbc;
        this.runner = runner;
        this.teams = teams;
        this.claims = claims;
        this.reviews = reviews;
        this.assetSubjects = assetSubjects;
        this.subjects = subjects;
        this.authority = authority;
        this.sources = sources;
        this.cipher = cipher;
        this.json = json;
        this.clock = clock.getIfAvailable(Clock::systemUTC);
        this.enabled = enabled;
    }

    public boolean enabled() {
        return enabled;
    }

    /** Called by a discovery sync after it committed. Never throws: a producer failure must not fail the sync. */
    public Optional<Result> publishAfterSync(UUID tenantId, Run run) {
        if (!enabled) return Optional.empty();
        try {
            return Optional.of(publish(tenantId, run));
        } catch (RuntimeException ex) {
            LOG.warn("{} ownership producer failed for tenant {}: {}", run.provider(), tenantId, ex.getMessage(), ex);
            return Optional.empty();
        }
    }

    public Result publish(UUID tenantId, Run run) {
        Provider provider = run.provider();
        boolean legacy = runner.runScoped(tenantId, () -> !authority.producersMayPublish(OwnershipAuthorityService.Domain.CLOUD_BOM));
        if (legacy) return Result.skipped("DOMAIN_LEGACY");
        boolean paused = runner.runScoped(tenantId, () -> claims.sourcePaused(provider.kind()));
        if (paused) return Result.skipped("SOURCE_PAUSED");
        Optional<Settings> found = runner.runScoped(tenantId, () -> sources.settings(provider));
        if (found.isEmpty()) return Result.skipped("NOT_CONFIGURED");
        Settings settings = found.get();
        Duration interval;
        try {
            interval = OwnershipSourcePolicy.requireValidInterval(Duration.ofMinutes(settings.intervalMinutes() == null ? 0 : settings.intervalMinutes()));
        } catch (IllegalArgumentException invalid) {
            return Result.skipped("INTERVAL_INVALID");
        }

        // Pass 1: read-only plan of every change, for the anomaly gate.
        List<Planned> plan = new ArrayList<>();
        List<Resource> observed = new ArrayList<>();
        forEachObservedResource(tenantId, provider, run.startedAt(), page -> runner.runScoped(tenantId, () -> {
            observed.addAll(page);
            for (Resource resource : page) {
                Map<String, String> tags = tags(resource.tagsJson());
                for (String key : KEYS) {
                    if (!settings.keyEnabled(key)) continue;
                    String ref = provider.assetProvider + ":asset:" + resource.assetId() + ":" + provider.keyWord + ":" + key;
                    planned(provider, new Desired(resource.assetId(), null, key, tagValue(provider, tags, key), TAG_CLASS, ref)).ifPresent(plan::add);
                }
            }
            return null;
        }));
        if (settings.accountInput()) {
            runner.runScoped(tenantId, () -> {
                for (AccountRead read : run.accountReads()) {
                    if (read.values() == null || read.accountId() == null || read.accountId().isBlank()) continue;
                    for (String key : KEYS) {
                        if (!settings.keyEnabled(key)) continue;
                        String ref = provider.assetProvider + ":" + provider.accountWord + ":" + read.accountId() + ":" + provider.keyWord + ":" + key;
                        planned(provider, new Desired(null, read.accountId(), key, tagValue(provider, read.values(), key), ACCOUNT_CLASS, ref))
                                .ifPresent(plan::add);
                    }
                }
                return null;
            });
        }
        List<UUID> absent = runner.runScoped(tenantId, () -> absentResourceClaims(provider, run));

        Map<String, Long> active = runner.runScoped(tenantId, () -> activeByClass(provider));
        boolean approved = runner.runScoped(tenantId, () -> sources.consumeAnomalyApproval(provider));
        List<String> tripped = new ArrayList<>();
        for (String priorityClass : approved ? List.<String>of() : List.of(TAG_CLASS, ACCOUNT_CLASS)) {
            long changes = plan.stream().filter(p -> p.desired().priorityClass().equals(priorityClass))
                    .filter(p -> p.action() == Action.CHANGE || p.action() == Action.END).count()
                    + (TAG_CLASS.equals(priorityClass) ? absent.size() : 0);
            long creates = plan.stream().filter(p -> p.desired().priorityClass().equals(priorityClass))
                    .filter(p -> p.action() == Action.CREATE).count();
            long activeClaims = active.getOrDefault(priorityClass, 0L);
            if (OwnershipSourcePolicy.anomalous(changes, creates, activeClaims, activeClaims == 0)) {
                tripped.add(priorityClass);
                runner.runScoped(tenantId, () -> reviews.raise("PRODUCER_ANOMALY", "PRODUCER_ANOMALY|" + provider.kind() + "|" + priorityClass,
                        null, provider.kind(), Map.of("priorityClass", priorityClass, "activeClaims", activeClaims,
                                "wouldChangeOrEnd", changes, "wouldCreate", creates,
                                "minChanges", OwnershipSourcePolicy.ANOMALY_MIN_CHANGES,
                                "fraction", OwnershipSourcePolicy.ANOMALY_FRACTION,
                                "absoluteChanges", OwnershipSourcePolicy.ANOMALY_ABSOLUTE_CHANGES)));
            }
        }
        if (!tripped.isEmpty()) {
            // The kill switch stops every class of this provider, so a tripped run writes nothing at all.
            runner.runScoped(tenantId, () -> {
                sources.pauseForAnomaly(provider, tripped);
                return null;
            });
            return new Result(observed.size(), 0, 0, 0, 0, 0, true, "ANOMALY");
        }

        // Pass 2: apply in bounded batches, one transaction each.
        Instant now = clock.instant();
        Instant staleAfter = OwnershipSourcePolicy.staleAfter(now, interval);
        Instant expiresAt = OwnershipSourcePolicy.expiresAt(now, interval);
        int[] counts = new int[Action.values().length];
        Map<String, UUID> accountSubjects = new LinkedHashMap<>();
        for (int from = 0; from < observed.size(); from += PAGE) {
            List<Resource> batch = observed.subList(from, Math.min(observed.size(), from + PAGE));
            runner.runScoped(tenantId, () -> {
                for (Resource resource : batch) linkToAccount(provider, resource, accountSubjects);
                return null;
            });
        }
        for (int from = 0; from < plan.size(); from += PAGE) {
            List<Planned> batch = plan.subList(from, Math.min(plan.size(), from + PAGE));
            runner.runScoped(tenantId, () -> {
                List<UUID> reobserve = new ArrayList<>();
                List<UUID> end = new ArrayList<>();
                for (Planned p : batch) {
                    switch (p.action()) {
                        case REOBSERVE -> reobserve.add(p.existingClaimId());
                        case CREATE, CHANGE -> record(provider, p, accountSubjects, now, staleAfter, expiresAt);
                        case UNMAPPED -> unmapped(provider, p, accountSubjects);
                        case END -> end.add(p.existingClaimId());
                    }
                    counts[p.action().ordinal()]++;
                }
                claims.reobserve(reobserve, now, staleAfter, expiresAt);
                claims.endAbsent(end, ACTOR);
                return null;
            });
        }
        for (int from = 0; from < absent.size(); from += PAGE) {
            List<UUID> batch = absent.subList(from, Math.min(absent.size(), from + PAGE));
            runner.runScoped(tenantId, () -> claims.endAbsent(batch, ACTOR));
        }
        return new Result(observed.size(), counts[Action.CREATE.ordinal()], counts[Action.REOBSERVE.ordinal()],
                counts[Action.CHANGE.ordinal()], counts[Action.UNMAPPED.ordinal()], counts[Action.END.ordinal()] + absent.size(), false, null);
    }

    // ----- planning ---------------------------------------------------------------------------------------------

    private Optional<Planned> planned(Provider provider, Desired d) {
        List<Map<String, Object>> existing = jdbc.queryForList(
                "SELECT id, team_id FROM ownership_claim WHERE source_kind = ? AND source_ref = ? AND status = 'ACTIVE'",
                provider.kind(), d.sourceRef());
        UUID existingId = existing.isEmpty() ? null : (UUID) existing.get(0).get("id");
        UUID existingTeam = existing.isEmpty() ? null : (UUID) existing.get(0).get("team_id");
        if (d.value() == null || d.value().isBlank()) {
            // The provider reported the resource without this key: an authoritative observation (§2.5).
            return existingId == null ? Optional.empty() : Optional.of(new Planned(Action.END, d, null, existingId));
        }
        Optional<UUID> team = acceptable(d.value()) ? teams.resolve(d.value()) : Optional.empty();
        if (team.isEmpty()) return Optional.of(new Planned(Action.UNMAPPED, d, null, existingId));
        if (existingId == null) return Optional.of(new Planned(Action.CREATE, d, team.get(), null));
        if (existingTeam.equals(team.get())) return Optional.of(new Planned(Action.REOBSERVE, d, team.get(), existingId));
        return Optional.of(new Planned(Action.CHANGE, d, team.get(), existingId));
    }

    /** Values longer than 256 characters or with control characters are never resolved (§2.4). */
    static boolean acceptable(String value) {
        return value.length() <= MAX_VALUE_LENGTH && value.chars().noneMatch(Character::isISOControl);
    }

    /** AWS tag keys match case-insensitively after trimming; GCP label keys are lower case by definition (§2.2). */
    static String tagValue(Provider provider, Map<String, String> tags, String key) {
        if (tags == null) return null;
        if (provider == Provider.GCP) return tags.get(key);
        for (Map.Entry<String, String> entry : tags.entrySet()) {
            if (entry.getKey() != null && entry.getKey().strip().equalsIgnoreCase(key)) return entry.getValue();
        }
        return null;
    }

    private Map<String, String> tags(String tagsJson) {
        if (tagsJson == null || tagsJson.isBlank()) return Map.of();
        try {
            Map<String, String> parsed = json.readValue(tagsJson, new TypeReference<LinkedHashMap<String, String>>() { });
            return parsed == null ? Map.of() : parsed;
        } catch (Exception malformed) {
            return Map.of();
        }
    }

    private void forEachObservedResource(UUID tenantId, Provider provider, Instant startedAt,
                                         java.util.function.Consumer<List<Resource>> consumer) {
        UUID after = new UUID(0L, 0L);   // PostgreSQL orders uuid as unsigned bytes; the nil UUID sorts first
        while (true) {
            UUID cursor = after;
            List<Resource> page = runner.runScoped(tenantId, () -> jdbc.query("""
                    SELECT id, cloud_account_id, cloud_resource_type, cloud_region, cloud_tags_json FROM assets
                     WHERE cloud_provider = ? AND last_cmdb_sync_at >= ? AND state <> 'DECOMMISSIONED' AND id > ?
                     ORDER BY id LIMIT ?
                    """, (rs, row) -> new Resource(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4), rs.getString(5)),
                    provider.assetProvider, java.sql.Timestamp.from(startedAt), cursor, PAGE));
            if (page.isEmpty()) return;
            consumer.accept(page);
            if (page.size() < PAGE) return;
            after = page.get(page.size() - 1).assetId();
        }
    }

    /** Active resource claims whose asset this run did not observe, inside a scope the run listed completely. */
    private List<UUID> absentResourceClaims(Provider provider, Run run) {
        if (run.completeScopes().isEmpty()) return List.of();
        List<UUID> absent = new ArrayList<>();
        jdbc.query("""
                SELECT c.id, a.cloud_account_id, a.cloud_resource_type, a.cloud_region
                  FROM ownership_claim c JOIN assets a ON a.id::text = split_part(c.source_ref, ':', 3)
                 WHERE c.source_kind = ? AND c.status = 'ACTIVE' AND c.source_ref LIKE ?
                   AND (a.last_cmdb_sync_at IS NULL OR a.last_cmdb_sync_at < ? OR a.state = 'DECOMMISSIONED')
                """, rs -> {
            String account = rs.getString(2);
            String type = rs.getString(3);
            String region = rs.getString(4);
            if (run.completeScopes().stream().anyMatch(scope -> scope.covers(account, type, region))) {
                absent.add(rs.getObject(1, UUID.class));
            }
        }, provider.kind(), provider.assetProvider + ":asset:%", java.sql.Timestamp.from(run.startedAt()));
        return absent;
    }

    private Map<String, Long> activeByClass(Provider provider) {
        Map<String, Long> active = new LinkedHashMap<>();
        jdbc.query("SELECT priority_class, count(*) FROM ownership_claim WHERE source_kind = ? AND status = 'ACTIVE' GROUP BY priority_class",
                rs -> { active.put(rs.getString(1), rs.getLong(2)); }, provider.kind());
        return active;
    }

    // ----- applying ---------------------------------------------------------------------------------------------

    private UUID accountSubject(Provider provider, String accountId, Map<String, UUID> cache) {
        return cache.computeIfAbsent(accountId, id -> subjects.register("CLOUD_ACCOUNT", provider.accountObjectId(id), null).id());
    }

    /**
     * §2.3: the resource's OWNERSHIP_PARENT is its account subject, set only when it has no active parent or its parent
     * is a CLOUD_ACCOUNT this producer set. Any other parent is kept and raises an INHERITANCE_ERROR review item.
     */
    private void linkToAccount(Provider provider, Resource resource, Map<String, UUID> accountSubjects) {
        if (resource.accountId() == null || resource.accountId().isBlank()) return;
        Optional<UUID> child = assetSubjects.subjectForAsset(resource.assetId());
        if (child.isEmpty()) return;
        UUID account = accountSubject(provider, resource.accountId(), accountSubjects);
        List<Map<String, Object>> parent = jdbc.queryForList("""
                SELECT e.parent_subject_id, e.created_by, s.subject_type FROM ownership_subject_edge e
                  JOIN ownership_subject s ON s.id = e.parent_subject_id
                 WHERE e.child_subject_id = ? AND e.edge_type = 'OWNERSHIP_PARENT' AND e.status = 'ACTIVE'
                """, child.get());
        if (parent.isEmpty()) {
            subjects.setParent(child.get(), account, ACTOR);
            return;
        }
        UUID current = (UUID) parent.get(0).get("parent_subject_id");
        if (current.equals(account)) return;
        boolean ours = ACTOR.equals(parent.get(0).get("created_by")) && "CLOUD_ACCOUNT".equals(parent.get(0).get("subject_type"));
        if (ours) {
            subjects.setParent(child.get(), account, ACTOR);     // the asset moved to another account
        } else {
            reviews.raise("INHERITANCE_ERROR", "INHERITANCE_ERROR|" + provider.kind() + "|" + child.get(), child.get(), provider.kind(),
                    Map.of("reason", "PARENT_SET_ELSEWHERE", "accountSubjectId", account, "currentParentId", current));
        }
    }

    private Optional<UUID> subjectFor(Provider provider, Desired d, Map<String, UUID> accountSubjects) {
        if (d.assetId() != null) return assetSubjects.subjectForAsset(d.assetId());
        return Optional.of(accountSubject(provider, d.accountId(), accountSubjects));
    }

    private void record(Provider provider, Planned p, Map<String, UUID> accountSubjects, Instant now, Instant staleAfter, Instant expiresAt) {
        Optional<UUID> subject = subjectFor(provider, p.desired(), accountSubjects);
        if (subject.isEmpty()) return;
        // Values are never resolved through a person, so principal_user_id stays unset (§2.4).
        claims.recordClaim(new ClaimRequest(subject.get(), p.teamId(), null, provider.kind(), p.desired().priorityClass(), null,
                p.desired().sourceRef(), p.teamId() + "@" + now.toEpochMilli(), provider.producerVersion, now, staleAfter, expiresAt,
                null, ACTOR));
    }

    /**
     * An unmapped value never becomes a claim, and an existing claim from the same key stays until the value maps,
     * expires or is cleared (§2.4). Tag values often hold emails, so they are stored only as tenant ciphertext.
     */
    private void unmapped(Provider provider, Planned p, Map<String, UUID> accountSubjects) {
        UUID tenant = TenantContext.getCurrentTenantId();
        String value = p.desired().value().strip();
        String normalized = value.toLowerCase(Locale.ROOT);
        String dedupe = "UNMAPPED_VALUE|" + provider.kind() + "|" + p.desired().key() + "|";
        String encrypted = null;
        byte[] index = null;
        if (cipher.readiness(tenant).ready()) {
            encrypted = cipher.encrypt(tenant, "ownership.unresolved_value", value);
            index = cipher.blindIndex(tenant, "ownership.unresolved_value", normalized);
            dedupe += HexFormat.of().formatHex(index);
        } else {
            dedupe += Integer.toHexString(normalized.hashCode()) + "|" + p.desired().sourceRef();
        }
        Optional<UUID> subject = subjectFor(provider, p.desired(), accountSubjects);
        reviews.raiseWithValue("UNMAPPED_VALUE", dedupe, subject.orElse(null), provider.kind(), encrypted, index,
                Map.of("field", provider.keyWord + ":" + p.desired().key(), "priorityClass", p.desired().priorityClass()));
    }
}
