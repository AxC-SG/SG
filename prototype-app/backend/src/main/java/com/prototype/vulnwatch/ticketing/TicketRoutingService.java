package com.prototype.vulnwatch.ticketing;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.service.ownership.OwnershipAuthorityService.Domain;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter.Consumer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/**
 * Server-derived ticket routing (Phase 0B §4.9). On the canonical path (the finding's domain is CANONICAL and the
 * tenant is in {@code app.ownership.read-waves.tickets}) the assignment group comes from the finding's current owner,
 * read live from {@code ownership_effective_assignment} in the caller's transaction:
 *
 * <ul>
 *   <li>OWNED, team has {@code ticket_assignment_group} → that group ({@code TEAM_MAPPING});</li>
 *   <li>OWNED without a mapping, or UNOWNED → the tenant default on the active connector ({@code TENANT_DEFAULT}),
 *       otherwise the user's selection ({@code USER_SELECTED}), otherwise unroutable;</li>
 *   <li>CONFLICT → never routed automatically.</li>
 * </ul>
 *
 * Findings are batched one ticket per owner team, plus one each for Unowned (Conflict is never batched). An override
 * with a reason sends every eligible finding as one ticket to one group ({@code OVERRIDE}). There is no implicit
 * default group, the team name is never sent as a group and caller-supplied CMDB groups are ignored. The preview's
 * {@code routingHash} binds the batches, the assignment IDs and the choice, is HMAC-signed under the tenant key and is
 * valid for {@link #HASH_TTL}; create recomputes the plan and refuses a stale or mismatched hash with 409.
 */
@Service
public class TicketRoutingService {

    public static final Duration HASH_TTL = Duration.ofMinutes(10);
    public static final int MAX_OVERRIDE_REASON = 500;
    static final String P_ROUTING_HASH = "ticket.routing.preview";
    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    public enum Bucket { TEAM, UNOWNED, CONFLICT }

    /** What the caller chose; every field is optional. */
    public record Choice(String selectedAssignmentGroup, String assignmentGroupOverride, String overrideReason) {
        public static Choice none() { return new Choice(null, null, null); }
        boolean overriding() { return assignmentGroupOverride != null && !assignmentGroupOverride.isBlank(); }
    }

    /** One eligible finding with its live owner. */
    public record Target(UUID findingId, String displayId, UUID componentId, String ownershipStatus, UUID teamId, String teamName,
                         UUID assignmentId, String teamAssignmentGroup) { }

    public record Batch(String bucket, UUID teamId, String teamName, String assignmentGroup, RoutingSource routingSource,
                        List<UUID> findingIds) { }

    public record Unroutable(UUID findingId, String displayId, String bucket, UUID teamId, String reason) { }

    public record Excluded(UUID findingId, String displayId, String reason) { }

    /**
     * {@code canonical} false means today's (legacy) routing applies and no hash is needed. {@code tenantDefault} is the
     * explicit default on the active connector, or null.
     */
    public record Preview(boolean canonical, List<Batch> batches, List<Unroutable> unroutable, List<Excluded> excluded,
                          String tenantDefaultGroup, String routingHash, Instant expiresAt) { }

    /** A computed plan: the preview plus the live owner of every eligible finding, for the attempt audit. */
    public record Plan(Preview preview, Map<UUID, Target> targets) { }

    /** Create was refused because routing changed or the hash is missing or expired; carries a fresh preview. */
    public static final class RoutingChangedException extends RuntimeException {
        private final transient Preview preview;

        public RoutingChangedException(String message, Preview preview) {
            super(message);
            this.preview = preview;
        }

        public Preview preview() {
            return preview;
        }
    }

    private final JdbcTemplate jdbc;
    private final OwnershipReadAdapter reads;
    private final TicketingProviderRegistry registry;
    private final TenantDataCipher cipher;

    public TicketRoutingService(JdbcTemplate jdbc, OwnershipReadAdapter reads, TicketingProviderRegistry registry, TenantDataCipher cipher) {
        this.jdbc = jdbc;
        this.reads = reads;
        this.registry = registry;
        this.cipher = cipher;
    }

    /** True when every given finding kind routes canonically for the current tenant. */
    public boolean canonical(List<String> findingKinds) {
        if (findingKinds.isEmpty()) return reads.canonical(Consumer.TICKETS, Domain.CORE);
        return findingKinds.stream().distinct().allMatch(kind -> reads.canonical(Consumer.TICKETS, OwnershipReadAdapter.domainForFindingKind(kind)));
    }

    /** The routing plan for these findings; writes nothing. */
    public Plan plan(Tenant tenant, List<UUID> findingIds, Choice choice) {
        validate(choice);
        List<Map<String, Object>> rows = findingIds.isEmpty() ? List.of() : jdbc.queryForList("""
                SELECT f.id, f.display_id, f.finding_kind, f.status, f.incident_id, f.component_id, f.ownership_subject_id,
                       e.ownership_status, e.owner_team_id, e.ownership_assignment_id, t.name AS team_name, t.ticket_assignment_group
                  FROM findings f
                  LEFT JOIN ownership_effective_assignment e ON e.subject_id = f.ownership_subject_id
                  LEFT JOIN team t ON t.id = e.owner_team_id
                 WHERE f.id = ANY (?::uuid[])
                 ORDER BY f.id
                """, array(findingIds));
        if (rows.size() != findingIds.stream().distinct().count()) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Finding not found");
        }
        boolean canonical = canonical(rows.stream().map(r -> (String) r.get("finding_kind")).toList());
        List<Excluded> excluded = new ArrayList<>();
        List<Map<String, Object>> eligible = new ArrayList<>();
        for (Map<String, Object> row : rows) {
            String status = (String) row.get("status");
            String incident = (String) row.get("incident_id");
            if ("RESOLVED".equals(status) || "AUTO_CLOSED".equals(status)) {
                excluded.add(new Excluded((UUID) row.get("id"), (String) row.get("display_id"), "CLOSED"));
            } else if (incident != null && !incident.isBlank()) {
                excluded.add(new Excluded((UUID) row.get("id"), (String) row.get("display_id"), "ALREADY_TICKETED"));
            } else {
                eligible.add(row);
            }
        }
        String tenantDefault = canonical ? tenantDefaultGroup(tenant) : null;
        if (!canonical) {
            return new Plan(new Preview(false, List.of(), List.of(), excluded, null, null, null), Map.of());
        }

        Map<UUID, Target> targets = new LinkedHashMap<>();
        for (Map<String, Object> row : eligible) {
            boolean linked = row.get("ownership_subject_id") != null;
            String status = !linked ? "UNOWNED" : row.get("ownership_status") == null ? "UNOWNED" : (String) row.get("ownership_status");
            boolean owned = "OWNED".equals(status);
            targets.put((UUID) row.get("id"), new Target((UUID) row.get("id"), (String) row.get("display_id"), (UUID) row.get("component_id"),
                    status, owned ? (UUID) row.get("owner_team_id") : null, owned ? (String) row.get("team_name") : null,
                    linked ? (UUID) row.get("ownership_assignment_id") : null, owned ? blankToNull((String) row.get("ticket_assignment_group")) : null));
        }

        List<Batch> batches = new ArrayList<>();
        List<Unroutable> unroutable = new ArrayList<>();
        if (choice.overriding()) {
            if (!targets.isEmpty()) {
                batches.add(new Batch("OVERRIDE", null, null, choice.assignmentGroupOverride().trim(), RoutingSource.OVERRIDE,
                        List.copyOf(targets.keySet())));
            }
        } else {
            String fallback = tenantDefault != null ? tenantDefault : blankToNull(choice.selectedAssignmentGroup());
            RoutingSource fallbackSource = tenantDefault != null ? RoutingSource.TENANT_DEFAULT : RoutingSource.USER_SELECTED;
            Map<String, List<Target>> byKey = new LinkedHashMap<>();
            for (Target target : targets.values()) {
                if ("CONFLICT".equals(target.ownershipStatus())) {
                    unroutable.add(new Unroutable(target.findingId(), target.displayId(), Bucket.CONFLICT.name(), null,
                            "Ownership is in conflict; resolve it or override the group with a reason"));
                    continue;
                }
                String group = target.teamAssignmentGroup() != null ? target.teamAssignmentGroup() : fallback;
                if (group == null) {
                    unroutable.add(new Unroutable(target.findingId(), target.displayId(), target.teamId() == null ? Bucket.UNOWNED.name() : Bucket.TEAM.name(),
                            target.teamId(), target.teamId() == null
                                    ? "Unowned and no tenant default group; select a group"
                                    : "The owner team has no ticket assignment group and there is no tenant default; select a group"));
                    continue;
                }
                byKey.computeIfAbsent(target.teamId() == null ? "UNOWNED" : target.teamId().toString(), k -> new ArrayList<>()).add(target);
            }
            byKey.forEach((key, members) -> {
                Target first = members.get(0);
                boolean mapped = first.teamAssignmentGroup() != null;
                batches.add(new Batch(first.teamId() == null ? Bucket.UNOWNED.name() : Bucket.TEAM.name(), first.teamId(), first.teamName(),
                        mapped ? first.teamAssignmentGroup() : fallback, mapped ? RoutingSource.TEAM_MAPPING : fallbackSource,
                        members.stream().map(Target::findingId).toList()));
            });
            batches.sort(Comparator.comparing((Batch b) -> b.teamName() == null ? "￿" : b.teamName()).thenComparing(b -> String.valueOf(b.teamId())));
        }
        Instant expires = Instant.now().plus(HASH_TTL);
        String digest = digest(batches, unroutable, excluded, targets, choice);
        String hash = sign(tenant, expires, digest);
        return new Plan(new Preview(true, batches, unroutable, excluded, tenantDefault, hash, expires), targets);
    }

    /**
     * Checks the caller's hash against a freshly computed plan: it must be untampered, unexpired and bound to the same
     * batches, assignments and choice. Throws {@link RoutingChangedException} with the fresh preview otherwise.
     */
    public void requireCurrent(Tenant tenant, Plan fresh, String routingHash, Choice choice) {
        if (!fresh.preview().canonical()) return;
        String digest = digest(fresh.preview().batches(), fresh.preview().unroutable(), fresh.preview().excluded(), fresh.targets(), choice);
        if (!valid(tenant, routingHash, digest, Instant.now())) {
            throw new RoutingChangedException(routingHash == null || routingHash.isBlank()
                    ? "Preview the ticket routing first and send its routingHash"
                    : "Ticket routing changed or the preview expired; review the new routing", fresh.preview());
        }
    }

    /** The explicit default group on the active connector configuration, or null. */
    public String tenantDefaultGroup(Tenant tenant) {
        TicketingSystem active = registry.activeProvider(tenant).map(TicketingProvider::system).orElse(null);
        if (active == null) return null;
        String table = active == TicketingSystem.JIRA ? "jira_ticketing_configs" : "servicenow_cmdb_configs";
        List<String> values = jdbc.queryForList("SELECT default_assignment_group FROM " + table
                + " WHERE default_assignment_group IS NOT NULL ORDER BY updated_at DESC LIMIT 1", String.class);
        return values.isEmpty() ? null : blankToNull(values.get(0));
    }

    private static void validate(Choice choice) {
        if (choice.overriding()) {
            if (choice.overrideReason() == null || choice.overrideReason().isBlank()) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "overrideReason is required with assignmentGroupOverride");
            }
            if (choice.overrideReason().length() > MAX_OVERRIDE_REASON) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "overrideReason is limited to " + MAX_OVERRIDE_REASON + " characters");
            }
            if (choice.assignmentGroupOverride().length() > 255) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "assignmentGroupOverride is limited to 255 characters");
            }
        } else if (choice.overrideReason() != null && !choice.overrideReason().isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "overrideReason needs assignmentGroupOverride");
        }
    }

    private static String digest(List<Batch> batches, List<Unroutable> unroutable, List<Excluded> excluded, Map<UUID, Target> targets,
                                 Choice choice) {
        StringBuilder canonical = new StringBuilder();
        for (Batch batch : batches) {
            canonical.append("B|").append(batch.bucket()).append('|').append(batch.teamId()).append('|').append(batch.assignmentGroup()).append('|')
                    .append(batch.routingSource()).append('|')
                    .append(batch.findingIds().stream().map(UUID::toString).sorted().collect(Collectors.joining(","))).append('\n');
        }
        unroutable.stream().map(u -> "U|" + u.findingId() + "|" + u.bucket()).sorted().forEach(line -> canonical.append(line).append('\n'));
        excluded.stream().map(e -> "X|" + e.findingId() + "|" + e.reason()).sorted().forEach(line -> canonical.append(line).append('\n'));
        targets.values().stream().map(t -> "A|" + t.findingId() + "|" + t.assignmentId() + "|" + t.ownershipStatus()).sorted()
                .forEach(line -> canonical.append(line).append('\n'));
        canonical.append("C|").append(blankToNull(choice.selectedAssignmentGroup())).append('|').append(blankToNull(choice.assignmentGroupOverride()));
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (java.security.NoSuchAlgorithmException impossible) {
            throw new IllegalStateException(impossible);
        }
    }

    private String sign(Tenant tenant, Instant expires, String digest) {
        String payload = expires.getEpochSecond() + "|" + digest;
        return ENCODER.encodeToString(payload.getBytes(StandardCharsets.UTF_8)) + "." + ENCODER.encodeToString(mac(tenant, payload));
    }

    private boolean valid(Tenant tenant, String token, String digest, Instant now) {
        if (token == null || token.length() > 1_024) return false;
        int dot = token.indexOf('.');
        if (dot <= 0 || dot != token.lastIndexOf('.')) return false;
        String payload;
        byte[] signature;
        try {
            payload = new String(DECODER.decode(token.substring(0, dot)), StandardCharsets.UTF_8);
            signature = DECODER.decode(token.substring(dot + 1));
        } catch (IllegalArgumentException malformed) {
            return false;
        }
        if (!MessageDigest.isEqual(mac(tenant, payload), signature)) return false;
        String[] parts = payload.split("\\|", 2);
        if (parts.length != 2) return false;
        try {
            return now.getEpochSecond() < Long.parseLong(parts[0]) && parts[1].equals(digest);
        } catch (NumberFormatException malformed) {
            return false;
        }
    }

    private byte[] mac(Tenant tenant, String payload) {
        var readiness = cipher.readiness(tenant.getId());
        if (!readiness.ready()) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Tenant encryption is not ready (" + readiness.reason() + ")");
        }
        return cipher.blindIndex(tenant.getId(), P_ROUTING_HASH, payload);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String array(List<UUID> ids) {
        return "{" + ids.stream().distinct().map(UUID::toString).collect(Collectors.joining(",")) + "}";
    }
}
