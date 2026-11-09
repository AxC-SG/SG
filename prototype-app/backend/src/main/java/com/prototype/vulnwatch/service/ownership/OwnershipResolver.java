package com.prototype.vulnwatch.service.ownership;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Comparator;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/**
 * Fixed MVP direct resolution (plan §6.9 steps 1–4, 8). Pure: same inputs and clock give the same result.
 * Inheritance (steps 5–6) is applied at read time by {@code ownership_effective_assignment}, never here.
 */
public final class OwnershipResolver {

    /** Bump whenever eligibility or selection rules change, so every assignment is re-resolved. */
    public static final int RESOLVER_VERSION = 1;

    public enum Status { OWNED, CONFLICT, NONE }

    /** One current claim on the subject, with the facts that decide its eligibility. */
    public record ClaimInput(UUID claimId, int priority, UUID teamId, String sourceKind, Instant observedAt,
                             Instant staleAfter, Instant expiresAt, boolean active, boolean teamActive,
                             boolean sourcePaused) {
        public ClaimInput {
            Objects.requireNonNull(claimId);
            Objects.requireNonNull(teamId);
            Objects.requireNonNull(sourceKind);
            Objects.requireNonNull(observedAt);
            if (priority < 1 || priority > 6) throw new IllegalArgumentException("priority must be 1..6");
        }

        boolean eligibleAt(Instant now) {
            return active && teamActive && !sourcePaused && (expiresAt == null || expiresAt.isAfter(now));
        }
    }

    public record DirectResult(Status status, UUID teamId, UUID winningClaimId, Integer winningPriority,
                               String winningSourceKind, List<UUID> conflictTeamIds, String reason, String inputWatermark) { }

    private OwnershipResolver() { }

    public static DirectResult resolve(List<ClaimInput> claims, Instant now) {
        List<ClaimInput> eligible = claims.stream().filter(c -> c.eligibleAt(now))
                .sorted(Comparator.comparing(ClaimInput::claimId)).toList();
        String watermark = watermark(eligible);
        if (eligible.isEmpty()) {
            return new DirectResult(Status.NONE, null, null, null, null, List.of(), "NO_ELIGIBLE_CLAIM", watermark);
        }
        int best = eligible.stream().mapToInt(ClaimInput::priority).min().orElseThrow();
        List<ClaimInput> winners = eligible.stream().filter(c -> c.priority() == best).toList();
        List<UUID> teams = winners.stream().map(ClaimInput::teamId).distinct().sorted().toList();
        String sourceKind = winners.stream().map(ClaimInput::sourceKind).distinct().count() == 1 ? winners.get(0).sourceKind() : null;
        if (teams.size() > 1) {
            // Same priority, different teams: a visible conflict. Newest observation never silently wins.
            return new DirectResult(Status.CONFLICT, null, null, best, sourceKind, teams, "CONFLICTING_TEAMS_AT_PRIORITY", watermark);
        }
        ClaimInput winner = winners.stream()
                .max(Comparator.comparing(ClaimInput::observedAt).thenComparing(ClaimInput::claimId)).orElseThrow();
        return new DirectResult(Status.OWNED, winner.teamId(), winner.claimId(), best, winner.sourceKind(), List.of(),
                "SINGLE_TEAM_AT_PRIORITY", watermark);
    }

    /**
     * SHA-256 over the resolver version and the identity, priority, team and source of every eligible claim.
     * Timestamps are deliberately excluded: re-observing an unchanged claim must not rewrite the assignment.
     * Staleness is computed at read time and expiry changes the eligible set itself.
     */
    static String watermark(List<ClaimInput> eligibleSortedById) {
        StringBuilder sb = new StringBuilder("v").append(RESOLVER_VERSION);
        for (ClaimInput c : eligibleSortedById) {
            sb.append('|').append(c.claimId()).append(',').append(c.priority()).append(',').append(c.teamId()).append(',')
                    .append(c.sourceKind());
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(sb.toString().getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
