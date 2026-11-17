package com.prototype.vulnwatch.service.ownership;

import java.time.Duration;
import java.time.Instant;

/**
 * Source staleness, expiry and anomaly-pause rules from the ownership plan (sections 12.1 and 12.3). Pure functions so
 * every producer applies the same defaults. A producer contract may only lower these defaults, never raise them.
 */
public final class OwnershipSourcePolicy {

    public static final Duration MIN_INTERVAL = Duration.ofMinutes(15);
    public static final Duration MAX_INTERVAL = Duration.ofDays(7);
    static final Duration STALE_FLOOR = Duration.ofHours(24);
    static final Duration EXPIRY_FLOOR = Duration.ofHours(72);
    static final Duration EXPIRY_CAP = Duration.ofDays(30);

    /** An anomaly pause needs at least this many proposed changes and this share of the source's active claims... */
    static final int ANOMALY_MIN_CHANGES = 100;
    static final double ANOMALY_FRACTION = 0.10;
    /** ...or this many proposed changes regardless of percentage. */
    static final int ANOMALY_ABSOLUTE_CHANGES = 10_000;

    private OwnershipSourcePolicy() { }

    /** MVP source schedules must be between 15 minutes and seven days. */
    public static Duration requireValidInterval(Duration interval) {
        if (interval == null || interval.compareTo(MIN_INTERVAL) < 0 || interval.compareTo(MAX_INTERVAL) > 0) {
            throw new IllegalArgumentException("Ownership source sync interval must be between PT15M and P7D");
        }
        return interval;
    }

    /** Stale after max(2 x interval, 24 hours) without a complete successful observation. */
    public static Instant staleAfter(Instant observedAt, Duration interval) {
        return observedAt.plus(max(interval.multipliedBy(2), STALE_FLOOR));
    }

    /** Expires after max(3 x interval, 72 hours), capped at 30 days. Always later than the stale threshold. */
    public static Instant expiresAt(Instant observedAt, Duration interval) {
        Duration expiry = max(interval.multipliedBy(3), EXPIRY_FLOOR);
        return observedAt.plus(expiry.compareTo(EXPIRY_CAP) > 0 ? EXPIRY_CAP : expiry);
    }

    /**
     * True when one run proposes at least 100 changes and at least 10 % of the source's active claims, or at least
     * 10,000 changes regardless of percentage.
     */
    public static boolean anomalous(long proposedChanges, long activeClaims) {
        if (proposedChanges >= ANOMALY_ABSOLUTE_CHANGES) return true;
        return proposedChanges >= ANOMALY_MIN_CHANGES && proposedChanges >= ANOMALY_FRACTION * activeClaims;
    }

    /**
     * The anomaly gate when a run's creates are counted apart from its other changes (plan §12.3). A source's first
     * complete baseline load is exempt only from the percentage-based check for creates: they still count toward the
     * absolute {@value #ANOMALY_ABSOLUTE_CHANGES}, and updates, deactivations and removals count as usual.
     */
    public static boolean anomalous(long changes, long creates, long active, boolean baselineLoad) {
        if (changes + creates >= ANOMALY_ABSOLUTE_CHANGES) return true;
        return anomalous(baselineLoad ? changes : changes + creates, active);
    }

    private static Duration max(Duration a, Duration b) {
        return a.compareTo(b) >= 0 ? a : b;
    }
}
