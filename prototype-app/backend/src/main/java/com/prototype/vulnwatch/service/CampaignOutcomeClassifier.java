package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.FindingCloseReason;
import java.util.EnumSet;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Campaign member outcome (Phase 0B §4.8). A pure function of the finding's status and closed reason, whether it was
 * closed or suppressed after the member was added, and whether an approved campaign exception names it. Rules apply in
 * order and the first match wins. An OPEN finding is never classified by its closed reason, because reopening clears
 * the closure metadata.
 *
 * <p>{@link #sql} renders the same rules as a SQL {@code CASE}, so counts, buckets and filters are computed in the
 * database from one rule table; {@code CampaignOutcomeClassifierPostgresIntegrationTest} checks that both agree for
 * every status and reason.
 */
public final class CampaignOutcomeClassifier {

    public enum Outcome { OPEN, REOPENED, CAMPAIGN_EXCEPTED, REMEDIATED, SUPPRESSED, FALSE_POSITIVE, ACCEPTED_RISK, CLOSED_OTHER }

    /** Outcomes that are active remediation work; overdue counts only these. */
    public static final Set<Outcome> ACTIVE = EnumSet.of(Outcome.OPEN, Outcome.REOPENED);

    /** Hidden from active-remediation views unless a filter asks for them (plan §9.11). */
    public static final Set<Outcome> EXCEPTED_BY_DEFAULT_HIDDEN = EnumSet.of(Outcome.SUPPRESSED, Outcome.FALSE_POSITIVE, Outcome.ACCEPTED_RISK);

    static final Set<FindingCloseReason> REMEDIATED_REASONS = EnumSet.of(FindingCloseReason.MANUAL_FIXED,
            FindingCloseReason.VERIFIED_REMEDIATION, FindingCloseReason.AUTO_NOT_OBSERVED, FindingCloseReason.AUTO_COMPONENT_REMOVED,
            FindingCloseReason.SUPERSEDED_BY_REPLACEMENT);

    private CampaignOutcomeClassifier() { }

    public static Outcome classify(String status, String closedReason, boolean campaignExcepted, boolean reopenedSinceAdd) {
        boolean open = "OPEN".equals(status);
        if ("SUPPRESSED".equals(status) || (!open && FindingCloseReason.AUTO_SUPPRESSED_BY_RULE.name().equals(closedReason))) {
            return Outcome.SUPPRESSED;
        }
        if (!open) {
            if (FindingCloseReason.MANUAL_FALSE_POSITIVE.name().equals(closedReason)) return Outcome.FALSE_POSITIVE;
            if (FindingCloseReason.MANUAL_ACCEPTED_RISK.name().equals(closedReason)) return Outcome.ACCEPTED_RISK;
            if (closedReason != null && REMEDIATED_REASONS.stream().anyMatch(r -> r.name().equals(closedReason))) return Outcome.REMEDIATED;
            return Outcome.CLOSED_OTHER;
        }
        if (campaignExcepted) return Outcome.CAMPAIGN_EXCEPTED;
        if (reopenedSinceAdd) return Outcome.REOPENED;
        return Outcome.OPEN;
    }

    /**
     * The rules as a SQL expression over the given column expressions ({@code excepted} and {@code reopened} are
     * boolean expressions). Inputs are trusted SQL fragments written by the caller, never request values.
     */
    public static String sql(String status, String closedReason, String excepted, String reopened) {
        return "(CASE"
                + " WHEN " + status + " = 'SUPPRESSED' OR (" + status + " <> 'OPEN' AND " + closedReason + " = 'AUTO_SUPPRESSED_BY_RULE') THEN 'SUPPRESSED'"
                + " WHEN " + status + " <> 'OPEN' AND " + closedReason + " = 'MANUAL_FALSE_POSITIVE' THEN 'FALSE_POSITIVE'"
                + " WHEN " + status + " <> 'OPEN' AND " + closedReason + " = 'MANUAL_ACCEPTED_RISK' THEN 'ACCEPTED_RISK'"
                + " WHEN " + status + " <> 'OPEN' AND " + closedReason + " IN (" + quoted(REMEDIATED_REASONS) + ") THEN 'REMEDIATED'"
                + " WHEN " + status + " <> 'OPEN' THEN 'CLOSED_OTHER'"
                + " WHEN " + excepted + " THEN 'CAMPAIGN_EXCEPTED'"
                + " WHEN " + reopened + " THEN 'REOPENED'"
                + " ELSE 'OPEN' END)";
    }

    private static String quoted(Set<FindingCloseReason> reasons) {
        return reasons.stream().map(r -> "'" + r.name() + "'").sorted().collect(Collectors.joining(","));
    }
}
