package com.prototype.vulnwatch.service;

import static com.prototype.vulnwatch.service.CampaignOutcomeClassifier.classify;
import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.service.CampaignOutcomeClassifier.Outcome;
import java.util.EnumMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Phase 0B §4.8: every closed reason, rule order and the open-member rules. */
class CampaignOutcomeClassifierTest {

    private static final Map<FindingCloseReason, Outcome> CLOSED = new EnumMap<>(FindingCloseReason.class);

    static {
        CLOSED.put(FindingCloseReason.MANUAL_FIXED, Outcome.REMEDIATED);
        CLOSED.put(FindingCloseReason.VERIFIED_REMEDIATION, Outcome.REMEDIATED);
        CLOSED.put(FindingCloseReason.AUTO_NOT_OBSERVED, Outcome.REMEDIATED);
        CLOSED.put(FindingCloseReason.AUTO_COMPONENT_REMOVED, Outcome.REMEDIATED);
        CLOSED.put(FindingCloseReason.SUPERSEDED_BY_REPLACEMENT, Outcome.REMEDIATED);
        CLOSED.put(FindingCloseReason.MANUAL_FALSE_POSITIVE, Outcome.FALSE_POSITIVE);
        CLOSED.put(FindingCloseReason.MANUAL_ACCEPTED_RISK, Outcome.ACCEPTED_RISK);
        CLOSED.put(FindingCloseReason.AUTO_SUPPRESSED_BY_RULE, Outcome.SUPPRESSED);
        CLOSED.put(FindingCloseReason.AUTO_ASSET_RETIRED, Outcome.CLOSED_OTHER);
        CLOSED.put(FindingCloseReason.AUTO_DUPLICATE, Outcome.CLOSED_OTHER);
        CLOSED.put(FindingCloseReason.AUTO_SOURCE_DISABLED, Outcome.CLOSED_OTHER);
        CLOSED.put(FindingCloseReason.AUTO_POLICY_NOT_OWNER_FACING, Outcome.CLOSED_OTHER);
        CLOSED.put(FindingCloseReason.AUTO_POLICY_PLATFORM_DEPRECATED, Outcome.CLOSED_OTHER);
        CLOSED.put(FindingCloseReason.AUTO_POLICY_TENANT_DISABLED, Outcome.CLOSED_OTHER);
        CLOSED.put(FindingCloseReason.AUTO_POLICY_VERSION_SUPERSEDED, Outcome.CLOSED_OTHER);
        CLOSED.put(FindingCloseReason.AUTO_RECLASSIFIED_NOT_SOFTWARE, Outcome.CLOSED_OTHER);
    }

    @Test
    void everyCloseReasonHasOneOutcomeAndOnlyFixesCountAsRemediated() {
        assertThat(CLOSED.keySet()).containsExactlyInAnyOrder(FindingCloseReason.values());
        for (FindingCloseReason reason : FindingCloseReason.values()) {
            for (String status : new String[] { "RESOLVED", "AUTO_CLOSED" }) {
                assertThat(classify(status, reason.name(), false, false)).as(status + "/" + reason).isEqualTo(CLOSED.get(reason));
                // An exception or a reopen event never changes a closed finding's outcome.
                assertThat(classify(status, reason.name(), true, true)).as(status + "/" + reason).isEqualTo(CLOSED.get(reason));
            }
        }
    }

    @Test
    void suppressedWinsAndClosedWithoutAReasonIsClosedOther() {
        assertThat(classify("SUPPRESSED", null, true, true)).isEqualTo(Outcome.SUPPRESSED);
        assertThat(classify("SUPPRESSED", "MANUAL_FIXED", false, false)).isEqualTo(Outcome.SUPPRESSED);
        assertThat(classify("RESOLVED", null, false, false)).isEqualTo(Outcome.CLOSED_OTHER);
    }

    @Test
    void openMembersAreExceptedThenReopenedThenOpen() {
        assertThat(classify("OPEN", null, true, true)).isEqualTo(Outcome.CAMPAIGN_EXCEPTED);
        assertThat(classify("OPEN", null, false, true)).isEqualTo(Outcome.REOPENED);
        assertThat(classify("OPEN", null, false, false)).isEqualTo(Outcome.OPEN);
        // A stale closed reason on an open finding does not classify it as closed.
        assertThat(classify("OPEN", "MANUAL_FIXED", false, false)).isEqualTo(Outcome.OPEN);
    }
}
