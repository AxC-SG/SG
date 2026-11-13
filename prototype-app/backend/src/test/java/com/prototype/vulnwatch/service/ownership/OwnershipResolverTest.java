package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.service.ownership.OwnershipResolver.ClaimInput;
import com.prototype.vulnwatch.service.ownership.OwnershipResolver.DirectResult;
import com.prototype.vulnwatch.service.ownership.OwnershipResolver.Status;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class OwnershipResolverTest {

    private static final Instant NOW = Instant.parse("2026-11-08T00:00:00Z");
    private static final UUID PAYMENTS = UUID.fromString("00000000-0000-0000-0000-00000000000a");
    private static final UUID IDENTITY = UUID.fromString("00000000-0000-0000-0000-00000000000b");

    @Test
    void noClaimsOrNoEligibleClaimsGiveNone() {
        assertThat(OwnershipResolver.resolve(List.of(), NOW).status()).isEqualTo(Status.NONE);
        List<ClaimInput> ineligible = List.of(
                claim(1, PAYMENTS).expires(NOW).build(),
                claim(2, PAYMENTS).teamArchived().build(),
                claim(2, PAYMENTS).paused().build());
        DirectResult result = OwnershipResolver.resolve(ineligible, NOW);
        assertThat(result.status()).isEqualTo(Status.NONE);
        assertThat(result.reason()).isEqualTo("NO_ELIGIBLE_CLAIM");
        assertThat(result.inputWatermark()).isEqualTo(OwnershipResolver.resolve(List.of(), NOW).inputWatermark());
    }

    @Test
    void highestPriorityWinsRegardlessOfRecency() {
        ClaimInput manual = claim(1, IDENTITY).observed(NOW.minus(Duration.ofDays(30))).build();
        ClaimInput servicenow = claim(2, PAYMENTS).observed(NOW).build();
        DirectResult result = OwnershipResolver.resolve(List.of(servicenow, manual), NOW);
        assertThat(result.status()).isEqualTo(Status.OWNED);
        assertThat(result.teamId()).isEqualTo(IDENTITY);
        assertThat(result.winningClaimId()).isEqualTo(manual.claimId());
        assertThat(result.winningPriority()).isEqualTo(1);
    }

    @Test
    void expiredWinnerFallsThroughToNextPriority() {
        ClaimInput manual = claim(1, IDENTITY).expires(NOW.minusSeconds(1)).build();
        ClaimInput servicenow = claim(2, PAYMENTS).build();
        DirectResult result = OwnershipResolver.resolve(List.of(manual, servicenow), NOW);
        assertThat(result.teamId()).isEqualTo(PAYMENTS);
        assertThat(result.winningPriority()).isEqualTo(2);
    }

    @Test
    void differentTeamsAtTheWinningPriorityConflict() {
        ClaimInput older = claim(2, PAYMENTS).observed(NOW.minusSeconds(600)).build();
        ClaimInput newer = claim(2, IDENTITY).observed(NOW).build();
        ClaimInput lower = claim(5, PAYMENTS).build();
        DirectResult result = OwnershipResolver.resolve(List.of(older, newer, lower), NOW);
        assertThat(result.status()).isEqualTo(Status.CONFLICT);
        assertThat(result.teamId()).isNull();
        assertThat(result.conflictTeamIds()).containsExactly(PAYMENTS, IDENTITY);
        assertThat(result.reason()).isEqualTo("CONFLICTING_TEAMS_AT_PRIORITY");
    }

    @Test
    void sameTeamFromTwoSourcesAtOnePriorityIsOwned() {
        ClaimInput aws = claim(3, PAYMENTS).source("AWS").build();
        ClaimInput gcp = claim(3, PAYMENTS).source("GCP").build();
        DirectResult result = OwnershipResolver.resolve(List.of(aws, gcp), NOW);
        assertThat(result.status()).isEqualTo(Status.OWNED);
        assertThat(result.teamId()).isEqualTo(PAYMENTS);
    }

    @Test
    void reObservationWithNewTimestampsKeepsTheWatermark() {
        ClaimInput first = claim(2, PAYMENTS).observed(NOW.minusSeconds(600)).stale(NOW.plusSeconds(60)).build();
        ClaimInput again = new ClaimInput(first.claimId(), 2, PAYMENTS, "SERVICENOW", NOW, NOW.plusSeconds(86_400),
                NOW.plusSeconds(604_800), true, true, false);
        assertThat(OwnershipResolver.resolve(List.of(again), NOW).inputWatermark())
                .isEqualTo(OwnershipResolver.resolve(List.of(first), NOW).inputWatermark());
    }

    @Test
    void watermarkIsOrderIndependentAndChangesWithInputs() {
        ClaimInput a = claim(2, PAYMENTS).build();
        ClaimInput b = claim(5, IDENTITY).build();
        String forward = OwnershipResolver.resolve(List.of(a, b), NOW).inputWatermark();
        assertThat(OwnershipResolver.resolve(List.of(b, a), NOW).inputWatermark()).isEqualTo(forward);
        assertThat(OwnershipResolver.resolve(List.of(a), NOW).inputWatermark()).isNotEqualTo(forward);
        assertThat(forward).hasSize(64);
    }

    private static Builder claim(int priority, UUID team) {
        return new Builder(priority, team);
    }

    private static final class Builder {
        private final int priority;
        private final UUID team;
        private final UUID id = UUID.randomUUID();
        private String source = "SERVICENOW";
        private Instant observed = NOW.minusSeconds(60);
        private Instant stale;
        private Instant expires;
        private boolean teamActive = true;
        private boolean paused;

        Builder(int priority, UUID team) {
            this.priority = priority;
            this.team = team;
        }

        Builder source(String value) { source = value; return this; }
        Builder observed(Instant value) { observed = value; return this; }
        Builder stale(Instant value) { stale = value; return this; }
        Builder expires(Instant value) { expires = value; return this; }
        Builder teamArchived() { teamActive = false; return this; }
        Builder paused() { paused = true; return this; }

        ClaimInput build() {
            return new ClaimInput(id, priority, team, source, observed, stale, expires, true, teamActive, paused);
        }
    }
}
