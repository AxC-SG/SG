package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class OwnershipSourcePolicyTest {

    private static final Instant T0 = Instant.parse("2026-11-14T00:00:00Z");

    @Test
    void staleUsesTheTwentyFourHourFloorForShortIntervals() {
        assertThat(OwnershipSourcePolicy.staleAfter(T0, Duration.ofMinutes(15))).isEqualTo(T0.plus(Duration.ofHours(24)));
        assertThat(OwnershipSourcePolicy.staleAfter(T0, Duration.ofHours(12))).isEqualTo(T0.plus(Duration.ofHours(24)));
    }

    @Test
    void staleIsTwiceTheIntervalOnceThatExceedsTheFloor() {
        assertThat(OwnershipSourcePolicy.staleAfter(T0, Duration.ofHours(24))).isEqualTo(T0.plus(Duration.ofHours(48)));
        assertThat(OwnershipSourcePolicy.staleAfter(T0, Duration.ofDays(7))).isEqualTo(T0.plus(Duration.ofDays(14)));
    }

    @Test
    void expiryUsesTheSeventyTwoHourFloorAndThirtyDayCap() {
        assertThat(OwnershipSourcePolicy.expiresAt(T0, Duration.ofMinutes(15))).isEqualTo(T0.plus(Duration.ofHours(72)));
        assertThat(OwnershipSourcePolicy.expiresAt(T0, Duration.ofHours(24))).isEqualTo(T0.plus(Duration.ofHours(72)));
        assertThat(OwnershipSourcePolicy.expiresAt(T0, Duration.ofDays(5))).isEqualTo(T0.plus(Duration.ofDays(15)));
        assertThat(OwnershipSourcePolicy.expiresAt(T0, Duration.ofDays(7))).isEqualTo(T0.plus(Duration.ofDays(21)));
    }

    @Test
    void expiryIsLaterThanStaleForEveryAllowedInterval() {
        for (Duration interval = OwnershipSourcePolicy.MIN_INTERVAL; interval.compareTo(OwnershipSourcePolicy.MAX_INTERVAL) <= 0;
             interval = interval.plusMinutes(97)) {
            assertThat(OwnershipSourcePolicy.expiresAt(T0, interval)).isAfter(OwnershipSourcePolicy.staleAfter(T0, interval));
        }
        assertThat(OwnershipSourcePolicy.expiresAt(T0, OwnershipSourcePolicy.MAX_INTERVAL))
                .isAfter(OwnershipSourcePolicy.staleAfter(T0, OwnershipSourcePolicy.MAX_INTERVAL));
    }

    @Test
    void intervalsOutsideFifteenMinutesToSevenDaysAreRejected() {
        assertThat(OwnershipSourcePolicy.requireValidInterval(Duration.ofMinutes(15))).isEqualTo(Duration.ofMinutes(15));
        assertThat(OwnershipSourcePolicy.requireValidInterval(Duration.ofDays(7))).isEqualTo(Duration.ofDays(7));
        assertThatThrownBy(() -> OwnershipSourcePolicy.requireValidInterval(Duration.ofMinutes(14)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OwnershipSourcePolicy.requireValidInterval(Duration.ofDays(7).plusSeconds(1)))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> OwnershipSourcePolicy.requireValidInterval(null)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void anomalyNeedsBothTheMinimumCountAndTenPercent() {
        assertThat(OwnershipSourcePolicy.anomalous(99, 100)).as("below 100 changes, even at 99%").isFalse();
        assertThat(OwnershipSourcePolicy.anomalous(100, 1000)).as("exactly 100 and exactly 10%").isTrue();
        assertThat(OwnershipSourcePolicy.anomalous(100, 1001)).as("100 changes but under 10%").isFalse();
        assertThat(OwnershipSourcePolicy.anomalous(100, 100)).isTrue();
        assertThat(OwnershipSourcePolicy.anomalous(5000, 100_000)).as("5% of a large source").isFalse();
    }

    @Test
    void tenThousandChangesPauseRegardlessOfPercentage() {
        assertThat(OwnershipSourcePolicy.anomalous(9_999, 1_000_000)).isFalse();
        assertThat(OwnershipSourcePolicy.anomalous(10_000, 1_000_000)).isTrue();
    }

    @Test
    void aFirstLoadWithNothingActiveNeverPauses() {
        assertThat(OwnershipSourcePolicy.anomalous(0, 0)).isFalse();
    }
}
