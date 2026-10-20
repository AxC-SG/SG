package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class ScheduleOccurrenceTest {
    @Test void delayedCallbacksUseTheExactUtcOccurrence() {
        assertEquals(Instant.parse("2026-10-18T02:00:00Z"),
                ScheduleOccurrence.due("0 0 2 * * SUN", Instant.parse("2026-10-18T02:00:42Z")));
        assertNull(ScheduleOccurrence.due("0 0 2 * * SUN", Instant.parse("2026-10-18T02:02:00Z")));
    }
    @Test void frequentSchedulesChooseTheLatestDueInstant() {
        assertEquals(Instant.parse("2026-10-20T12:00:45Z"),
                ScheduleOccurrence.due("*/15 * * * * *", Instant.parse("2026-10-20T12:00:49Z")));
        assertThrows(IllegalArgumentException.class, () -> ScheduleOccurrence.due("invalid", Instant.now()));
    }
}
