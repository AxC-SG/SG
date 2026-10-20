package com.prototype.vulnwatch.service;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import org.springframework.scheduling.support.CronExpression;

/** Stable UTC identity for callbacks within the scheduler's one-minute lateness window. */
public final class ScheduleOccurrence {
    private ScheduleOccurrence() {}

    public static Instant due(String cron, Instant now) {
        CronExpression expression = CronExpression.parse(cron);
        ZonedDateTime end = now.atZone(ZoneOffset.UTC);
        ZonedDateTime next = expression.next(end.minusSeconds(61));
        Instant latest = null;
        while (next != null && !next.isAfter(end)) {
            latest = next.toInstant();
            next = expression.next(next);
        }
        return latest;
    }
}
