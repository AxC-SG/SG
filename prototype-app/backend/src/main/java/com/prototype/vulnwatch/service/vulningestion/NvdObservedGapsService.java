package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.dto.NvdObservedGapsResponse;
import com.prototype.vulnwatch.dto.NvdBaselinePlanResponse;
import com.prototype.vulnwatch.dto.NvdObservedScopesResponse;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Reports windows with no successful NVD interval observation for exactly one filter scope. */
@Service
public class NvdObservedGapsService {
    private static final int MAX_WINDOWS = 1000;
    private static final Duration MAX_PLAN_SPAN = Duration.ofDays(366L * 40);
    private static final Duration PARTITION_SPAN = Duration.ofDays(120);
    private final JdbcTemplate jdbc;

    public NvdObservedGapsService(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ, timeout = 15)
    public NvdObservedScopesResponse scopes(String afterFeedKey) {
        if (afterFeedKey != null && !afterFeedKey.matches("nvd:[0-9a-f]{32}")) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid NVD filter-scope cursor");
        }
        List<NvdObservedScopesResponse.Scope> rows = jdbc.query("""
                select feed_key,count(*),min(interval_start),max(interval_end)
                from platform.feed_coverage_observations o
                join platform.sync_runs r on r.id=o.run_id and lower(r.status)='completed'
                where o.source_system='nvd' and o.ids_recorded_at is not null
                  and o.feed_key>? and o.feed_key ~ '^nvd:[0-9a-f]{32}$'
                group by feed_key order by feed_key limit 51
                """, (rs, row) -> new NvdObservedScopesResponse.Scope(
                        rs.getString(1), rs.getLong(2), rs.getTimestamp(3).toInstant(),
                        rs.getTimestamp(4).toInstant()), afterFeedKey == null ? "" : afterFeedKey);
        boolean hasMore = rows.size() > 50;
        List<NvdObservedScopesResponse.Scope> items = List.copyOf(
                hasMore ? rows.subList(0, 50) : rows);
        return new NvdObservedScopesResponse(items, hasMore,
                hasMore ? items.get(items.size() - 1).feedKey() : null);
    }

    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ, timeout = 15)
    public NvdObservedGapsResponse inspect(String feedKey, Instant from, Instant to) {
        if (feedKey == null || !feedKey.matches("nvd:[0-9a-f]{32}") || from == null || to == null
                || !from.isBefore(to) || Duration.between(from, to).compareTo(Duration.ofDays(120)) > 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "A valid NVD filter-scope key and interval of at most 120 days are required");
        }
        var windows = jdbc.query("""
                select o.interval_start,o.interval_end from platform.feed_coverage_observations o
                join platform.sync_runs r on r.id=o.run_id and lower(r.status)='completed'
                where o.source_system='nvd' and o.ids_recorded_at is not null
                  and o.feed_key=? and o.interval_start<? and o.interval_end>?
                order by o.interval_start,o.interval_end limit ?
                """, (rs, row) -> new NvdObservedGapsResponse.Interval(
                        rs.getTimestamp(1).toInstant(), rs.getTimestamp(2).toInstant()),
                feedKey, Timestamp.from(to), Timestamp.from(from), MAX_WINDOWS + 1);
        if (windows.size() > MAX_WINDOWS) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Too many observed windows for this interval; choose a narrower interval");
        }
        var gaps = new ArrayList<NvdObservedGapsResponse.Interval>();
        Instant cursor = from;
        for (var window : windows) {
            Instant start = window.from().isBefore(from) ? from : window.from();
            Instant end = window.to().isAfter(to) ? to : window.to();
            if (start.isAfter(cursor)) gaps.add(new NvdObservedGapsResponse.Interval(cursor, start));
            if (end.isAfter(cursor)) cursor = end;
        }
        if (cursor.isBefore(to)) gaps.add(new NvdObservedGapsResponse.Interval(cursor, to));
        return new NvdObservedGapsResponse(feedKey, from, to, windows.size(),
                java.util.List.copyOf(gaps), "UNKNOWN");
    }

    /** Bounded operator checklist. An observed window is not proof of a complete upstream snapshot. */
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ, timeout = 30)
    public NvdBaselinePlanResponse plan(String feedKey, Instant from, Instant to) {
        if (feedKey == null || !feedKey.matches("nvd:[0-9a-f]{32}") || from == null || to == null
                || !from.isBefore(to) || Duration.between(from, to).compareTo(MAX_PLAN_SPAN) > 0
                || to.isAfter(Instant.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "A past NVD scope and interval of at most 40 years are required");
        }
        var partitions = new ArrayList<NvdBaselinePlanResponse.Partition>();
        for (Instant start = from; start.isBefore(to); ) {
            Instant end = start.plus(PARTITION_SPAN);
            if (end.isAfter(to)) end = to;
            var observed = inspect(feedKey, start, end);
            partitions.add(new NvdBaselinePlanResponse.Partition(start, end,
                    observed.observedWindowCount(), observed.unobservedIntervals()));
            start = end;
        }
        return new NvdBaselinePlanResponse(feedKey, from, to, List.copyOf(partitions), "UNKNOWN");
    }
}
