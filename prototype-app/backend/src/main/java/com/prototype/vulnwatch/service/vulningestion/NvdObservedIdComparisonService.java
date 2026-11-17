package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.dto.NvdObservedIdComparisonResponse;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Bounded, read-only replay comparison. Never certifies the upstream source corpus. */
@Service
public class NvdObservedIdComparisonService {
    private final JdbcTemplate jdbc;

    public NvdObservedIdComparisonService(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional(readOnly = true, isolation = Isolation.REPEATABLE_READ, timeout = 30)
    public NvdObservedIdComparisonResponse compare(UUID first, UUID second, String feedKey,
                                                    Instant from, Instant to) {
        if (first == null || second == null || first.equals(second) || feedKey == null
                || !feedKey.matches("nvd:[0-9a-f]{32}") || from == null || to == null
                || !from.isBefore(to) || Duration.between(from, to).compareTo(Duration.ofDays(120)) > 0) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "Two distinct NVD runs, one filter scope and a bounded interval are required");
        }
        int firstCount = requireCompleteManifest(first, feedKey, from, to);
        int secondCount = requireCompleteManifest(second, feedKey, from, to);
        long onlyFirst = differenceCount(first, second, from, to);
        long onlySecond = differenceCount(second, first, from, to);
        return new NvdObservedIdComparisonResponse(first, second, feedKey, from, to,
                firstCount, secondCount, onlyFirst, onlySecond,
                differenceSample(first, second, from, to), differenceSample(second, first, from, to),
                onlyFirst == 0 && onlySecond == 0, "UNKNOWN");
    }

    private int requireCompleteManifest(UUID runId, String feedKey, Instant from, Instant to) {
        List<Integer> rows = jdbc.query("""
                select o.fetched_records from platform.feed_coverage_observations o
                join platform.sync_runs r on r.id=o.run_id
                where o.run_id=? and o.feed_key=? and o.source_system='nvd'
                  and o.interval_start=? and o.interval_end=? and lower(r.status)='completed'
                  and r.sync_type='NVD' and r.tenant_id is null
                  and o.ids_recorded_at is not null
                """, (rs, row) -> rs.getInt(1), runId, feedKey, Timestamp.from(from), Timestamp.from(to));
        if (rows.size() != 1) throw new ResponseStatusException(HttpStatus.CONFLICT,
                "Both runs must have completed observations for the same NVD scope and interval");
        Long ids = jdbc.queryForObject("""
                select count(*) from platform.nvd_observed_interval_ids
                where run_id=? and interval_start=? and interval_end=?
                """, Long.class, runId, Timestamp.from(from), Timestamp.from(to));
        if (ids == null || ids.longValue() != rows.get(0).longValue()) throw new ResponseStatusException(HttpStatus.CONFLICT,
                "An observed run has no complete CVE ID manifest");
        return rows.get(0);
    }

    private long differenceCount(UUID left, UUID right, Instant from, Instant to) {
        Long value = jdbc.queryForObject("""
                select count(*) from (
                  select cve_id from platform.nvd_observed_interval_ids
                  where run_id=? and interval_start=? and interval_end=?
                  except
                  select cve_id from platform.nvd_observed_interval_ids
                  where run_id=? and interval_start=? and interval_end=?
                ) missing
                """, Long.class, left, Timestamp.from(from), Timestamp.from(to),
                right, Timestamp.from(from), Timestamp.from(to));
        return value == null ? 0 : value;
    }

    private List<String> differenceSample(UUID left, UUID right, Instant from, Instant to) {
        return jdbc.query("""
                select cve_id from (
                  select cve_id from platform.nvd_observed_interval_ids
                  where run_id=? and interval_start=? and interval_end=?
                  except
                  select cve_id from platform.nvd_observed_interval_ids
                  where run_id=? and interval_start=? and interval_end=?
                ) missing order by cve_id limit 20
                """, (rs, row) -> rs.getString(1), left, Timestamp.from(from), Timestamp.from(to),
                right, Timestamp.from(from), Timestamp.from(to));
    }
}
