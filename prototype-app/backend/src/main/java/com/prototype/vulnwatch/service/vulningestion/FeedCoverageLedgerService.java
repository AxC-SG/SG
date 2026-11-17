package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.service.TenantContext;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Records bounded source observations. Rows are not historical-completeness certificates. */
@Service
public class FeedCoverageLedgerService {
    private final JdbcTemplate jdbc;

    public FeedCoverageLedgerService(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Transactional
    public void observeNvdInterval(UUID runId, String feedKey, Instant start, Instant end,
                                   int fetched, Set<String> observedIds) {
        if (runId == null || feedKey == null || !feedKey.startsWith("nvd:")
                || start == null || end == null || !start.isBefore(end) || fetched < 0
                || observedIds == null || observedIds.size() != fetched
                || observedIds.stream().anyMatch(id -> id == null || !id.matches("CVE-[0-9]{4}-[0-9]{4,}"))) {
            throw new IllegalArgumentException("Valid NVD run, scope, interval and complete ID set are required");
        }
        TenantContext.runAsPlatform(() -> {
            int updated = jdbc.update("""
                insert into platform.feed_coverage_observations
                  (run_id, source_system, feed_key, interval_start, interval_end, fetched_records, ids_recorded_at)
                values (?, 'nvd', ?, ?, ?, ?, now())
                on conflict (run_id, interval_start, interval_end) do update
                  set fetched_records = excluded.fetched_records, observed_at = now(),
                      ids_recorded_at = excluded.ids_recorded_at
                where feed_coverage_observations.feed_key = excluded.feed_key
                """, runId, feedKey, Timestamp.from(start), Timestamp.from(end), fetched);
            if (updated != 1) throw new IllegalStateException("NVD coverage scope changed for an existing interval");
            // The manifest and its observation share one transaction; a failed batch cannot certify coverage.
            jdbc.update("""
                    delete from platform.nvd_observed_interval_ids
                    where run_id=? and interval_start=? and interval_end=?
                    """, runId, Timestamp.from(start), Timestamp.from(end));
            jdbc.batchUpdate("""
                    insert into platform.nvd_observed_interval_ids
                      (run_id, interval_start, interval_end, cve_id) values (?, ?, ?, ?)
                    """, observedIds, 500, (ps, id) -> {
                ps.setObject(1, runId);
                ps.setTimestamp(2, Timestamp.from(start));
                ps.setTimestamp(3, Timestamp.from(end));
                ps.setString(4, id);
            });
            return null;
        });
    }
}
