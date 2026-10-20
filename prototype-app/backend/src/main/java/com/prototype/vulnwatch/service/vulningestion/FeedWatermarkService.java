package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.service.TenantContext;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Optional;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** Completed intervals only. Partial pages are replayed through the existing idempotent ingestion path. */
@Service
public class FeedWatermarkService {
    private final JdbcTemplate jdbc;
    public FeedWatermarkService(JdbcTemplate jdbc) { this.jdbc = jdbc; }
    public Optional<Instant> completedUntil(String feedKey) {
        return TenantContext.runAsPlatform(() -> jdbc.query(
                "select completed_until from platform.feed_sync_watermarks where feed_key = ?",
                (rs, row) -> rs.getTimestamp(1).toInstant(), feedKey).stream().findFirst());
    }
    @org.springframework.transaction.annotation.Transactional
    public void complete(String feedKey, Instant until) {
        TenantContext.runAsPlatform(() -> jdbc.update("""
                insert into platform.feed_sync_watermarks(feed_key, completed_until, updated_at)
                values (?, ?, now()) on conflict (feed_key) do update
                  set completed_until = greatest(feed_sync_watermarks.completed_until, excluded.completed_until),
                      updated_at = now()
                """, feedKey, Timestamp.from(until)));
    }
}
