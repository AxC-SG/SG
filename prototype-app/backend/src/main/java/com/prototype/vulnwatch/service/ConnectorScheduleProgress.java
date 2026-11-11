package com.prototype.vulnwatch.service;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ConnectorScheduleProgress {

    private static final long POLL_SECONDS = 300;

    enum Kind { AWS_DISCOVERY, GITHUB_SOURCE }

    private final JdbcTemplate jdbc;

    public ConnectorScheduleProgress(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Advances the high-water mark inside the transaction that accepts the ingestion job. */
    @Transactional(propagation = Propagation.MANDATORY)
    public boolean advance(UUID tenantId, Kind kind, UUID sourceId, Instant sweepStartedAt) {
        long occurrence = Math.floorDiv(sweepStartedAt.getEpochSecond(), POLL_SECONDS) * POLL_SECONDS;
        return jdbc.update("""
                insert into platform.connector_schedule_progress as progress
                    (tenant_id, schedule_kind, source_id, last_occurrence_at)
                values (?, ?, ?, ?)
                on conflict (tenant_id, schedule_kind, source_id) do update
                   set last_occurrence_at = excluded.last_occurrence_at
                 where progress.last_occurrence_at < excluded.last_occurrence_at
                """, tenantId, kind.name(), sourceId, Timestamp.from(Instant.ofEpochSecond(occurrence))) == 1;
    }

    @Transactional(propagation = Propagation.MANDATORY)
    public void removeGithubSource(UUID tenantId, UUID sourceId) {
        jdbc.update("""
                delete from platform.connector_schedule_progress
                where tenant_id = ? and schedule_kind = 'GITHUB_SOURCE' and source_id = ?
                """, tenantId, sourceId);
    }
}
