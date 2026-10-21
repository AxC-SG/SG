package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.FindingDeltaQueueEntry;
import java.time.Instant;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface FindingDeltaQueueEntryRepository extends JpaRepository<FindingDeltaQueueEntry, Long> {
    boolean existsByDedupeKeyAndStatus(String dedupeKey,String status);
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("select e from FindingDeltaQueueEntry e where e.id=:id and e.status='PROCESSING' and e.attemptCount=:attempt")
    java.util.Optional<FindingDeltaQueueEntry> lockProcessingAttempt(@Param("id") Long id, @Param("attempt") int attempt);

    interface EventTypeCountRow {
        String getEventType();
        long getEntryCount();
    }

    interface StatusSummaryRow {
        long getPendingCount();
        long getProcessingCount();
        long getFailedCount();
        Instant getOldestVisiblePendingAt();
        Instant getOldestProcessingStartedAt();
        Instant getLatestCompletedAt();
    }

    /**
     * Atomically claim up to {@code limit} PENDING entries that are ready to process.
     * SKIP LOCKED ensures concurrent pollers never pick the same row.
     */
    @Query(value = """
            SELECT * FROM finding_delta_queue
             WHERE status = 'PENDING'
               AND visible_after <= now()
             ORDER BY id
             LIMIT :limit
             FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<FindingDeltaQueueEntry> pollPending(@Param("limit") int limit);

    /**
     * Insert a new event, silently ignoring duplicates for the same dedupe_key
     * that are already PENDING. Returns 1 if inserted, 0 if skipped.
     */
    @Modifying
    @Transactional
    @Query(value = """
            INSERT INTO finding_delta_queue
                (event_type, tenant_id, component_id, vulnerability_id,
                 source_key, source_tag, dedupe_key)
            VALUES
                (:eventType, COALESCE(:tenantId, (
                    SELECT id FROM platform.tenants WHERE schema_name = current_schema()
                 )), :componentId, :vulnerabilityId,
                 :sourceKey, :sourceTag, :dedupeKey)
            ON CONFLICT (dedupe_key) WHERE status = 'PENDING' DO NOTHING
            """, nativeQuery = true)
    int insertIfNotDuplicate(
            @Param("eventType")      String eventType,
            @Param("tenantId")       java.util.UUID tenantId,
            @Param("componentId")    java.util.UUID componentId,
            @Param("vulnerabilityId") java.util.UUID vulnerabilityId,
            @Param("sourceKey")      String sourceKey,
            @Param("sourceTag")      String sourceTag,
            @Param("dedupeKey")      String dedupeKey
    );

    @Query("SELECT COUNT(e) FROM FindingDeltaQueueEntry e WHERE e.status = 'PENDING'")
    long countPending();

    @Query("SELECT COUNT(e) FROM FindingDeltaQueueEntry e WHERE e.status = 'PROCESSING'")
    long countProcessing();

    @Query(value = """
            select * from finding_delta_queue where status='PROCESSING'
              and (processing_started_at is null or processing_started_at<=:cutoff)
             order by id limit 100 for update skip locked
            """, nativeQuery = true)
    List<FindingDeltaQueueEntry> findStaleProcessingEntries(@Param("cutoff") Instant cutoff);

    @Query(value = """
            select
              coalesce(sum(case when status = 'PENDING' then 1 else 0 end), 0) as pendingCount,
              coalesce(sum(case when status = 'PROCESSING' then 1 else 0 end), 0) as processingCount,
              coalesce(sum(case when status = 'FAILED' then 1 else 0 end), 0) as failedCount,
              min(case
                    when status = 'PENDING' and visible_after <= :before
                    then visible_after
                  end) as oldestVisiblePendingAt,
              min(case
                    when status = 'PROCESSING'
                    then processing_started_at
                  end) as oldestProcessingStartedAt,
              max(case
                    when status = 'DONE'
                    then completed_at
                  end) as latestCompletedAt
            from finding_delta_queue
            """, nativeQuery = true)
    StatusSummaryRow summarizeStatus(@Param("before") Instant before);

    @Query("""
            select e.eventType as eventType, count(e) as entryCount
            from FindingDeltaQueueEntry e
            where e.status = 'PENDING'
            group by e.eventType
            """)
    List<EventTypeCountRow> countPendingByEventType();

    @Query("SELECT COUNT(e) FROM FindingDeltaQueueEntry e WHERE e.status = 'FAILED'")
    long countFailed();

    @Query("SELECT MAX(e.completedAt) FROM FindingDeltaQueueEntry e WHERE e.status = 'DONE'")
    Instant findLatestCompletedAt();

    @Query("""
            select min(e.visibleAfter)
            from FindingDeltaQueueEntry e
            where e.status = 'PENDING'
              and e.visibleAfter <= :before
            """)
    Instant findOldestVisiblePendingAt(@Param("before") Instant before);

    @Query("SELECT MIN(e.processingStartedAt) FROM FindingDeltaQueueEntry e WHERE e.status = 'PROCESSING'")
    Instant findOldestProcessingStartedAt();

    /**
     * BLG-014: Count PENDING entries whose visible_after is before the given threshold —
     * i.e. items that should have been processed but have not been claimed yet.
     * Used by SloMetricsService to detect queue staleness.
     */
    @Query("SELECT COUNT(e) FROM FindingDeltaQueueEntry e WHERE e.status = 'PENDING' AND e.visibleAfter <= :threshold")
    long countStaleVisible(@Param("threshold") Instant threshold);
}
