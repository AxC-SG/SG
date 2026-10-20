package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.IngestionJob;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface IngestionJobRepository extends JpaRepository<IngestionJob, UUID> {

    @Query(value = """
            select * from ingestion_jobs where status='RUNNING'
              and job_type in ('REMOTE_ENDPOINT','GITHUB_REPOSITORY','GITHUB_GHCR','AWS_DISCOVERY','SERVICENOW_CMDB','AI_SECURITY_AWS_BEDROCK','AI_SECURITY_AZURE_DISCOVERY','AI_SECURITY_COPILOT_STUDIO','AI_GRID_BOM_PROJECTION')
              and lease_expires_at <= clock_timestamp()
              order by lease_expires_at, id limit :limit
            """, nativeQuery = true)
    List<IngestionJob> pollExpiredAttempts(@Param("limit") int limit);

    @Query(value="select * from ingestion_jobs where job_type in ('GITHUB_REPOSITORY','GITHUB_GHCR') and status in ('QUEUED','RUNNING') and payload_json::jsonb->>'sourceId'=:sourceId order by requested_at,id limit 1",nativeQuery=true)
    Optional<IngestionJob> findActiveGithubSource(@Param("sourceId") String sourceId);

    interface StatusSummaryRow {
        long getQueuedCount();
        long getRunningCount();
        Instant getOldestVisibleQueuedAt();
        Instant getOldestRunningStartedAt();
    }

    @Query(value = """
            SELECT * FROM ingestion_jobs
             WHERE status = 'QUEUED'
               AND visible_at <= now()
             ORDER BY requested_at, id
             LIMIT :limit
             FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<IngestionJob> pollPending(@Param("limit") int limit);

    @Query(value = """
            SELECT * FROM ingestion_jobs
             WHERE status = 'QUEUED'
               AND visible_at <= now()
               AND job_type <> :excludedJobType
             ORDER BY requested_at, id
             LIMIT :limit
             FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<IngestionJob> pollPendingExcluding(
            @Param("excludedJobType") String excludedJobType,
            @Param("limit") int limit);

    @Query(value = """
            SELECT * FROM ingestion_jobs
             WHERE status = 'QUEUED'
               AND visible_at <= now()
               AND job_type NOT IN (:excludedJobTypes)
               AND job_type IN ('REMOTE_ENDPOINT','GITHUB_REPOSITORY','GITHUB_GHCR','AWS_DISCOVERY','SERVICENOW_CMDB')
             ORDER BY requested_at, id
             LIMIT :limit
             FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<IngestionJob> pollPendingExcludingJobTypes(
            @Param("excludedJobTypes") Collection<String> excludedJobTypes,
            @Param("limit") int limit);

    @Query(value = """
            SELECT * FROM ingestion_jobs
             WHERE status = 'QUEUED'
               AND visible_at <= now()
               AND job_type = :jobType
             ORDER BY requested_at, id
             LIMIT :limit
             FOR UPDATE SKIP LOCKED
            """, nativeQuery = true)
    List<IngestionJob> pollPendingByJobType(@Param("jobType") String jobType, @Param("limit") int limit);

    @Query(value = """
            SELECT * FROM ingestion_jobs
             WHERE dedupe_key = :dedupeKey
               AND status IN ('QUEUED', 'RUNNING')
             ORDER BY requested_at DESC, id DESC
             LIMIT 1
             FOR UPDATE
            """, nativeQuery = true)
    Optional<IngestionJob> findActiveByDedupeKeyForUpdate(@Param("dedupeKey") String dedupeKey);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status = :status")
    long countByStatusValue(@Param("status") String status);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status = :status AND j.jobType <> :excludedJobType")
    long countByStatusExcludingJobType(
            @Param("status") String status,
            @Param("excludedJobType") String excludedJobType);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status = :status AND j.jobType NOT IN :excludedJobTypes")
    long countByStatusExcludingJobTypes(
            @Param("status") String status,
            @Param("excludedJobTypes") Collection<String> excludedJobTypes);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status = :status AND j.jobType = :jobType")
    long countByStatusAndJobType(@Param("status") String status, @Param("jobType") String jobType);

    @Query(value = """
            select
              coalesce(sum(case when status = 'QUEUED' then 1 else 0 end), 0) as queuedCount,
              coalesce(sum(case when status = 'RUNNING' then 1 else 0 end), 0) as runningCount,
              min(case
                    when status = 'QUEUED' and visible_at <= :before
                    then visible_at
                  end) as oldestVisibleQueuedAt,
              min(case
                    when status = 'RUNNING'
                    then started_at
                  end) as oldestRunningStartedAt
            from ingestion_jobs
            """, nativeQuery = true)
    StatusSummaryRow summarizeStatus(@Param("before") Instant before);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.status IN :statuses AND j.jobType IN ('REMOTE_ENDPOINT','GITHUB_REPOSITORY','GITHUB_GHCR')")
    long countByStatusIn(@Param("statuses") Collection<String> statuses);

    @Query("""
            select min(j.visibleAt)
            from IngestionJob j
            where j.status = :status
              and j.visibleAt <= :before
            """)
    Instant findOldestVisibleAtByStatusBefore(@Param("status") String status, @Param("before") Instant before);

    @Query("SELECT MIN(j.startedAt) FROM IngestionJob j WHERE j.status = :status")
    Instant findOldestStartedAtByStatus(@Param("status") String status);

    List<IngestionJob> findByStatus(String status);

    @Query("SELECT COUNT(j) FROM IngestionJob j WHERE j.requestedAt >= :since AND j.jobType IN ('REMOTE_ENDPOINT','GITHUB_REPOSITORY','GITHUB_GHCR')")
    long countAcceptedSince(@Param("since") Instant since);

    Page<IngestionJob> findAllByOrderByRequestedAtDescIdDesc(Pageable pageable);
}
