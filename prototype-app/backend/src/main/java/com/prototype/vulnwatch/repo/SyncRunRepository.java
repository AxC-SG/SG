package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SyncRun;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SyncRunRepository extends JpaRepository<SyncRun, UUID> {
    // One candidate per supported type keeps a blocked family from filling the bounded poll.
    @Query(value="""
            select candidate.* from platform.sync_runs candidate
            join (
                select distinct on (upper(sync_type)) id from platform.sync_runs
                where tenant_id is null and run_scope='PLATFORM_VULNERABILITY'
                  and lower(status)='queued' and upper(sync_type) in ('KEV','GHSA','CSAF_MICROSOFT','CSAF_REDHAT','EUVD','JVN','NVD','NVD_FULL','VEX_ASSERTION_REPAIR','VEX_ROLLOUT_BACKFILL','OSV','EPSS','EOL_CATALOG_REFRESH','EOL_RELEASE_REFRESH','EOL_MAPPING_RESOLVE','EOL_DENORMALIZE','EOL_FULL_REFRESH','EOL_DATE_SWEEP')
                order by upper(sync_type),started_at,id
            ) queued on queued.id=candidate.id
            order by candidate.started_at,candidate.id limit 100
            """,nativeQuery=true)
    List<SyncRun> findQueuedPlatformVulnerabilityRuns();
    List<SyncRun> findTop10ByOrderByStartedAtDesc();
    List<SyncRun> findAllByOrderByStartedAtDesc();
    List<SyncRun> findByStatusIgnoreCase(String status);
    List<SyncRun> findByStartedAtGreaterThanEqual(Instant fromInclusive);
    Optional<SyncRun> findTopBySyncTypeIgnoreCaseOrderByStartedAtDesc(String syncType);
    Optional<SyncRun> findTopBySyncTypeIgnoreCaseAndTenant_IdOrderByStartedAtDesc(String syncType, UUID tenantId);
    List<SyncRun> findByTenant_IdOrderByStartedAtDesc(UUID tenantId);
    List<SyncRun> findByRunScopeIgnoreCaseOrderByStartedAtDesc(String runScope);

    @Query("""
            select r
            from SyncRun r
            where lower(r.status) in :statuses
            order by r.startedAt asc
            """)
    List<SyncRun> findQueueByStatuses(@Param("statuses") List<String> statuses);

    @Query("""
            select r
            from SyncRun r
            where r.tenant.id = :tenantId
              and lower(r.status) in :statuses
            order by r.startedAt asc
            """)
    List<SyncRun> findQueueByTenantAndStatuses(@Param("tenantId") UUID tenantId, @Param("statuses") List<String> statuses);

    @Query("""
            select r
            from SyncRun r
            where lower(r.syncType) = lower(:syncType)
              and lower(r.status) in :statuses
            order by r.startedAt desc
            """)
    List<SyncRun> findActiveRunsBySyncType(
            @Param("syncType") String syncType,
            @Param("statuses") List<String> statuses
    );

    @Query("""
            select r
            from SyncRun r
            where r.tenant.id = :tenantId
              and lower(r.syncType) = lower(:syncType)
              and lower(r.status) in :statuses
            order by r.startedAt desc
            """)
    List<SyncRun> findActiveRunsByTenantAndSyncType(
            @Param("tenantId") UUID tenantId,
            @Param("syncType") String syncType,
            @Param("statuses") List<String> statuses
    );

    @Query("""
            select r
            from SyncRun r
            where lower(r.runScope) = lower(:runScope)
            order by r.startedAt desc
            """)
    List<SyncRun> findByRunScope(@Param("runScope") String runScope, Sort sort);

    void deleteByTenant_Id(UUID tenantId);
}
