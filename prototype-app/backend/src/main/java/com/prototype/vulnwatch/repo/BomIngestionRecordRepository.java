package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomStatus;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

public interface BomIngestionRecordRepository extends JpaRepository<BomIngestionRecord, UUID> {
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from BomIngestionRecord r where r.assetId = :assetId order by r.id")
    List<BomIngestionRecord> lockAssetRecords(@org.springframework.data.repository.query.Param("assetId") UUID assetId);

    List<BomIngestionRecord> findByTenant_IdOrderByIngestedAtDesc(UUID tenantId, Pageable pageable);

    List<BomIngestionRecord> findByTenant_IdAndStatusOrderByIngestedAtDesc(UUID tenantId, BomStatus status, Pageable pageable);

    List<BomIngestionRecord> findByTenant_IdAndStatus(UUID tenantId, BomStatus status);

    List<BomIngestionRecord> findByTenant_IdAndAssetIdInAndStatusOrderByIngestedAtDesc(
            UUID tenantId,
            Collection<UUID> assetIds,
            BomStatus status
    );

    List<BomIngestionRecord> findByTenant_IdAndAssetIdAndStatusOrderByIngestedAtDesc(
            UUID tenantId,
            UUID assetId,
            BomStatus status
    );

    long countByTenant_IdAndStatus(UUID tenantId, BomStatus status);

    /** Every document version for an asset, any status, for reconstructing its source chains. */
    List<BomIngestionRecord> findByAssetId(UUID assetId);

    /** Assets whose documents predate source tracking and so still need backfilling. */
    @Query("""
        SELECT DISTINCT r.assetId FROM BomIngestionRecord r
        WHERE r.sourceId IS NULL AND r.assetId IS NOT NULL
        """)
    List<UUID> findAssetIdsAwaitingSourceBackfill(Pageable pageable);
}
