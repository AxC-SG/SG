package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.FixAsset;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface FixAssetRepository extends JpaRepository<FixAsset, UUID> {
    Optional<FixAsset> findByFixIdAndAssetIdAndProvider(UUID fixId, UUID assetId, String provider);
    List<FixAsset> findByFixId(UUID fixId, Pageable pageable);
    long countByFixId(UUID fixId);
    List<FixAsset> findByAssetId(UUID assetId);
    List<FixAsset> findByFixIdInAndAssetId(Collection<UUID> fixIds, UUID assetId);

    /** Per fix: applicable assets and remediated assets, for coverage. */
    @Query("""
            select fa.fixId,
                   count(distinct case when fa.status not in ('NOT_APPLICABLE','SUPERSEDED') then fa.assetId end),
                   count(distinct case when fa.status in ('INSTALLED','APPLIED') then fa.assetId end)
              from FixAsset fa
             where fa.fixId in :fixIds
             group by fa.fixId
            """)
    List<Object[]> coverage(@Param("fixIds") Collection<UUID> fixIds);
}
