package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CbomFindingStatus;
import com.prototype.vulnwatch.domain.CbomRiskFinding;
import com.prototype.vulnwatch.domain.CbomRiskSeverity;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CbomRiskFindingRepository extends JpaRepository<CbomRiskFinding, UUID> {

    Optional<CbomRiskFinding> findByTenant_IdAndComponent_IdAndFindingFingerprint(
            UUID tenantId,
            UUID componentId,
            String findingFingerprint
    );

    List<CbomRiskFinding> findByTenant_Id(UUID tenantId);

    List<CbomRiskFinding> findByTenant_IdAndComponent_IdIn(UUID tenantId, Collection<UUID> componentIds);

    List<CbomRiskFinding> findByTenant_IdAndComponent_Id(UUID tenantId, UUID componentId);

    /** Findings reported by one CBOM document, for withdrawing its evidence when it goes. */
    @Query("""
        SELECT f FROM CbomRiskFinding f WHERE f.component.sourceBom.id = :sourceBomId
        """)
    List<CbomRiskFinding> findBySourceBomId(@Param("sourceBomId") UUID sourceBomId);

    List<CbomRiskFinding> findByTenant_IdAndComponent_Asset_IdAndStatusOrderBySeverityAscCreatedAtDesc(
            UUID tenantId,
            UUID assetId,
            CbomFindingStatus status
    );

    List<CbomRiskFinding> findByTenant_IdAndComponent_Asset_IdAndSeverityAndStatusOrderByCreatedAtDesc(
            UUID tenantId,
            UUID assetId,
            CbomRiskSeverity severity,
            CbomFindingStatus status
    );

    Optional<CbomRiskFinding> findByIdAndTenant_Id(UUID id, UUID tenantId);

    @Query("""
        SELECT f FROM CbomRiskFinding f
        WHERE f.tenant.id = :tenantId
          AND f.component.asset.id = :assetId
          AND f.status IN :statuses
        """)
    List<CbomRiskFinding> findForAssetAndStatuses(
            @Param("tenantId") UUID tenantId,
            @Param("assetId") UUID assetId,
            @Param("statuses") Collection<CbomFindingStatus> statuses
    );
}
