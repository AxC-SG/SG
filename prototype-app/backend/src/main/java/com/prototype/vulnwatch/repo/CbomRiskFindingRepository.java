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

    List<CbomRiskFinding> findByTenant_IdAndIdIn(UUID tenantId, Collection<UUID> ids);

    /** Ids of findings reported by components of one CBOM document. */
    @Query("SELECT f.id FROM CbomRiskFinding f WHERE f.component.sourceBom.id = :sourceBomId")
    List<UUID> findIdsBySourceBomId(@Param("sourceBomId") UUID sourceBomId);

    /**
     * Bounded drift detector for the mirror repair sweep. Returns CBOM findings whose canonical
     * CRYPTO row is missing although the finding is live, or is still OPEN although the finding
     * is no longer live. Content drift is not detected here; CBOM_DELTA producers own that.
     * Tenant-local: runs in the current tenant schema.
     */
    @Query(value = """
        SELECT r.id FROM cbom_risk_findings r
          JOIN cbom_components c ON c.id = r.cbom_component_id
          LEFT JOIN findings f ON f.fingerprint = 'cbom:' || r.id::text AND f.finding_kind = 'CRYPTO'
         WHERE (r.status = 'OPEN' AND c.active AND r.evidence_state <> 'WITHDRAWN' AND f.id IS NULL)
            OR (f.status = 'OPEN' AND r.status <> 'ACCEPTED'
                AND NOT (r.status = 'OPEN' AND c.active AND r.evidence_state <> 'WITHDRAWN'))
         ORDER BY r.id
         LIMIT :limit
        """, nativeQuery = true)
    List<UUID> findMirrorRepairCandidates(@Param("limit") int limit);

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
