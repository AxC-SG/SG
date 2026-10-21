package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.dto.TopFindingMetricResponse;
import java.time.Instant;
import java.util.Collection;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaSpecificationExecutor;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FindingRepository extends JpaRepository<Finding, UUID>, JpaSpecificationExecutor<Finding> {
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("select f from Finding f where f.incidentId is not null order by f.id")
    List<Finding> findForIncidentSync();
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("select f from Finding f where f.status = :status and (:assetId is null or f.asset.id = :assetId) order by f.id")
    List<Finding> findForMaintenance(@Param("status") FindingStatus status, @Param("assetId") UUID assetId);

    interface VulnerabilityFindingCountRow {
        UUID getVulnerabilityId();
        long getFindingCount();
    }

    List<Finding> findAllByOrderByUpdatedAtDesc();
    Optional<Finding> findByTenantAndFingerprint(Tenant tenant, String fingerprint);
    @Query("""
            select f
            from Finding f
            where f.tenant = :tenant
              and f.policyId = :policyId
              and f.findingKind in ('AI_POSTURE', 'AI_EXPOSURE')
              and f.status in (com.prototype.vulnwatch.domain.FindingStatus.OPEN,
                               com.prototype.vulnwatch.domain.FindingStatus.SUPPRESSED)
            """)
    List<Finding> findOpenAiFindingsByTenantAndPolicy(
            @Param("tenant") Tenant tenant,
            @Param("policyId") String policyId
    );
    Page<Finding> findAllByOrderByUpdatedAtDesc(Pageable pageable);
    List<Finding> findByStatusOrderByUpdatedAtDesc(FindingStatus status);
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    List<Finding> findByStatusAndSuppressedUntilBeforeOrderById(FindingStatus status, Instant before);
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select f
            from Finding f
            where f.tenant = :tenant
              and f.status = :status
              and f.autoCloseEligibleAt < :before
            order by f.id
            """)
    List<Finding> findAutoCloseCandidates(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status,
            @Param("before") Instant before
    );
    List<Finding> findByAsset(Asset asset);
    List<Finding> findByAssetAndStatus(Asset asset, FindingStatus status);
    List<Finding> findByAsset_IdIn(Collection<UUID> assetIds);
    List<Finding> findByComponent(InventoryComponent component);
    List<Finding> findByComponent_IdIn(Collection<UUID> componentIds);
    @Query("""
            select f from Finding f
            join fetch f.component c
            left join fetch f.vulnerability
            where f.tenant.id = :tenantId
              and f.status = com.prototype.vulnwatch.domain.FindingStatus.OPEN
              and c.id in :componentIds
            """)
    List<Finding> findOpenByTenantAndComponentIds(
            @Param("tenantId") UUID tenantId,
            @Param("componentIds") Collection<UUID> componentIds
    );
    java.util.Optional<Finding> findFirstByComponent_IdAndVulnerability_Id(UUID componentId, UUID vulnerabilityId);
    List<Finding> findByVulnerability_Id(UUID vulnerabilityId);
    List<Finding> findByTenant_IdAndVulnerability_Id(UUID tenantId, UUID vulnerabilityId);
    List<Finding> findByTenant_IdAndVulnerability_IdIn(UUID tenantId, Collection<UUID> vulnerabilityIds);
    @Query("""
            select distinct f.tenant.id
            from Finding f
            where f.vulnerability.id = :vulnerabilityId
            """)
    Set<UUID> findDistinctTenantIdsByVulnerabilityId(@Param("vulnerabilityId") UUID vulnerabilityId);

    @Query("""
            select distinct f.component.id
            from Finding f
            where f.tenant = :tenant
              and f.status = :status
              and f.component is not null
            """)
    Set<UUID> findDistinctComponentIdsByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status
    );
    long countByVulnerabilityAndStatus(Vulnerability vulnerability, FindingStatus status);
    void deleteByAsset(Asset asset);
    @Query("select count(f) from Finding f where f.status=:status and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')")
    long countByStatus(@Param("status") FindingStatus status);
    @Query("select count(f) from Finding f where f.status=:status and f.confidenceScore>=:minConfidence and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')")
    long countByStatusAndConfidenceScoreGreaterThanEqual(@Param("status") FindingStatus status, @Param("minConfidence") double minConfidence);
    long countBySuppressedByRuleId(UUID suppressedByRuleId);
    long countByOwnerGroup(String ownerGroup);

    List<Finding> findBySuppressedByRuleId(UUID suppressedByRuleId);
    @Query("select count(f) from Finding f where f.status=:status and f.riskScore>=:minRiskScore and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')")
    long countByStatusAndRiskScoreGreaterThanEqual(@Param("status") FindingStatus status, @Param("minRiskScore") double minRiskScore);

    @Query("""
            select count(f)
            from Finding f
            join f.vulnerability v
            where f.status = :status and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME') and upper(v.severity) = upper(:severity)
            """)
    long countByStatusAndSeverity(
            @Param("status") FindingStatus status,
            @Param("severity") String severity
    );

    @Query("""
            select count(f)
            from Finding f
            join f.vulnerability v
            where (f.findingKind is null or f.findingKind <> 'AI_RUNTIME') and upper(coalesce(f.severityOverride, v.severity)) = upper(:severity)
            """)
    long countBySeverity(@Param("severity") String severity);

    @Query("""
            select coalesce(avg(f.riskScore), 0)
            from Finding f
            where f.tenant = :tenant and f.status = :status and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
            """)
    double averageRiskScoreByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status
    );

    @Query("""
            select coalesce(avg(f.confidenceScore), 0)
            from Finding f
            where f.tenant = :tenant and f.status = :status and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
            """)
    double averageConfidenceScoreByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status
    );

    @Query("""
            select new com.prototype.vulnwatch.dto.TopFindingMetricResponse(v.externalId, count(f))
            from Finding f
            join f.vulnerability v
            where f.tenant = :tenant and f.status = :status and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
            group by v.externalId
            order by count(f) desc
            """)
    List<TopFindingMetricResponse> findTopVulnerabilitiesByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status,
            Pageable pageable
    );

    @Query("""
            select new com.prototype.vulnwatch.dto.TopFindingMetricResponse(
                concat(concat(lower(c.ecosystem), ':'), lower(c.packageName)),
                count(f)
            )
            from Finding f
            join f.component c
            where f.tenant = :tenant and f.status = :status and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
            group by c.ecosystem, c.packageName
            order by count(f) desc
            """)
    List<TopFindingMetricResponse> findTopInstalledComponentsByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status,
            Pageable pageable
    );

    @Query("""
            select new com.prototype.vulnwatch.dto.TopFindingMetricResponse(
                concat(concat(a.name, ' ('), concat(a.identifier, ')')),
                count(f)
            )
            from Finding f
            join f.asset a
            where f.tenant = :tenant and f.status = :status and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
            group by a.name, a.identifier
            order by count(f) desc
            """)
    List<TopFindingMetricResponse> findTopAssetsByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status,
            Pageable pageable
    );

    @Query("""
            select new com.prototype.vulnwatch.dto.TopFindingMetricResponse(
                concat(concat(concat(v.externalId, ' | '), lower(c.ecosystem)), concat(':', lower(c.packageName))),
                count(f)
            )
            from Finding f
            join f.vulnerability v
            join f.component c
            where f.tenant = :tenant and f.status = :status and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
            group by v.externalId, c.ecosystem, c.packageName
            order by count(f) desc
            """)
    List<TopFindingMetricResponse> findTopVulnerabilityProductIdentitiesByTenantAndStatus(
            @Param("tenant") Tenant tenant,
            @Param("status") FindingStatus status,
            Pageable pageable
    );

    @Query("""
            select f.vulnerability.id, count(f)
            from Finding f
            where f.status = :status
              and f.vulnerability.id in :vulnerabilityIds
            group by f.vulnerability.id
            """)
    List<Object[]> countByVulnerabilityIdsAndStatus(
            @Param("vulnerabilityIds") List<UUID> vulnerabilityIds,
            @Param("status") FindingStatus status
    );

    @Query("""
            select
              f.vulnerability.id as vulnerabilityId,
              count(f) as findingCount
            from Finding f
            where f.status = :status
              and f.vulnerability.id in :vulnerabilityIds
            group by f.vulnerability.id
            """)
    List<VulnerabilityFindingCountRow> countByVulnerabilityIdsAndStatusGrouped(
            @Param("vulnerabilityIds") Collection<UUID> vulnerabilityIds,
            @Param("status") FindingStatus status
    );

    @Query("""
            select count(distinct f.id)
            from Finding f
            where f.status = :status
              and f.decisionState = :decisionState
              and exists (
                select 1
                from FindingEvent fe
                where fe.finding = f
                  and fe.eventType = :eventType
              )
            """)
    long countByStatusAndDecisionStateWithEvent(
            @Param("status") FindingStatus status,
            @Param("decisionState") FindingDecisionState decisionState,
            @Param("eventType") String eventType
    );

    @Query("""
            select distinct upper(v.severity)
            from Finding f
            join f.vulnerability v
            where f.tenant = :tenant and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
              and v.severity is not null
              and trim(v.severity) <> ''
            """)
    List<String> findDistinctSeveritiesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct f.status
            from Finding f
            where f.tenant = :tenant and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
            """)
    List<FindingStatus> findDistinctStatusesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct f.decisionState
            from Finding f
            where f.tenant = :tenant and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
            """)
    List<FindingDecisionState> findDistinctDecisionStatesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct lower(f.matchedBy)
            from Finding f
            where f.tenant = :tenant and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
              and f.matchedBy is not null
              and trim(f.matchedBy) <> ''
            """)
    List<String> findDistinctMatchMethodsByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct f.vexStatus
            from Finding f
            where f.tenant = :tenant and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
              and f.vexStatus is not null
              and trim(f.vexStatus) <> ''
            """)
    List<String> findDistinctVexStatusesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct f.vexFreshness
            from Finding f
            where f.tenant = :tenant and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
              and f.vexFreshness is not null
              and trim(f.vexFreshness) <> ''
            """)
    List<String> findDistinctVexFreshnessByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct f.vexProvider
            from Finding f
            where f.tenant = :tenant and (f.findingKind is null or f.findingKind <> 'AI_RUNTIME')
              and f.vexProvider is not null
              and trim(f.vexProvider) <> ''
            """)
    List<String> findDistinctVexProvidersByTenant(@Param("tenant") Tenant tenant);

    /** Findings that already have a linked ServiceNow incident (for daily status sync). */
    @Query("select f from Finding f where f.incidentId is not null")
    List<Finding> findAllWithIncidentId();

    /** Find findings for a set of component IDs matching a CVE external ID. */
    @Query("""
            select f from Finding f
            where f.component.id in :componentIds
              and f.vulnerability.externalId = :cveId
            """)
    List<Finding> findByComponentIdInAndVulnerabilityCveId(
            @Param("componentIds") Collection<UUID> componentIds,
            @Param("cveId") String cveId
    );

    /** Count open findings grouped by component ID for a set of component IDs. */
    @Query("""
            select f.component.id, count(f)
            from Finding f
            where f.component.id in :componentIds
              and f.status = com.prototype.vulnwatch.domain.FindingStatus.OPEN
            group by f.component.id
            """)
    List<Object[]> countOpenByComponentIds(@Param("componentIds") Collection<UUID> componentIds);

    /** Count open findings grouped by asset ID for a set of asset IDs.
     *  Covers both direct asset findings (f.asset_id) and component-scoped findings
     *  (f.component_id → inventory_components.asset_id). */
    @Query(value = """
            SELECT COALESCE(f.asset_id, ic.asset_id) AS resolved_asset_id, count(f.id)
            FROM findings f
            LEFT JOIN inventory_components ic ON ic.id = f.component_id
            WHERE f.tenant_id = :tenantId
              AND f.status = 'OPEN'
              AND (f.asset_id IN :assetIds OR ic.asset_id IN :assetIds)
            GROUP BY COALESCE(f.asset_id, ic.asset_id)
            """, nativeQuery = true)
    List<Object[]> countOpenFindingsByAssetIds(
            @Param("tenantId") UUID tenantId,
            @Param("assetIds") Collection<UUID> assetIds
    );

    /** Count open findings grouped by ecosystem and packageName for a tenant. */
    @Query(value = """
            SELECT lower(ic.ecosystem), lower(ic.package_name), count(f.id)
            FROM findings f
            JOIN inventory_components ic ON ic.id = f.component_id
            WHERE f.tenant_id = :tenantId
              AND f.status = 'OPEN'
            GROUP BY lower(ic.ecosystem), lower(ic.package_name)
            """, nativeQuery = true)
    List<Object[]> countOpenByEcosystemPackageForTenant(@Param("tenantId") UUID tenantId);

    /** Same grouping as countOpenByEcosystemPackageForTenant, broken out by resolved severity
     *  (severity_override, then the linked vulnerability's severity, then a risk_score bucket —
     *  the same resolution FindingProjectionRefreshService uses) so the BOM Components Findings
     *  column can show a critical/high/other breakdown instead of one flat count. */
    @Query(value = """
            SELECT lower(ic.ecosystem), lower(ic.package_name),
                   upper(coalesce(f.severity_override, v.severity,
                       case when f.risk_score >= 9 then 'CRITICAL'
                            when f.risk_score >= 7 then 'HIGH'
                            when f.risk_score >= 4 then 'MEDIUM' else 'LOW' end)) AS resolved_severity,
                   count(f.id)
            FROM findings f
            JOIN inventory_components ic ON ic.id = f.component_id
            LEFT JOIN vulnerabilities v ON v.id = f.vulnerability_id
            WHERE f.tenant_id = :tenantId
              AND f.status = 'OPEN'
            GROUP BY lower(ic.ecosystem), lower(ic.package_name), resolved_severity
            """, nativeQuery = true)
    List<Object[]> countOpenByEcosystemPackageAndSeverityForTenant(@Param("tenantId") UUID tenantId);

    /** Count open findings grouped by resolved asset type and severity, for the Grid Exposure widget.
     *  Covers both direct asset findings (f.asset_id) and component-scoped findings
     *  (f.component_id -> inventory_components.asset_id). */
    @Query(value = """
            SELECT COALESCE(a.type, ca.type) AS asset_type,
                   upper(COALESCE(f.severity_override, v.severity)) AS severity,
                   count(f.id)
            FROM findings f
            JOIN vulnerabilities v ON v.id = f.vulnerability_id
            LEFT JOIN assets a ON a.id = f.asset_id
            LEFT JOIN inventory_components ic ON ic.id = f.component_id
            LEFT JOIN assets ca ON ca.id = ic.asset_id
            WHERE f.tenant_id = :tenantId
              AND f.status = 'OPEN'
            GROUP BY COALESCE(a.type, ca.type), upper(COALESCE(f.severity_override, v.severity))
            """, nativeQuery = true)
    List<Object[]> countOpenByAssetTypeAndSeverityForTenant(@Param("tenantId") UUID tenantId);
}
