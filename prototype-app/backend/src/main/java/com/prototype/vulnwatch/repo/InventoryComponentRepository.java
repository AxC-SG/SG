package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface InventoryComponentRepository extends JpaRepository<InventoryComponent, UUID> {

    interface NormalizationAggregateRow {
        long getTotal();
        long getNormalizedNameCount();
        long getNormalizedVersionCount();
        long getSoftwareIdentityCount();
    }

    interface TenantComponentLookupRow {
        UUID getTenantId();
        UUID getComponentId();
    }

    @Query("""
            select
              count(c) as total,
              sum(case when c.normalizedName is not null and trim(c.normalizedName) <> '' then 1 else 0 end) as normalizedNameCount,
              sum(case when c.normalizedVersion is not null and trim(c.normalizedVersion) <> '' then 1 else 0 end) as normalizedVersionCount,
              sum(case when c.softwareIdentity is not null then 1 else 0 end) as softwareIdentityCount
            from InventoryComponent c
            where c.tenant = :tenant
              and c.componentStatus = :status
            """)
    Optional<NormalizationAggregateRow> findNormalizationAggregate(
            @Param("tenant") Tenant tenant,
            @Param("status") InventoryComponentStatus status
    );

    @Query("""
            select
              count(c) as total,
              sum(case when c.normalizedName is not null and trim(c.normalizedName) <> '' then 1 else 0 end) as normalizedNameCount,
              sum(case when c.normalizedVersion is not null and trim(c.normalizedVersion) <> '' then 1 else 0 end) as normalizedVersionCount,
              sum(case when c.softwareIdentity is not null then 1 else 0 end) as softwareIdentityCount
            from InventoryComponent c
            where c.tenant = :tenant
              and c.componentStatus = :status
              and (c.lastObservedAt is null or c.lastObservedAt < :before)
            """)
    Optional<NormalizationAggregateRow> findNormalizationAggregateBeforeLastObservedAt(
            @Param("tenant") Tenant tenant,
            @Param("status") InventoryComponentStatus status,
            @Param("before") Instant before
    );
    List<InventoryComponent> findByTenant(Tenant tenant);
    List<InventoryComponent> findByComponentStatus(InventoryComponentStatus status);
    List<InventoryComponent> findByComponentStatusOrderByLastObservedAtDesc(InventoryComponentStatus status);
    long countByComponentStatus(InventoryComponentStatus status);

    @Query("select c.id from InventoryComponent c where c.componentStatus = :status")
    List<UUID> findIdsByComponentStatus(@Param("status") InventoryComponentStatus status);
    @Query("""
            select c from InventoryComponent c
            join fetch c.asset a
            where c.tenant.id = :tenantId
              and c.componentStatus = :status
              and a.type = com.prototype.vulnwatch.domain.AssetType.APPLICATION
            order by a.name asc, c.packageName asc, c.id asc
            """)
    List<InventoryComponent> findActiveApplicationComponentsWithAsset(
            @Param("tenantId") UUID tenantId,
            @Param("status") InventoryComponentStatus status
    );

    List<InventoryComponent> findByAsset(Asset asset);

    List<InventoryComponent> findByAssetId(UUID assetId);

    long countByIdInAndComponentStatus(Collection<UUID> ids, InventoryComponentStatus status);

    /**
     * Components credited to one uploaded document. This is the only link back from an
     * inventory component to the BOM that produced it, and it is single-valued: re-ingesting
     * the same asset from another source overwrites it, so it can attribute a component to
     * the most recent source only.
     */
    List<InventoryComponent> findByAsset_IdAndSbomUpload_Id(UUID assetId, UUID sbomUploadId);
    List<InventoryComponent> findByAsset_IdIn(Collection<UUID> assetIds);
    List<InventoryComponent> findByAssetAndComponentStatus(Asset asset, InventoryComponentStatus status);
    @Query("""
            select c
            from InventoryComponent c
            where c.tenant.id = :tenantId
              and c.asset.id = :assetId
              and c.componentStatus = :status
              and (
                lower(coalesce(c.normalizedName, c.packageName)) = lower(:componentName)
                or lower(coalesce(c.packageName, '')) = lower(:componentName)
              )
              and (
                :componentVersion is null
                or lower(coalesce(c.normalizedVersion, c.version, '')) = lower(cast(:componentVersion as string))
                or lower(coalesce(c.version, '')) = lower(cast(:componentVersion as string))
              )
            """)
    List<InventoryComponent> findActiveByTenantAssetAndComponentNameVersion(
            @Param("tenantId") UUID tenantId,
            @Param("assetId") UUID assetId,
            @Param("status") InventoryComponentStatus status,
            @Param("componentName") String componentName,
            @Param("componentVersion") String componentVersion
    );
    @Query("""
            select c
            from InventoryComponent c
            left join c.sbomUpload u
            left join c.softwareIdentity s
            where c.tenant = :tenant
              and (:assetTypes is null or c.asset.type in :assetTypes)
              and (:componentStatuses is null or c.componentStatus in :componentStatuses)
              and (:normalizedSourceSystems is null or lower(coalesce(u.ingestionSourceSystem, '')) in :normalizedSourceSystems)
              and (:normalizedEcosystems is null or lower(coalesce(c.ecosystem, '')) in :normalizedEcosystems)
              and (:applyOwnerIds = false or c.id in :ownerIds)
              and (:applyReviewFilters = false or c.asset.type = com.prototype.vulnwatch.domain.AssetType.HOST)
              and (
                :normalizedQueryPattern is null
                or lower(coalesce(c.asset.name, '')) like :normalizedQueryPattern
                or lower(coalesce(c.asset.identifier, '')) like :normalizedQueryPattern
                or lower(coalesce(c.packageName, '')) like :normalizedQueryPattern
                or lower(coalesce(c.normalizedName, '')) like :normalizedQueryPattern
                or lower(coalesce(s.displayName, '')) like :normalizedQueryPattern
                or lower(coalesce(c.purl, '')) like :normalizedQueryPattern
              )
              and (
                :applyReviewFilters = false
                or (
                  (:reviewNeedsAny = true and (
                    exists(
                      select 1
                      from SoftwareInstance si
                      where si.inventoryComponent = c
                        and si.activeInstall = true
                        and (si.version is null or trim(si.version) = '')
                        and (si.normalizedVersion is null or trim(si.normalizedVersion) = '')
                    )
                    or exists(
                      select 1
                      from SoftwareInstance si
                      where si.inventoryComponent = c
                        and si.activeInstall = true
                        and si.softwareIdentity is null
                    )
                    or exists(
                      select 1
                      from SoftwareInstance si
                      join si.discoveryModel dm
                      where si.inventoryComponent = c
                        and si.activeInstall = true
                        and (
                          dm.lowConfidence = true
                          or dm.approved = false
                          or (dm.normalizationStatus is not null and lower(trim(dm.normalizationStatus)) <> 'approved')
                        )
                    )
                    or exists(
                      select 1
                      from CiAlias alias
                      where alias.ci.asset = c.asset
                        and alias.confidence is not null
                        and alias.confidence < :lowConfidenceAliasThreshold
                        and (u is null or lower(coalesce(alias.sourceSystem, '')) = lower(coalesce(u.ingestionSourceSystem, '')))
                    )
                  ))
                  or (:reviewMissingVersion = true and exists(
                    select 1
                    from SoftwareInstance si
                    where si.inventoryComponent = c
                      and si.activeInstall = true
                      and (si.version is null or trim(si.version) = '')
                      and (si.normalizedVersion is null or trim(si.normalizedVersion) = '')
                  ))
                  or (:reviewUnmappedSoftware = true and exists(
                    select 1
                    from SoftwareInstance si
                    where si.inventoryComponent = c
                      and si.activeInstall = true
                      and si.softwareIdentity is null
                  ))
                  or (:reviewLowConfidenceAlias = true and exists(
                    select 1
                    from CiAlias alias
                    where alias.ci.asset = c.asset
                      and alias.confidence is not null
                      and alias.confidence < :lowConfidenceAliasThreshold
                      and (u is null or lower(coalesce(alias.sourceSystem, '')) = lower(coalesce(u.ingestionSourceSystem, '')))
                  ))
                  or (:reviewDiscoveryModel = true and exists(
                    select 1
                    from SoftwareInstance si
                    join si.discoveryModel dm
                    where si.inventoryComponent = c
                      and si.activeInstall = true
                      and (
                        dm.lowConfidence = true
                        or dm.approved = false
                        or (dm.normalizationStatus is not null and lower(trim(dm.normalizationStatus)) <> 'approved')
                      )
                  ))
                )
              )
            """)
    Page<InventoryComponent> findPageByFilters(
            @Param("tenant") Tenant tenant,
            @Param("assetTypes") Collection<AssetType> assetTypes,
            @Param("componentStatuses") Collection<InventoryComponentStatus> componentStatuses,
            @Param("normalizedSourceSystems") Collection<String> normalizedSourceSystems,
            @Param("normalizedEcosystems") Collection<String> normalizedEcosystems,
            @Param("applyReviewFilters") boolean applyReviewFilters,
            @Param("reviewNeedsAny") boolean reviewNeedsAny,
            @Param("reviewMissingVersion") boolean reviewMissingVersion,
            @Param("reviewUnmappedSoftware") boolean reviewUnmappedSoftware,
            @Param("reviewLowConfidenceAlias") boolean reviewLowConfidenceAlias,
            @Param("reviewDiscoveryModel") boolean reviewDiscoveryModel,
            @Param("lowConfidenceAliasThreshold") double lowConfidenceAliasThreshold,
            @Param("normalizedQueryPattern") String normalizedQueryPattern,
            @Param("applyOwnerIds") boolean applyOwnerIds,
            @Param("ownerIds") Collection<UUID> ownerIds,
            Pageable pageable
    );

    @Query("""
            select distinct c.asset.type
            from InventoryComponent c
            where c.tenant = :tenant
            """)
    List<AssetType> findDistinctAssetTypesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct c.componentStatus
            from InventoryComponent c
            where c.tenant = :tenant
            """)
    List<InventoryComponentStatus> findDistinctComponentStatusesByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct lower(u.ingestionSourceSystem)
            from InventoryComponent c
            left join c.sbomUpload u
            where c.tenant = :tenant
              and u.ingestionSourceSystem is not null
              and trim(u.ingestionSourceSystem) <> ''
            """)
    List<String> findDistinctSourceSystemsByTenant(@Param("tenant") Tenant tenant);

    @Query("""
            select distinct lower(c.ecosystem)
            from InventoryComponent c
            where c.tenant = :tenant
              and c.ecosystem is not null
              and trim(c.ecosystem) <> ''
            """)
    List<String> findDistinctEcosystemsByTenant(@Param("tenant") Tenant tenant);

    void deleteByAsset(Asset asset);

    @Query("""
            select distinct c.tenant.id
            from InventoryComponent c
            where c.normalizedPurl in :purls
            """)
    Set<UUID> findDistinctTenantIdsByNormalizedPurlIn(@Param("purls") Collection<String> purls);

    @Query("""
            select distinct c.id
            from InventoryComponent c
            where c.tenant.id = :tenantId
              and c.normalizedPurl in :purls
            """)
    Set<UUID> findDistinctIdsByTenantIdAndNormalizedPurlIn(
            @Param("tenantId") UUID tenantId,
            @Param("purls") Collection<String> purls
    );

    @Query("""
            select distinct
              c.tenant.id as tenantId,
              c.id as componentId
            from InventoryComponent c
            where c.normalizedPurl in :purls
            """)
    List<TenantComponentLookupRow> findDistinctTenantComponentRowsByNormalizedPurlIn(
            @Param("purls") Collection<String> purls
    );

    @Query("""
            select distinct c.tenant.id
            from InventoryComponent c
            where c.coordKey in :coordKeys
            """)
    Set<UUID> findDistinctTenantIdsByCoordKeyIn(@Param("coordKeys") Collection<String> coordKeys);

    @Query("""
            select distinct c.id
            from InventoryComponent c
            where c.tenant.id = :tenantId
              and c.coordKey in :coordKeys
            """)
    Set<UUID> findDistinctIdsByTenantIdAndCoordKeyIn(
            @Param("tenantId") UUID tenantId,
            @Param("coordKeys") Collection<String> coordKeys
    );

    @Query("""
            select distinct
              c.tenant.id as tenantId,
              c.id as componentId
            from InventoryComponent c
            where c.coordKey in :coordKeys
            """)
    List<TenantComponentLookupRow> findDistinctTenantComponentRowsByCoordKeyIn(
            @Param("coordKeys") Collection<String> coordKeys
    );

    @Query("""
            select c.id
            from InventoryComponent c
            where c.componentStatus = com.prototype.vulnwatch.domain.InventoryComponentStatus.ACTIVE
              and (
                c.eolSlug is not null
                or c.eolDate is not null
                or c.eolSupportEndDate is not null
              )
            """)
    List<UUID> findActiveLifecycleTrackedIds();

    @Query("""
            select c.id
            from InventoryComponent c
            join c.softwareIdentity sid
            where c.componentStatus = com.prototype.vulnwatch.domain.InventoryComponentStatus.ACTIVE
              and lower(concat(coalesce(sid.vendor, ''), '::', coalesce(sid.product, ''))) = :normalizedKey
            """)
    List<UUID> findActiveIdsBySoftwareIdentityNormalizedKey(@Param("normalizedKey") String normalizedKey);

    @Query("""
            select c.id
            from InventoryComponent c
            where c.componentStatus = com.prototype.vulnwatch.domain.InventoryComponentStatus.ACTIVE
              and (
                (c.eolDate is not null and c.eolDate <= :today and (c.isEol is null or c.isEol = false))
                or (c.eolSupportEndDate is not null and c.eolSupportEndDate = :eosThreshold)
              )
            """)
    List<UUID> findLifecycleTransitionComponentIds(
            @Param("today") java.time.LocalDate today,
            @Param("eosThreshold") java.time.LocalDate eosThreshold
    );
}
