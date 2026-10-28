package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AssetRepository extends JpaRepository<Asset, UUID> {

    /** Cloud-discovered assets for the Cloud Resources view; every filter is optional. */
    @Query("""
            select a from Asset a
             where a.cloudProvider is not null and a.cloudProvider <> ''
               and (:provider is null or a.cloudProvider = :provider)
               and (:accountId is null or a.cloudAccountId = :accountId)
               and (:region is null or a.cloudRegion = :region)
               and (:resourceType is null or a.cloudResourceType = :resourceType)
               and (:state is null or a.state = :state)
               and (:search is null or lower(a.name) like :search escape '\\' or lower(a.identifier) like :search escape '\\')
            """)
    org.springframework.data.domain.Page<Asset> searchCloudResources(
            @Param("provider") String provider,
            @Param("accountId") String accountId,
            @Param("region") String region,
            @Param("resourceType") String resourceType,
            @Param("state") AssetState state,
            @Param("search") String search,
            org.springframework.data.domain.Pageable pageable);

    /** Facet counts for the Cloud Resources filters. */
    @Query("""
            select a.cloudProvider, a.cloudAccountId, a.cloudRegion, a.cloudResourceType, a.state, count(a)
              from Asset a
             where a.cloudProvider is not null and a.cloudProvider <> ''
             group by a.cloudProvider, a.cloudAccountId, a.cloudRegion, a.cloudResourceType, a.state
            """)
    List<Object[]> cloudResourceFacets();
    List<Asset> findAllByOrderByNameAsc();
    List<Asset> findByTenant(Tenant tenant);
    List<Asset> findByTenant_IdAndIdentifierIn(UUID tenantId, Collection<String> identifiers);
    List<Asset> findByIdentifierIn(Collection<String> identifiers);
    Optional<Asset> findByIdentifier(String identifier);

    /** Host assets whose name is the given short hostname, or that hostname plus a domain. */
    @Query("""
            select a from Asset a
             where a.type = com.prototype.vulnwatch.domain.AssetType.HOST
               and (lower(a.name) = :hostname or lower(a.name) like concat(:hostname, '.%'))
            """)
    List<Asset> findHostsByShortName(@Param("hostname") String hostname);
    List<Asset> findByState(AssetState state);

    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select a
            from Asset a
            where a.lastInventoryAt is not null
              and a.lastInventoryAt < :cutoff
              and a.state = com.prototype.vulnwatch.domain.AssetState.ACTIVE
            order by a.id
            """)
    List<Asset> findActiveAssetsWithInventoryBefore(@Param("cutoff") Instant cutoff);

    @Query("select distinct a.supportGroup from Asset a where a.tenant = :tenant and a.supportGroup is not null order by a.supportGroup")
    List<String> findDistinctSupportGroupsByTenant(@Param("tenant") Tenant tenant);
    @Query("select distinct a.supportGroup from Asset a where a.supportGroup is not null order by a.supportGroup")
    List<String> findDistinctSupportGroups();

    @Query("select distinct a.assignedTo from Asset a where a.tenant = :tenant and a.assignedTo is not null order by a.assignedTo")
    List<String> findDistinctAssignedToByTenant(@Param("tenant") Tenant tenant);
    @Query("select distinct a.assignedTo from Asset a where a.assignedTo is not null order by a.assignedTo")
    List<String> findDistinctAssignedTo();

    long countByCloudProviderAndCloudAccountIdAndType(
            String cloudProvider,
            String cloudAccountId,
            com.prototype.vulnwatch.domain.AssetType type
    );

    long countByCloudProviderAndCloudAccountIdAndTypeAndSsmManagedTrue(
            String cloudProvider,
            String cloudAccountId,
            com.prototype.vulnwatch.domain.AssetType type
    );

    long countByCloudProviderAndCloudAccountIdAndTypeAndMissingIamInstanceProfileTrue(
            String cloudProvider,
            String cloudAccountId,
            com.prototype.vulnwatch.domain.AssetType type
    );

    long countByCloudProviderAndCloudAccountIdAndTypeAndSsmInventoryAvailableTrue(
            String cloudProvider,
            String cloudAccountId,
            com.prototype.vulnwatch.domain.AssetType type
    );
}
