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
    List<Asset> findAllByOrderByNameAsc();
    List<Asset> findByTenant(Tenant tenant);
    List<Asset> findByTenant_IdAndIdentifierIn(UUID tenantId, Collection<String> identifiers);
    List<Asset> findByIdentifierIn(Collection<String> identifiers);
    Optional<Asset> findByIdentifier(String identifier);
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
