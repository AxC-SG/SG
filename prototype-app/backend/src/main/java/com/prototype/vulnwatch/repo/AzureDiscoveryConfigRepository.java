package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AzureDiscoveryConfig;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AzureDiscoveryConfigRepository extends JpaRepository<AzureDiscoveryConfig, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from AzureDiscoveryConfig c where c.id = :id and c.tenant.id = :tenantId")
    Optional<AzureDiscoveryConfig> findByIdAndTenantIdForUpdate(@Param("id") UUID id, @Param("tenantId") UUID tenantId);

    Optional<AzureDiscoveryConfig> findByTenant_IdAndSourceSystemIgnoreCase(UUID tenantId, String sourceSystem);

    Optional<AzureDiscoveryConfig> findBySourceSystemIgnoreCase(String sourceSystem);

    List<AzureDiscoveryConfig> findByEnabledTrueAndAutoSyncEnabledTrueOrderByUpdatedAtAsc();

    long countByTenant_Id(UUID tenantId);
}
