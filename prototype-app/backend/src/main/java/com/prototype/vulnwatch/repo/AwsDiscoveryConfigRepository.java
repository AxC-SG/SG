package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AwsDiscoveryConfigRepository extends JpaRepository<AwsDiscoveryConfig, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from AwsDiscoveryConfig c where c.id = :id and c.tenant.id = :tenantId")
    Optional<AwsDiscoveryConfig> findByIdAndTenantIdForUpdate(@Param("id") UUID id, @Param("tenantId") UUID tenantId);

    Optional<AwsDiscoveryConfig> findByTenant_IdAndSourceSystemIgnoreCase(UUID tenantId, String sourceSystem);
    Optional<AwsDiscoveryConfig> findBySourceSystemIgnoreCase(String sourceSystem);

    List<AwsDiscoveryConfig> findByEnabledTrueAndAutoSyncEnabledTrueOrderByUpdatedAtAsc();

    long countByTenant_Id(UUID tenantId);
}
