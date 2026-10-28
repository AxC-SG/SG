package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.GcpDiscoveryConfig;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface GcpDiscoveryConfigRepository extends JpaRepository<GcpDiscoveryConfig, UUID> {

    /** The configuration row is the sync admission lock, exactly as for the AWS connector. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from GcpDiscoveryConfig c where c.id = :id and c.tenant.id = :tenantId")
    Optional<GcpDiscoveryConfig> findByIdAndTenantIdForUpdate(@Param("id") UUID id, @Param("tenantId") UUID tenantId);

    Optional<GcpDiscoveryConfig> findByTenant_IdAndSourceSystemIgnoreCase(UUID tenantId, String sourceSystem);

    long countByTenant_Id(UUID tenantId);
}
