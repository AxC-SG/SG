package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.PatchConnectorConfig;
import com.prototype.vulnwatch.domain.PatchProviderType;
import jakarta.persistence.LockModeType;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PatchConnectorConfigRepository extends JpaRepository<PatchConnectorConfig, UUID> {

    /** The configuration row is the sync admission lock, as for the inventory connectors. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from PatchConnectorConfig c where c.id = :id and c.tenant.id = :tenantId")
    Optional<PatchConnectorConfig> findByIdAndTenantIdForUpdate(@Param("id") UUID id, @Param("tenantId") UUID tenantId);

    Optional<PatchConnectorConfig> findByTenant_IdAndProvider(UUID tenantId, PatchProviderType provider);

    long countByTenant_Id(UUID tenantId);
}
