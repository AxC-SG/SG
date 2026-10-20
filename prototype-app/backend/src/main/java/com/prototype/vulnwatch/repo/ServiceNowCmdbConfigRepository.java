package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.ServiceNowCmdbConfig;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface ServiceNowCmdbConfigRepository extends JpaRepository<ServiceNowCmdbConfig, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from ServiceNowCmdbConfig c where c.id = :id and c.tenant.id = :tenantId")
    Optional<ServiceNowCmdbConfig> findByIdAndTenantIdForUpdate(@Param("id") UUID id, @Param("tenantId") UUID tenantId);
    Optional<ServiceNowCmdbConfig> findByTenant_IdAndSourceSystemIgnoreCase(UUID tenantId, String sourceSystem);
    Optional<ServiceNowCmdbConfig> findBySourceSystemIgnoreCase(String sourceSystem);
    List<ServiceNowCmdbConfig> findByEnabledTrueAndAutoSyncEnabledTrueOrderByUpdatedAtAsc();
    long countByTenant_Id(UUID tenantId);
}
