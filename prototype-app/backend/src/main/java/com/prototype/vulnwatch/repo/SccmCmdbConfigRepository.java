package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import jakarta.persistence.LockModeType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SccmCmdbConfigRepository extends JpaRepository<SccmCmdbConfig, UUID> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select c from SccmCmdbConfig c where c.id = :id and c.tenant.id = :tenantId")
    Optional<SccmCmdbConfig> findByIdAndTenantIdForUpdate(@Param("id") UUID id, @Param("tenantId") UUID tenantId);
    Optional<SccmCmdbConfig> findByTenant_IdAndSourceSystemIgnoreCase(UUID tenantId, String sourceSystem);
    Optional<SccmCmdbConfig> findBySourceSystemIgnoreCase(String sourceSystem);
    List<SccmCmdbConfig> findByEnabledTrueAndAutoSyncEnabledTrueOrderByUpdatedAtAsc();
    long countByTenant_Id(UUID tenantId);
}
