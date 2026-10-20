package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.TenantUserInvite;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantUserInviteRepository extends JpaRepository<TenantUserInvite, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select i from TenantUserInvite i where i.id = :id and i.tenant.id = :tenantId")
    Optional<TenantUserInvite> findByIdAndTenantIdForUpdate(@Param("id") UUID id, @Param("tenantId") UUID tenantId);
    List<TenantUserInvite> findByTenantIdOrderByCreatedAtDesc(UUID tenantId);
    Optional<TenantUserInvite> findByIdAndTenantId(UUID id, UUID tenantId);
    Optional<TenantUserInvite> findByTokenHash(String tokenHash);
    @Query("select i.tenant.id from TenantUserInvite i where i.tokenHash = :hash")
    Optional<UUID> findTenantIdByTokenHash(@Param("hash") String hash);
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select i from TenantUserInvite i where i.tokenHash = :hash")
    Optional<TenantUserInvite> findByTokenHashForUpdate(@Param("hash") String hash);
    Optional<TenantUserInvite> findFirstByTenantIdAndEmailIgnoreCaseAndStatusInOrderByCreatedAtDesc(
            UUID tenantId,
            String email,
            List<String> statuses
    );
}
