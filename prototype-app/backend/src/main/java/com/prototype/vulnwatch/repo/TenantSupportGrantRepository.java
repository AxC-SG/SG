package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.TenantSupportGrant;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Lock;
import jakarta.persistence.LockModeType;
import org.springframework.data.repository.query.Param;

public interface TenantSupportGrantRepository extends JpaRepository<TenantSupportGrant, UUID> {

    List<TenantSupportGrant> findByTenant_IdOrderByRequestedAtDesc(UUID tenantId);

    List<TenantSupportGrant> findByInvitedPlatformSubjectIgnoreCaseOrderByRequestedAtDesc(String invitedPlatformSubject);

    @Query("""
            select g
            from TenantSupportGrant g
            join fetch g.tenant t
            where lower(g.invitedPlatformSubject) = lower(:subject)
              and upper(g.status) = 'ACTIVE'
              and g.revokedAt is null
              and (g.expiresAt is null or g.expiresAt > :now)
            order by g.expiresAt asc nulls last, g.requestedAt desc
            """)
    List<TenantSupportGrant> findActiveByInvitedPlatformSubject(@Param("subject") String subject, @Param("now") Instant now);

    @Query("""
            select g
            from TenantSupportGrant g
            join fetch g.tenant t
            where lower(g.invitedPlatformSubject) = lower(:subject)
              and t.id = :tenantId
              and upper(g.status) = 'ACTIVE'
              and g.revokedAt is null
              and (g.expiresAt is null or g.expiresAt > :now)
            order by g.expiresAt desc nulls first, g.requestedAt desc
            """)
    List<TenantSupportGrant> findActiveByInvitedPlatformSubjectAndTenantId(
            @Param("subject") String subject,
            @Param("tenantId") UUID tenantId,
            @Param("now") Instant now
    );

    Optional<TenantSupportGrant> findById(UUID id);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select g from TenantSupportGrant g where g.id = :id")
    Optional<TenantSupportGrant> findByIdForUpdate(@Param("id") UUID id);
}
