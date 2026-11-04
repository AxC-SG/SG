package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.TenantMembership;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface TenantMembershipRepository extends JpaRepository<TenantMembership, UUID> {
    List<TenantMembership> findByTenantIdOrderByCreatedAtAsc(UUID tenantId);
    List<TenantMembership> findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(String externalSubject, String status);
    Optional<TenantMembership> findFirstByUserExternalSubjectAndTenantIdAndStatus(String externalSubject, UUID tenantId, String status);
    Optional<TenantMembership> findFirstByUserExternalSubjectAndTenantId(String externalSubject, UUID tenantId);
    List<TenantMembership> findByProvenance(String provenance);
    long countByTenantIdAndRoleAndStatus(UUID tenantId, String role, String status);
}
