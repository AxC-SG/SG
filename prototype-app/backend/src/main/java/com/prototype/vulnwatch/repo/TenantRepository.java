package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.Tenant;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;

public interface TenantRepository extends JpaRepository<Tenant, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select t from Tenant t where t.id = :id")
    Optional<Tenant> findByIdForUpdate(@Param("id") UUID id);

    Optional<Tenant> findByNameIgnoreCase(String name);
    Optional<Tenant> findBySlugIgnoreCase(String slug);
    Optional<Tenant> findBySchemaName(String schemaName);
    boolean existsByNameIgnoreCase(String name);
    boolean existsBySlugIgnoreCase(String slug);
    boolean existsBySchemaName(String schemaName);
    List<Tenant> findAllByOrderByCreatedAtAsc();
    List<Tenant> findByPlanCodeIgnoreCaseAndStatusIgnoreCaseAndDemoExpiresAtBefore(String planCode, String status, Instant now);
    List<Tenant> findByDemoExpiresAtBeforeAndPurgedAtIsNullOrderByDemoExpiresAtAsc(Instant now);
}
