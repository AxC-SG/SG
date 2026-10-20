package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.DemoRequest;
import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DemoRequestRepository extends JpaRepository<DemoRequest, UUID> {
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from DemoRequest r where r.id = :id")
    Optional<DemoRequest> findByIdForUpdate(@Param("id") UUID id);
    List<DemoRequest> findAllByOrderByRequestedAtDesc();
    Optional<DemoRequest> findFirstByEmailIgnoreCaseAndStatusInOrderByRequestedAtDesc(String email, List<String> statuses);
    Optional<DemoRequest> findFirstByEmailIgnoreCaseAndTenantIdIsNotNullOrderByRequestedAtAsc(String email);
}
