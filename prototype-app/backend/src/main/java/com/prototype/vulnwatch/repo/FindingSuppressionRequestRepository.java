package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.FindingSuppressionRequest;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

public interface FindingSuppressionRequestRepository extends JpaRepository<FindingSuppressionRequest, UUID> {
    Optional<FindingSuppressionRequest> findByIdAndTenant_Id(UUID id, UUID tenantId);
    Optional<FindingSuppressionRequest> findByFinding_IdAndStatus(UUID findingId, String status);
    List<FindingSuppressionRequest> findByTenant_IdOrderByCreatedAtDesc(UUID tenantId);

    @Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    List<FindingSuppressionRequest> findByStatusAndDecisionDueAtBeforeOrderById(String status, Instant before);
}
