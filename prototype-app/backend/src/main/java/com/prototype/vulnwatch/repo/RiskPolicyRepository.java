package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RiskPolicyRepository extends JpaRepository<RiskPolicy, UUID> {
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.Query("select p from RiskPolicy p order by p.id")
    java.util.List<RiskPolicy> findAllForUpdate();
    Optional<RiskPolicy> findByTenant(Tenant tenant);

    Optional<RiskPolicy> findTopByOrderByUpdatedAtDesc();
}
