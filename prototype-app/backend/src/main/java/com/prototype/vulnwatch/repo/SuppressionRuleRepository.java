package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.SuppressionRule;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SuppressionRuleRepository extends JpaRepository<SuppressionRule, UUID> {
    @org.springframework.data.jpa.repository.Lock(jakarta.persistence.LockModeType.PESSIMISTIC_WRITE)
    @org.springframework.data.jpa.repository.Query("select r from SuppressionRule r order by r.createdAt, r.id")
    List<SuppressionRule> findAllForUpdate();
    List<SuppressionRule> findAllByOrderByCreatedAtAsc();
}
