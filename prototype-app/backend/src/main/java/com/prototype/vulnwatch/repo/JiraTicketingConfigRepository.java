package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.JiraTicketingConfig;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface JiraTicketingConfigRepository extends JpaRepository<JiraTicketingConfig, UUID> {
    Optional<JiraTicketingConfig> findByTenant_Id(UUID tenantId);
    long countByTenant_Id(UUID tenantId);
}
