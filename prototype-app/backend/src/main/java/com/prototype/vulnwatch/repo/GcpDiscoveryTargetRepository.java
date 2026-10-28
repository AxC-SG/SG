package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.GcpDiscoveryConfig;
import com.prototype.vulnwatch.domain.GcpDiscoveryTarget;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface GcpDiscoveryTargetRepository extends JpaRepository<GcpDiscoveryTarget, UUID> {

    List<GcpDiscoveryTarget> findByConfigOrderByProjectIdAsc(GcpDiscoveryConfig config);

    List<GcpDiscoveryTarget> findByConfigAndEnabledTrueOrderByProjectIdAsc(GcpDiscoveryConfig config);

    Optional<GcpDiscoveryTarget> findByIdAndTenant_Id(UUID id, UUID tenantId);

    Optional<GcpDiscoveryTarget> findByConfigAndProjectId(GcpDiscoveryConfig config, String projectId);

    long countByTenant_Id(UUID tenantId);
}
