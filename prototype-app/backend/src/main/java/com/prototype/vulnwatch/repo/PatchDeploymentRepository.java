package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.PatchDeployment;
import com.prototype.vulnwatch.domain.PatchProviderType;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PatchDeploymentRepository extends JpaRepository<PatchDeployment, UUID> {
    Optional<PatchDeployment> findByProviderAndExternalId(PatchProviderType provider, String externalId);
}
