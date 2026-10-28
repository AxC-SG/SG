package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.FixPatchDetail;
import com.prototype.vulnwatch.domain.PatchProviderType;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface FixPatchDetailRepository extends JpaRepository<FixPatchDetail, UUID> {
    Optional<FixPatchDetail> findByProviderAndExternalId(PatchProviderType provider, String externalId);
    List<FixPatchDetail> findByFixId(UUID fixId);
    List<FixPatchDetail> findByFixIdIn(Collection<UUID> fixIds);
}
