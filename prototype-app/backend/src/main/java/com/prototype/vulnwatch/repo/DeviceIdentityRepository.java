package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.DeviceIdentity;
import com.prototype.vulnwatch.domain.PatchProviderType;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DeviceIdentityRepository extends JpaRepository<DeviceIdentity, UUID> {
    Optional<DeviceIdentity> findByProviderAndExternalId(PatchProviderType provider, String externalId);
    List<DeviceIdentity> findBySerialNumber(String serialNumber);
    List<DeviceIdentity> findByNormalizedHostname(String normalizedHostname);
    List<DeviceIdentity> findByAssetId(UUID assetId);
}
