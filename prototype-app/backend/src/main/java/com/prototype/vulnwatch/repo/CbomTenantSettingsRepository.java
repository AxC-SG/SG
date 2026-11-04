package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CbomTenantSettings;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface CbomTenantSettingsRepository extends JpaRepository<CbomTenantSettings, UUID> {
}
