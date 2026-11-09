package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AssetResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.service.ownership.OwnershipReadAdapter;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class AssetQueryService {

    private final AssetRepository assetRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final OwnershipReadAdapter ownershipReads;

    public AssetQueryService(
            AssetRepository assetRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            OwnershipReadAdapter ownershipReads
    ) {
        this.assetRepository = assetRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.ownershipReads = ownershipReads;
    }

    public List<AssetResponse> listAssets(Tenant tenant) {
        // One set-based ownership read for the whole list; empty (no query) while inventory is not canonical.
        Map<UUID, OwnershipReadAdapter.Summary> ownership = tenantSchemaExecutionService.run(tenant, ownershipReads::forAllAssets);
        return tenantSchemaExecutionService.run(tenant, assetRepository::findAllByOrderByNameAsc).stream()
                .map(asset -> new AssetResponse(
                        asset.getId(),
                        asset.getType().name(),
                        asset.getName(),
                        asset.getIdentifier(),
                        asset.getServiceName(),
                        asset.getEnvironment(),
                        asset.getOwnerTeam(),
                        asset.getOwnerEmail(),
                        asset.getBusinessCriticality().name(),
                        asset.getState().name(),
                        asset.getLastInventoryAt(),
                        asset.getLastCmdbSyncAt(),
                        ownership.get(asset.getId())))
                .toList();
    }

    public List<String> listAssignmentGroups(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, assetRepository::findDistinctSupportGroups);
    }

    public List<String> listAssignedTo(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, assetRepository::findDistinctAssignedTo);
    }
}
