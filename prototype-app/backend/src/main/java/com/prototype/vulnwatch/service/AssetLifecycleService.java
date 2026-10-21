package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetState;
import com.prototype.vulnwatch.domain.BusinessCriticality;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CmdbAssetRecordRequest;
import com.prototype.vulnwatch.dto.CmdbAssetSyncRequest;
import com.prototype.vulnwatch.dto.CmdbAssetSyncResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class AssetLifecycleService {

    private final AssetRepository assetRepository;
    private final FindingRepository findingRepository;
    private final FindingWorkflowService findingWorkflowService;
    private final RiskPolicyService riskPolicyService;
    private final WorkspaceService workspaceService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TenantWorkRunner tenantWorkRunner;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();
    private TransactionTemplate writeTransactionTemplate;

    @Value("${app.assets.stale-days-to-inactive:30}")
    private int staleDaysToInactive;

    public AssetLifecycleService(
            AssetRepository assetRepository,
            FindingRepository findingRepository,
            FindingWorkflowService findingWorkflowService,
            RiskPolicyService riskPolicyService,
            WorkspaceService workspaceService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.assetRepository = assetRepository;
        this.findingRepository = findingRepository;
        this.findingWorkflowService = findingWorkflowService;
        this.riskPolicyService = riskPolicyService;
        this.workspaceService = workspaceService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager == null) {
            this.writeTransactionTemplate = null;
            return;
        }
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public CmdbAssetSyncResponse syncFromCmdb(CmdbAssetSyncRequest request) {
        Tenant tenant = workspaceService.getWorkspace();
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            int inserted = 0;
            int updated = 0;
            for (CmdbAssetRecordRequest record : request.assets()) {
                Asset asset = assetRepository.findByIdentifier(record.assetIdentifier().trim()).orElse(null);
                boolean isNew = asset == null;
                if (isNew) {
                    asset = new Asset();
                    asset.setTenant(tenant);
                    asset.setIdentifier(record.assetIdentifier().trim());
                }
                asset.setType(record.assetType());
                asset.setName(record.assetName().trim());
                asset.setServiceName(trimToNull(record.serviceName()));
                asset.setEnvironment(trimToNull(record.environment()));
                asset.setOwnerTeam(trimToNull(record.ownerTeam()));
                asset.setOwnerEmail(trimToNull(record.ownerEmail()));
                asset.setBusinessCriticality(record.businessCriticality() == null ? BusinessCriticality.MEDIUM : record.businessCriticality());
                if (record.assetType() == com.prototype.vulnwatch.domain.AssetType.CONTAINER_IMAGE) {
                    asset.setImageDigest(trimToNull(record.imageDigest()));
                    asset.setImageTag(trimToNull(record.imageTag()));
                    asset.setImageRepository(trimToNull(record.imageRepository()));
                    asset.setBaseImageDigest(trimToNull(record.baseImageDigest()));
                }
                AssetState previousState = asset.getState();
                AssetState nextState = record.state() == null ? AssetState.ACTIVE : record.state();
                asset.setState(nextState);
                asset.setLastCmdbSyncAt(Instant.now());
                asset = assetRepository.save(asset);
                if (isNew) {
                    inserted++;
                } else {
                    updated++;
                }
                if (previousState != nextState) {
                    handleStateTransitionInCurrentTenantSchema(asset, previousState, nextState, "cmdb-sync");
                }
            }
            return new CmdbAssetSyncResponse(
                    request.assets().size(),
                    inserted,
                    updated,
                    "CMDB asset sync completed");
        }));
    }

    public void markInventoryIngested(Asset asset) {
        if (asset == null || asset.getTenant() == null) {
            return;
        }
        tenantSchemaExecutionService.run(asset.getTenant(), () -> executeWrite(() -> {
            AssetState previousState = asset.getState();
            asset.setLastInventoryAt(Instant.now());
            asset.setState(AssetState.ACTIVE);
            assetRepository.save(asset);
            if (previousState != AssetState.ACTIVE) {
                handleStateTransitionInCurrentTenantSchema(asset, previousState, AssetState.ACTIVE, "inventory-ingest");
            }
            return null;
        }));
    }

    public void handleStateTransition(Asset asset, AssetState from, AssetState to, String actor) {
        if (asset == null || asset.getTenant() == null) {
            return;
        }
        tenantSchemaExecutionService.run(asset.getTenant(), () -> executeWrite(() -> {
            handleStateTransitionInCurrentTenantSchema(asset, from, to, actor);
            return null;
        }));
    }

    private void handleStateTransitionInCurrentTenantSchema(Asset asset, AssetState from, AssetState to, String actor) {
        if (to == AssetState.ACTIVE) {
            return;
        }
        RiskPolicy policy = riskPolicyService.getOrCreate(asset.getTenant());
        if (!policy.isAutoCloseEnabled() || !policy.isAutoCloseAssetRetiredEnabled()) {
            return;
        }
        List<Finding> openFindings = new ArrayList<>();
        openFindings.addAll(findingRepository.findForMaintenance(FindingStatus.OPEN, asset.getId()));
        for (Finding finding : openFindings) {
            Map<String, Object> details = new LinkedHashMap<>();
            details.put("assetStateFrom", from == null ? null : from.name());
            details.put("assetStateTo", to.name());
            details.put("actor", actor);
            findingWorkflowService.autoCloseFinding(
                    finding,
                    FindingCloseReason.AUTO_ASSET_RETIRED,
                    "Finding auto-closed due to asset state transition",
                    details,
                    Instant.now());
        }
        if (!openFindings.isEmpty()) {
            findingRepository.saveAll(openFindings);
        }
    }

    @Scheduled(zone = "UTC", cron = "0 5 2 * * *")
    public void markStaleAssetsInactive() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("asset-lifecycle.mark-stale-assets-inactive")) {
            return;
        }
        Instant cutoff = Instant.now().minus(Math.max(1, staleDaysToInactive), ChronoUnit.DAYS);
        tenantWorkRunner.forEachActiveTenant(tenant -> {
            List<Asset> stale = assetRepository.findActiveAssetsWithInventoryBefore(cutoff);
            for (Asset asset : stale) {
                AssetState previousState = asset.getState();
                asset.setState(AssetState.INACTIVE);
                assetRepository.save(asset);
                handleStateTransitionInCurrentTenantSchema(asset, previousState, AssetState.INACTIVE, "stale-inventory");
            }
        });
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private <T> T executeWrite(java.util.function.Supplier<T> work) {
        if (writeTransactionTemplate == null) {
            return work.get();
        }
        return writeTransactionTemplate.execute(status -> work.get());
    }
}
