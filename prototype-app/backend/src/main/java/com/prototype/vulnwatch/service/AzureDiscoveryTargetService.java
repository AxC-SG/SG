package com.prototype.vulnwatch.service;

import com.azure.core.credential.TokenCredential;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AzureCredentialProvider;
import com.prototype.vulnwatch.client.AzureDiscoveryClient;
import com.prototype.vulnwatch.client.AzureDiscoveryClient.AzureConnectivityResult;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.AzureDiscoveryConfig;
import com.prototype.vulnwatch.domain.AzureDiscoveryTarget;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AzureConnectionTestResponse;
import com.prototype.vulnwatch.dto.AzureDiscoveryTargetRequest;
import com.prototype.vulnwatch.dto.AzureDiscoveryTargetResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.AzureDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AzureDiscoveryTargetRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AzureDiscoveryTargetService {

    private static final String DEFAULT_REGIONS = "[\"eastus2\"]";

    private final AzureDiscoveryConfigRepository configRepository;
    private final AzureDiscoveryTargetRepository targetRepository;
    private final AssetRepository assetRepository;
    private final AzureDiscoveryClient azureDiscoveryClient;
    private final ObjectMapper objectMapper;
    private final TenantQuotaService tenantQuotaService;
    private final CredentialEncryptionService credentialEncryptionService;

    public AzureDiscoveryTargetService(
            AzureDiscoveryConfigRepository configRepository,
            AzureDiscoveryTargetRepository targetRepository,
            AssetRepository assetRepository,
            AzureDiscoveryClient azureDiscoveryClient,
            ObjectMapper objectMapper,
            TenantQuotaService tenantQuotaService,
            CredentialEncryptionService credentialEncryptionService
    ) {
        this.configRepository = configRepository;
        this.targetRepository = targetRepository;
        this.assetRepository = assetRepository;
        this.azureDiscoveryClient = azureDiscoveryClient;
        this.objectMapper = objectMapper;
        this.tenantQuotaService = tenantQuotaService;
        this.credentialEncryptionService = credentialEncryptionService;
    }

    @Transactional(readOnly = true)
    public List<AzureDiscoveryTargetResponse> list(Tenant tenant) {
        AzureDiscoveryConfig config = requireConfig(tenant);
        return targetRepository.findByConfigOrderBySubscriptionNameAscSubscriptionIdAsc(config).stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional
    public AzureDiscoveryTargetResponse create(Tenant tenant, AzureDiscoveryTargetRequest request) {
        GenericAzureDiscoveryPolicy.requireAvailable();

        AzureDiscoveryConfig config = requireConfig(tenant);
        tenantQuotaService.assertCanCreateConnector(tenant, "azure-target");
        AzureDiscoveryTarget target = new AzureDiscoveryTarget();
        target.setTenant(tenant);
        target.setConfig(config);
        apply(target, request, config);
        return toResponse(targetRepository.save(target));
    }

    @Transactional
    public AzureDiscoveryTargetResponse update(Tenant tenant, UUID targetId, AzureDiscoveryTargetRequest request) {
        GenericAzureDiscoveryPolicy.requireAvailable();

        AzureDiscoveryTarget target = requireTarget(tenant, targetId);
        apply(target, request, target.getConfig());
        target.touch();
        return toResponse(targetRepository.save(target));
    }

    @Transactional
    public void delete(Tenant tenant, UUID targetId) {
        GenericAzureDiscoveryPolicy.requireAvailable();

        AzureDiscoveryTarget target = requireTarget(tenant, targetId);
        targetRepository.delete(target);
    }

    @Transactional
    public AzureConnectionTestResponse test(Tenant tenant, UUID targetId) {
        GenericAzureDiscoveryPolicy.requireAvailable();

        AzureDiscoveryTarget target = requireTarget(tenant, targetId);
        Instant testedAt = Instant.now();
        TokenCredential credential;
        try {
            credential = AzureCredentialProvider.from(configWithDecryptedCredential(target.getConfig()));
        } catch (Exception e) {
            persistTestResult(target, "FAILED", e.getMessage(), testedAt, null);
            return failedResponse(e.getMessage(), testedAt);
        }

        AzureConnectivityResult result = azureDiscoveryClient.testConnectivity(credential, target.getSubscriptionId());
        AzureConnectionTestResponse response = toTestResponse(result, testedAt);
        persistTestResult(target, response.status(), response.message(), testedAt, result.subscriptionName());
        return response;
    }

    @Transactional
    public void ensureLegacyTarget(AzureDiscoveryConfig config) {
        GenericAzureDiscoveryPolicy.requireAvailable();

        if (config == null || config.getTenant() == null || targetRepository.countByConfig(config) > 0) {
            return;
        }
        List<String> subscriptionIds = parseList(config.getSubscriptionIdsJson());
        if (subscriptionIds.isEmpty()) {
            return;
        }
        for (String subscriptionId : subscriptionIds) {
            AzureDiscoveryTarget target = new AzureDiscoveryTarget();
            target.setTenant(config.getTenant());
            target.setConfig(config);
            target.setSubscriptionId(subscriptionId);
            target.setSubscriptionName("Subscription " + subscriptionId);
            target.setEnabled(config.isEnabled());
            target.setRegionsJson(defaultIfBlank(config.getRegionsJson(), DEFAULT_REGIONS));
            targetRepository.save(target);
        }
    }

    AzureDiscoveryTarget requireTarget(Tenant tenant, UUID targetId) {
        if (tenant == null || tenant.getId() == null || targetId == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Azure discovery target not found");
        }
        return targetRepository.findByIdAndTenant_Id(targetId, tenant.getId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Azure discovery target not found: " + targetId));
    }

    private AzureDiscoveryConfig requireConfig(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Workspace is not available");
        }
        AzureDiscoveryConfig config = configRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "azure")
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Azure Cloud Discovery connector is not configured yet"));
        ensureLegacyTarget(config);
        return config;
    }

    private void apply(AzureDiscoveryTarget target, AzureDiscoveryTargetRequest request, AzureDiscoveryConfig config) {
        target.setSubscriptionId(trimToNull(request.subscriptionId()));
        target.setSubscriptionName(defaultIfBlank(request.subscriptionName(),
                hasText(request.subscriptionId()) ? "Subscription " + request.subscriptionId().trim() : "Subscription"));
        target.setEnabled(request.enabled() == null || request.enabled());
        target.setRegionsJson(defaultIfBlank(request.regionsJson(), defaultIfBlank(config.getRegionsJson(), DEFAULT_REGIONS)));
    }

    private void persistTestResult(AzureDiscoveryTarget target, String status, String message, Instant testedAt, String subscriptionName) {
        target.setLastTestStatus(status);
        target.setLastTestMessage(message);
        target.setLastTestedAt(testedAt);
        if (hasText(subscriptionName) && !hasText(target.getSubscriptionName())) {
            target.setSubscriptionName(subscriptionName.trim());
        }
        target.touch();
        targetRepository.save(target);
    }

    private AzureDiscoveryTargetResponse toResponse(AzureDiscoveryTarget target) {
        String subscriptionId = target.getSubscriptionId();
        long hostCount = hasText(subscriptionId)
                ? assetRepository.countByCloudProviderAndCloudAccountIdAndType("azure", subscriptionId, AssetType.HOST)
                : 0;
        return new AzureDiscoveryTargetResponse(
                target.getId(),
                target.getSubscriptionId(),
                target.getSubscriptionName(),
                target.isEnabled(),
                defaultIfBlank(target.getRegionsJson(), DEFAULT_REGIONS),
                target.getLastTestStatus(),
                target.getLastTestMessage(),
                target.getLastTestedAt(),
                target.getLastSyncAt(),
                hostCount
        );
    }

    private AzureConnectionTestResponse toTestResponse(AzureConnectivityResult result, Instant testedAt) {
        if (!result.success()) {
            return failedResponse("Azure target connection failed: " + result.errorMessage(), testedAt);
        }
        String message = "Azure target connection succeeded. Subscription: "
                + (hasText(result.subscriptionName()) ? result.subscriptionName() : result.subscriptionId()) + ".";
        return new AzureConnectionTestResponse(
                "SUCCESS",
                message,
                null,
                List.of(result.subscriptionId()),
                List.of(),
                java.util.Map.of(),
                testedAt
        );
    }

    private AzureConnectionTestResponse failedResponse(String message, Instant testedAt) {
        return new AzureConnectionTestResponse("FAILED", message, null, List.of(), List.of(), java.util.Map.of(), testedAt);
    }

    private AzureDiscoveryConfig configWithDecryptedCredential(AzureDiscoveryConfig config) {
        AzureDiscoveryConfig runtime = new AzureDiscoveryConfig();
        runtime.setTenant(config.getTenant());
        runtime.setSourceSystem(config.getSourceSystem());
        runtime.setAuthType(config.getAuthType());
        runtime.setAzureTenantId(config.getAzureTenantId());
        runtime.setClientId(config.getClientId());
        runtime.setClientSecret(credentialEncryptionService.decrypt(config.getClientSecret()));
        runtime.setSubscriptionIdsJson(config.getSubscriptionIdsJson());
        runtime.setRegionsJson(config.getRegionsJson());
        runtime.setEnabled(config.isEnabled());
        runtime.setAutoSyncEnabled(config.isAutoSyncEnabled());
        runtime.setIntervalMinutes(config.getIntervalMinutes());
        return runtime;
    }

    private List<String> parseList(String json) {
        if (!hasText(json)) {
            return List.of();
        }
        try {
            List<String> values = objectMapper.readValue(json, new TypeReference<List<String>>() {});
            List<String> normalized = new ArrayList<>();
            for (String value : values) {
                if (hasText(value)) {
                    normalized.add(value.trim());
                }
            }
            return normalized;
        } catch (Exception e) {
            return List.of();
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String trimToNull(String value) {
        if (value == null) return null;
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String defaultIfBlank(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }
}
