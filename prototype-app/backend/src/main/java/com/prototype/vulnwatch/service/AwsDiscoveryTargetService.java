package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsCredentialProvider;
import com.prototype.vulnwatch.client.AwsCustomerBinding;
import com.prototype.vulnwatch.client.AwsDiscoveryClient;
import com.prototype.vulnwatch.client.AwsDiscoveryClient.AwsConnectivityResult;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.AwsDiscoveryTarget;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AwsConnectionTestResponse;
import com.prototype.vulnwatch.dto.AwsDiscoveryTargetRequest;
import com.prototype.vulnwatch.dto.AwsDiscoveryTargetResponse;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryTargetRepository;
import java.time.Instant;
import java.util.Collections;
import java.util.Locale;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

@Service
public class AwsDiscoveryTargetService {

    private static final String DEFAULT_REGIONS = "[\"us-east-1\"]";
    private static final String DEFAULT_RESOURCE_TYPES = "[\"EC2\"]";

    private final AwsDiscoveryConfigRepository configRepository;
    private final AwsDiscoveryTargetRepository targetRepository;
    private final AssetRepository assetRepository;
    private final AwsDiscoveryClient awsDiscoveryClient;
    private final ObjectMapper objectMapper;
    private final TenantQuotaService tenantQuotaService;
    private final CredentialEncryptionService credentialEncryptionService;

    public AwsDiscoveryTargetService(
            AwsDiscoveryConfigRepository configRepository,
            AwsDiscoveryTargetRepository targetRepository,
            AssetRepository assetRepository,
            AwsDiscoveryClient awsDiscoveryClient,
            ObjectMapper objectMapper,
            TenantQuotaService tenantQuotaService,
            CredentialEncryptionService credentialEncryptionService
    ) {
        this.configRepository = configRepository;
        this.targetRepository = targetRepository;
        this.assetRepository = assetRepository;
        this.awsDiscoveryClient = awsDiscoveryClient;
        this.objectMapper = objectMapper;
        this.tenantQuotaService = tenantQuotaService;
        this.credentialEncryptionService = credentialEncryptionService;
    }

    @Transactional(readOnly = true)
    public List<AwsDiscoveryTargetResponse> list(Tenant tenant) {
        AwsDiscoveryConfig config = requireConfig(tenant);
        return targetRepository.findByConfigOrderByAccountNameAscAccountIdAsc(config).stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional
    public AwsDiscoveryTargetResponse create(Tenant tenant, AwsDiscoveryTargetRequest request) {
        AwsDiscoveryConfig config = requireConfig(tenant);
        tenantQuotaService.assertCanCreateConnector(tenant, "aws-target");
        AwsDiscoveryTarget target = new AwsDiscoveryTarget();
        target.setTenant(tenant);
        target.setConfig(config);
        apply(target, request, config);
        return toResponse(targetRepository.save(target));
    }

    @Transactional
    public AwsDiscoveryTargetResponse update(Tenant tenant, UUID targetId, AwsDiscoveryTargetRequest request) {
        AwsDiscoveryTarget target = requireTarget(tenant, targetId);
        apply(target, request, target.getConfig());
        target.touch();
        return toResponse(targetRepository.save(target));
    }

    @Transactional
    public void delete(Tenant tenant, UUID targetId) {
        AwsDiscoveryTarget target = requireTarget(tenant, targetId);
        targetRepository.delete(target);
    }

    @Transactional
    public AwsConnectionTestResponse test(Tenant tenant, UUID targetId) {
        AwsDiscoveryTarget target = requireTarget(tenant, targetId);
        Instant testedAt = Instant.now();
        AwsCredentialsProvider creds;
        try {
            creds = AwsCredentialProvider.from(configWithDecryptedCredential(target.getConfig()), target);
            awsDiscoveryClient.verifyCustomerIdentity(creds, target.getAccountId(), target.getRoleArn());
        } catch (Exception e) {
            persistTestResult(target, "FAILED", e.getMessage(), testedAt, null);
            return failedResponse(appendExternalIdHint(e.getMessage(), target.getRoleArn(), target.getExternalId()), testedAt);
        }

        List<String> regions = parseRegions(target.getRegionsJson());
        AwsConnectivityResult result = awsDiscoveryClient.testConnectivity(creds, regions);
        AwsConnectionTestResponse response = toTestResponse(result, target, testedAt);
        persistTestResult(target, response.status(), response.message(), testedAt, response.resolvedAccountId());
        return response;
    }

    @Transactional
    public void ensureLegacyTarget(AwsDiscoveryConfig config) {
        if (config == null || config.getTenant() == null || targetRepository.countByConfig(config) > 0) {
            return;
        }
        if (!hasText(config.getAwsAccountId()) && !hasText(config.getCrossAccountRoleArn())) {
            return;
        }
        AwsDiscoveryTarget target = new AwsDiscoveryTarget();
        target.setTenant(config.getTenant());
        target.setConfig(config);
        target.setAccountId(trimToNull(config.getAwsAccountId()));
        target.setAccountName(hasText(config.getAwsAccountId()) ? "AWS Account " + config.getAwsAccountId() : "AWS Account");
        target.setRoleArn(trimToNull(config.getCrossAccountRoleArn()));
        target.setExternalId(trimToNull(config.getExternalId()));
        target.setCredentialBindingVersion(config.getCredentialBindingVersion());
        target.setEnabled(config.isEnabled());
        target.setRegionsJson(defaultIfBlank(config.getRegionsJson(), DEFAULT_REGIONS));
        target.setResourceTypesJson(DEFAULT_RESOURCE_TYPES);
        target.setLastTestStatus(config.getLastTestStatus());
        target.setLastTestMessage(config.getLastTestMessage());
        target.setLastTestedAt(config.getLastTestedAt());
        target.setLastSyncAt(config.getLastSyncAt());
        targetRepository.save(target);
    }

    AwsDiscoveryTarget requireTarget(Tenant tenant, UUID targetId) {
        if (tenant == null || tenant.getId() == null || targetId == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "AWS discovery target not found");
        }
        return targetRepository.findByIdAndTenant_Id(targetId, tenant.getId())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "AWS discovery target not found: " + targetId));
    }

    private AwsDiscoveryConfig requireConfig(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Workspace is not available");
        }
        AwsDiscoveryConfig config = configRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws")
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "AWS Cloud Discovery connector is not configured yet"));
        ensureLegacyTarget(config);
        return config;
    }

    private void apply(AwsDiscoveryTarget target, AwsDiscoveryTargetRequest request, AwsDiscoveryConfig config) {
        try {
            String account = trimToNull(request.accountId());
            String role = trimToNull(request.roleArn());
            if (account == null || !account.equals(AwsCustomerBinding.accountForRole(role))) {
                throw new IllegalArgumentException("AWS target role must belong to its 12-digit account ID");
            }
            target.setExternalId(AwsCustomerBinding.externalId(target.getTenant().getId(), target.getExternalId(),
                    target.getCredentialBindingVersion(), request.externalId()));
            target.setCredentialBindingVersion(AwsCustomerBinding.VERSION);
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, invalid.getMessage());
        }
        target.setAccountId(trimToNull(request.accountId()));
        target.setAccountName(defaultIfBlank(request.accountName(), hasText(request.accountId()) ? "AWS Account " + request.accountId().trim() : "AWS Account"));
        target.setRoleArn(trimToNull(request.roleArn()));
        target.setEnabled(request.enabled() == null || request.enabled());
        target.setRegionsJson(defaultIfBlank(request.regionsJson(), defaultIfBlank(config.getRegionsJson(), DEFAULT_REGIONS)));
        target.setResourceTypesJson(DEFAULT_RESOURCE_TYPES);
    }

    private void persistTestResult(AwsDiscoveryTarget target, String status, String message, Instant testedAt, String accountId) {
        target.setLastTestStatus(status);
        target.setLastTestMessage(message);
        target.setLastTestedAt(testedAt);
        target.touch();
        targetRepository.save(target);
    }

    private AwsDiscoveryTargetResponse toResponse(AwsDiscoveryTarget target) {
        String accountId = target.getAccountId();
        long hostCount = hasText(accountId)
                ? assetRepository.countByCloudProviderAndCloudAccountIdAndType("aws", accountId, AssetType.HOST)
                : 0;
        long ssmManaged = hasText(accountId)
                ? assetRepository.countByCloudProviderAndCloudAccountIdAndTypeAndSsmManagedTrue("aws", accountId, AssetType.HOST)
                : 0;
        long missingIam = hasText(accountId)
                ? assetRepository.countByCloudProviderAndCloudAccountIdAndTypeAndMissingIamInstanceProfileTrue("aws", accountId, AssetType.HOST)
                : 0;
        long inventory = hasText(accountId)
                ? assetRepository.countByCloudProviderAndCloudAccountIdAndTypeAndSsmInventoryAvailableTrue("aws", accountId, AssetType.HOST)
                : 0;
        return new AwsDiscoveryTargetResponse(
                target.getId(),
                target.getAccountId(),
                target.getAccountName(),
                target.getRoleArn(),
                target.getCredentialBindingVersion() == AwsCustomerBinding.VERSION ? target.getExternalId() : "",
                target.isEnabled(),
                defaultIfBlank(target.getRegionsJson(), DEFAULT_REGIONS),
                DEFAULT_RESOURCE_TYPES,
                target.getLastTestStatus(),
                target.getLastTestMessage(),
                target.getLastTestedAt(),
                target.getLastSyncAt(),
                hostCount,
                ssmManaged,
                missingIam,
                inventory
        );
    }

    private List<String> parseRegions(String regionsJson) {
        if (!hasText(regionsJson)) return List.of("us-east-1");
        try {
            return objectMapper.readValue(regionsJson, new TypeReference<>() {});
        } catch (Exception e) {
            return List.of("us-east-1");
        }
    }

    private String formatRegionErrors(java.util.Map<String, String> regionErrors) {
        if (regionErrors == null || regionErrors.isEmpty()) {
            return "";
        }
        return " Region errors: " + regionErrors.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .toList() + ".";
    }

    private String formatWarnings(List<String> warnings) {
        if (warnings == null || warnings.isEmpty()) {
            return "";
        }
        return " Warnings: " + String.join(" | ", warnings) + ".";
    }

    private AwsConnectionTestResponse toTestResponse(
            AwsConnectivityResult result,
            AwsDiscoveryTarget target,
            Instant testedAt
    ) {
        if (!result.success()) {
            return failedResponse(
                    appendExternalIdHint("AWS target connection failed: " + result.errorMessage(), target.getRoleArn(), target.getExternalId()),
                    testedAt
            );
        }
        String status = (!result.regionErrors().isEmpty() || !result.warnings().isEmpty()) ? "SUCCESS_WITH_WARNINGS" : "SUCCESS";
        String message = appendExternalIdHint(
                "AWS target connection succeeded. Account: " + result.accountId()
                        + ". Reachable regions: " + String.join(", ", result.reachableRegions()) + "."
                        + formatRegionErrors(result.regionErrors())
                        + formatWarnings(result.warnings()),
                target.getRoleArn(),
                target.getExternalId()
        );
        return new AwsConnectionTestResponse(
                status,
                message,
                result.accountId(),
                result.reachableRegions(),
                result.warnings(),
                result.regionErrors(),
                testedAt
        );
    }

    private AwsConnectionTestResponse failedResponse(String message, Instant testedAt) {
        return new AwsConnectionTestResponse("FAILED", message, null, Collections.emptyList(), Collections.emptyList(), Collections.emptyMap(), testedAt);
    }

    private String appendExternalIdHint(String message, String roleArn, String externalId) {
        if (!hasText(roleArn) || hasText(externalId)) {
            return message;
        }
        String normalized = message == null ? "" : message.toLowerCase(Locale.ROOT);
        if (!normalized.contains("assumerole") && !normalized.contains("accessdenied") && !normalized.contains("not authorized")) {
            return message;
        }
        return message + " Role may require External ID; configure it in the connector if the trust policy uses sts:ExternalId.";
    }

    private AwsDiscoveryConfig configWithDecryptedCredential(AwsDiscoveryConfig config) {
        if (config == null || !hasText(config.getCredentialSecret())) {
            return config;
        }
        AwsDiscoveryConfig runtimeConfig = new AwsDiscoveryConfig();
        runtimeConfig.setTenant(config.getTenant());
        runtimeConfig.setSourceSystem(config.getSourceSystem());
        runtimeConfig.setAuthType(config.getAuthType());
        runtimeConfig.setAccessKeyId(config.getAccessKeyId());
        runtimeConfig.setCredentialSecret(credentialEncryptionService.decrypt(config.getCredentialSecret()));
        runtimeConfig.setCrossAccountRoleArn(config.getCrossAccountRoleArn());
        runtimeConfig.setExternalId(config.getExternalId());
        runtimeConfig.setCredentialBindingVersion(config.getCredentialBindingVersion());
        runtimeConfig.setAwsAccountId(config.getAwsAccountId());
        runtimeConfig.setRegionsJson(config.getRegionsJson());
        runtimeConfig.setResourceTypesJson(config.getResourceTypesJson());
        runtimeConfig.setEnabled(config.isEnabled());
        runtimeConfig.setAutoSyncEnabled(config.isAutoSyncEnabled());
        runtimeConfig.setIntervalMinutes(config.getIntervalMinutes());
        return runtimeConfig;
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
