package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsCredentialProvider;
import com.prototype.vulnwatch.client.AwsCustomerBinding;
import com.prototype.vulnwatch.client.AwsDiscoveryClient;
import com.prototype.vulnwatch.client.AwsDiscoveryClient.AwsConnectivityResult;
import com.prototype.vulnwatch.domain.AwsAuthType;
import com.prototype.vulnwatch.domain.AwsDiscoveryConfig;
import com.prototype.vulnwatch.domain.AwsDiscoveryTarget;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AwsConnectionTestResponse;
import com.prototype.vulnwatch.dto.AwsDiscoveryConfigRequest;
import com.prototype.vulnwatch.dto.AwsDiscoveryConfigResponse;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryTargetRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Service
public class AwsDiscoveryConfigService {

    private static final String DEFAULT_RESOURCE_TYPES = "[\"EC2\"]";

    private final AwsDiscoveryConfigRepository repo;
    private final AwsDiscoveryTargetRepository targetRepository;
    private final AwsDiscoveryClient awsDiscoveryClient;
    private final ObjectMapper objectMapper;
    private final TenantQuotaService tenantQuotaService;
    private final CredentialEncryptionService credentialEncryptionService;

    public AwsDiscoveryConfigService(
            AwsDiscoveryConfigRepository repo,
            AwsDiscoveryTargetRepository targetRepository,
            AwsDiscoveryClient awsDiscoveryClient,
            ObjectMapper objectMapper,
            TenantQuotaService tenantQuotaService,
            CredentialEncryptionService credentialEncryptionService
    ) {
        this.repo = repo;
        this.targetRepository = targetRepository;
        this.awsDiscoveryClient = awsDiscoveryClient;
        this.objectMapper = objectMapper;
        this.tenantQuotaService = tenantQuotaService;
        this.credentialEncryptionService = credentialEncryptionService;
    }

    @Transactional(readOnly = true)
    public AwsDiscoveryConfigResponse get(Tenant tenant) {
        return toResponse(findConfig(tenant).orElse(null));
    }

    @Transactional
    public AwsDiscoveryConfigResponse save(Tenant tenant, AwsDiscoveryConfigRequest request) {
        AwsDiscoveryConfig config = findConfig(tenant)
                .orElseGet(() -> {
                    tenantQuotaService.assertCanCreateConnector(tenant, "aws");
                    AwsDiscoveryConfig c = new AwsDiscoveryConfig();
                    c.setTenant(tenant);
                    c.setSourceSystem("aws");
                    return c;
                });
        apply(config, request);
        config.touch();
        return toResponse(repo.save(config));
    }

    @Transactional
    public AwsConnectionTestResponse test(Tenant tenant) {
        AwsDiscoveryConfig config = requireConfig(tenant);
        Instant testedAt = Instant.now();
        AwsDiscoveryConfig runtimeConfig = configWithDecryptedCredential(config);
        List<AwsDiscoveryTarget> targets = resolveTargetsForValidation(config);
        AwsConnectionTestResponse response = targets.isEmpty()
                ? testConfigCredentials(runtimeConfig, config, testedAt)
                : testTargets(runtimeConfig, targets, testedAt);
        persistTestResult(config, response.status(), response.message(), testedAt, response.resolvedAccountId());
        return response;
    }

    // ── Private helpers ────────────────────────────────────────────────────────────────────────

    Optional<AwsDiscoveryConfig> findConfig(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return Optional.empty();
        }
        return repo.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws");
    }

    AwsDiscoveryConfig requireConfig(Tenant tenant) {
        return findConfig(tenant).orElseThrow(() -> new ResponseStatusException(BAD_REQUEST,
                "AWS Cloud Discovery connector is not configured yet"));
    }

    private void apply(AwsDiscoveryConfig config, AwsDiscoveryConfigRequest request) {
        if (request.authType() != null && parseAuthType(request.authType()) != AwsAuthType.CROSS_ACCOUNT_ROLE) {
            throw new ResponseStatusException(BAD_REQUEST, "Customer AWS discovery requires a cross-account IAM role");
        }
        String role = trimToNull(request.crossAccountRoleArn());
        try {
            config.setAwsAccountId(AwsCustomerBinding.accountForRole(role));
            config.setExternalId(AwsCustomerBinding.externalId(config.getTenant().getId(), config.getExternalId(),
                    config.getCredentialBindingVersion(), request.externalId()));
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(BAD_REQUEST, invalid.getMessage());
        }
        config.setAuthType(AwsAuthType.CROSS_ACCOUNT_ROLE);
        config.setCredentialBindingVersion(AwsCustomerBinding.VERSION);
        config.setAccessKeyId(trimToNull(request.accessKeyId()));
        if (hasText(request.credentialSecret())) {
            config.setCredentialSecret(credentialEncryptionService.encrypt(request.credentialSecret().trim()));
        }
        config.setCrossAccountRoleArn(trimToNull(request.crossAccountRoleArn()));
        if (hasText(request.regionsJson())) {
            config.setRegionsJson(request.regionsJson().trim());
        }
        config.setResourceTypesJson(DEFAULT_RESOURCE_TYPES);
        config.setEnabled(request.enabled() == null || request.enabled());
        config.setAutoSyncEnabled(request.autoSyncEnabled() != null && request.autoSyncEnabled());
        config.setIntervalMinutes(request.intervalMinutes() == null ? 1440
                : Math.max(5, request.intervalMinutes()));
    }

    private void persistTestResult(AwsDiscoveryConfig config, String status, String message,
                                   Instant testedAt, String resolvedAccountId) {
        config.setLastTestStatus(status);
        config.setLastTestMessage(message);
        config.setLastTestedAt(testedAt);
        config.touch();
        repo.save(config);
    }

    private AwsConnectionTestResponse testConfigCredentials(
            AwsDiscoveryConfig runtimeConfig,
            AwsDiscoveryConfig persistedConfig,
            Instant testedAt
    ) {
        AwsCredentialsProvider creds;
        try {
            creds = AwsCredentialProvider.from(runtimeConfig);
            awsDiscoveryClient.verifyCustomerIdentity(creds, persistedConfig.getAwsAccountId(), persistedConfig.getCrossAccountRoleArn());
        } catch (Exception e) {
            return failedResponse(appendExternalIdHint(e.getMessage(), persistedConfig.getCrossAccountRoleArn(), persistedConfig.getExternalId()), testedAt);
        }
        List<String> regions = parseRegions(runtimeConfig.getRegionsJson());
        return toTestResponse(
                "AWS connection",
                awsDiscoveryClient.testConnectivity(creds, regions),
                persistedConfig.getCrossAccountRoleArn(),
                persistedConfig.getExternalId(),
                testedAt
        );
    }

    private AwsConnectionTestResponse testTargets(
            AwsDiscoveryConfig runtimeConfig,
            List<AwsDiscoveryTarget> targets,
            Instant testedAt
    ) {
        List<String> reachableRegions = new ArrayList<>();
        List<String> warnings = new ArrayList<>();
        Map<String, String> regionErrors = new LinkedHashMap<>();
        List<String> failures = new ArrayList<>();
        String resolvedAccountId = null;
        int successfulTargets = 0;

        for (AwsDiscoveryTarget target : targets) {
            AwsConnectionTestResponse targetResponse = testTargetCredentials(runtimeConfig, target, testedAt);
            if ("FAILED".equalsIgnoreCase(targetResponse.status())) {
                failures.add(labelForTarget(target) + ": " + targetResponse.message());
            } else {
                successfulTargets++;
                if (resolvedAccountId == null && hasText(targetResponse.resolvedAccountId())) {
                    resolvedAccountId = targetResponse.resolvedAccountId();
                }
                reachableRegions.addAll(targetResponse.reachableRegions());
                warnings.addAll(targetResponse.warnings());
                regionErrors.putAll(prefixRegionErrors(labelForTarget(target), targetResponse.regionErrors()));
                if ("SUCCESS_WITH_WARNINGS".equalsIgnoreCase(targetResponse.status())) {
                    warnings.add(labelForTarget(target) + ": " + targetResponse.message());
                }
            }
        }

        if (successfulTargets == 0) {
            String message = failures.isEmpty()
                    ? "AWS connection failed."
                    : "AWS connection failed. " + String.join(" ", failures);
            return new AwsConnectionTestResponse("FAILED", message, null, Collections.emptyList(), warnings, regionErrors, testedAt);
        }

        String status = (!failures.isEmpty() || !regionErrors.isEmpty() || !warnings.isEmpty())
                ? "SUCCESS_WITH_WARNINGS"
                : "SUCCESS";
        StringBuilder message = new StringBuilder("AWS connection succeeded");
        if (resolvedAccountId != null) {
            message.append(". Account: ").append(resolvedAccountId);
        }
        if (!reachableRegions.isEmpty()) {
            message.append(". Reachable regions: ").append(String.join(", ", reachableRegions));
        }
        if (!failures.isEmpty()) {
            message.append(". Failed targets: ").append(String.join(" ", failures));
        }
        if (!regionErrors.isEmpty()) {
            message.append(formatRegionErrors(regionErrors));
        }
        if (!warnings.isEmpty()) {
            message.append(" Warnings: ").append(String.join(" | ", warnings)).append(".");
        }
        return new AwsConnectionTestResponse(status, message.toString(), resolvedAccountId, reachableRegions, warnings, regionErrors, testedAt);
    }

    private AwsConnectionTestResponse testTargetCredentials(
            AwsDiscoveryConfig runtimeConfig,
            AwsDiscoveryTarget target,
            Instant testedAt
    ) {
        AwsCredentialsProvider creds;
        try {
            creds = AwsCredentialProvider.from(runtimeConfig, target);
            awsDiscoveryClient.verifyCustomerIdentity(creds, target.getAccountId(), target.getRoleArn());
        } catch (Exception e) {
            return failedResponse(appendExternalIdHint(e.getMessage(), target.getRoleArn(), target.getExternalId()), testedAt);
        }
        List<String> regions = parseRegions(defaultIfBlank(target.getRegionsJson(), runtimeConfig.getRegionsJson()));
        return toTestResponse("AWS target connection", awsDiscoveryClient.testConnectivity(creds, regions), target.getRoleArn(), target.getExternalId(), testedAt);
    }

    private AwsConnectionTestResponse toTestResponse(
            String subject,
            AwsConnectivityResult result,
            String roleArn,
            String externalId,
            Instant testedAt
    ) {
        if (!result.success()) {
            return failedResponse(
                    appendExternalIdHint(subject + " failed: " + result.errorMessage(), roleArn, externalId),
                    testedAt
            );
        }
        String status = (!result.regionErrors().isEmpty() || !result.warnings().isEmpty()) ? "SUCCESS_WITH_WARNINGS" : "SUCCESS";
        String message = subject + " succeeded. Account: " + result.accountId()
                + ". Reachable regions: " + String.join(", ", result.reachableRegions()) + "."
                + formatRegionErrors(result.regionErrors())
                + formatWarnings(result.warnings());
        return new AwsConnectionTestResponse(
                status,
                appendExternalIdHint(message, roleArn, externalId),
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

    private List<AwsDiscoveryTarget> resolveTargetsForValidation(AwsDiscoveryConfig config) {
        List<AwsDiscoveryTarget> targets = targetRepository.findByConfigAndEnabledTrueOrderByAccountNameAscAccountIdAsc(config);
        if (!targets.isEmpty()) {
            return targets;
        }
        if (!hasText(config.getCrossAccountRoleArn())) {
            return List.of();
        }
        AwsDiscoveryTarget legacyTarget = new AwsDiscoveryTarget();
        legacyTarget.setConfig(config);
        legacyTarget.setTenant(config.getTenant());
        legacyTarget.setAccountId(config.getAwsAccountId());
        legacyTarget.setAccountName(hasText(config.getAwsAccountId()) ? "AWS Account " + config.getAwsAccountId() : "AWS Account");
        legacyTarget.setRoleArn(config.getCrossAccountRoleArn());
        legacyTarget.setExternalId(config.getExternalId());
        legacyTarget.setCredentialBindingVersion(config.getCredentialBindingVersion());
        legacyTarget.setEnabled(config.isEnabled());
        legacyTarget.setRegionsJson(defaultIfBlank(config.getRegionsJson(), "[\"us-east-1\"]"));
        return List.of(legacyTarget);
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

    private String formatWarnings(List<String> warnings) {
        if (warnings == null || warnings.isEmpty()) {
            return "";
        }
        return " Warnings: " + String.join(" | ", warnings) + ".";
    }

    private String labelForTarget(AwsDiscoveryTarget target) {
        return hasText(target.getAccountName()) ? target.getAccountName()
                : hasText(target.getAccountId()) ? target.getAccountId()
                : "AWS target";
    }

    private Map<String, String> prefixRegionErrors(String label, Map<String, String> regionErrors) {
        if (regionErrors == null || regionErrors.isEmpty()) {
            return Collections.emptyMap();
        }
        Map<String, String> prefixed = new LinkedHashMap<>();
        regionErrors.forEach((region, error) -> prefixed.put(label + " / " + region, error));
        return prefixed;
    }

    private AwsDiscoveryConfigResponse toResponse(AwsDiscoveryConfig config) {
        if (config == null) {
            return new AwsDiscoveryConfigResponse(
                    null, "aws", false, AwsAuthType.CROSS_ACCOUNT_ROLE.name(),
                    "", false, "", "", null,
                    "[\"us-east-1\"]",
                    DEFAULT_RESOURCE_TYPES,
                    true, false, 1440,
                    null, null, null, null);
        }
        boolean configured = config.getCredentialBindingVersion() == AwsCustomerBinding.VERSION
                && hasText(config.getCrossAccountRoleArn());
        return new AwsDiscoveryConfigResponse(
                config.getId(),
                config.getSourceSystem(),
                configured,
                (config.getAuthType() == null ? AwsAuthType.INSTANCE_METADATA : config.getAuthType()).name(),
                defaultIfBlank(config.getAccessKeyId(), ""),
                hasText(config.getCredentialSecret()),
                defaultIfBlank(config.getCrossAccountRoleArn(), ""),
                config.getCredentialBindingVersion() == AwsCustomerBinding.VERSION ? defaultIfBlank(config.getExternalId(), "") : "",
                config.getAwsAccountId(),
                defaultIfBlank(config.getRegionsJson(), "[\"us-east-1\"]"),
                DEFAULT_RESOURCE_TYPES,
                config.isEnabled(),
                config.isAutoSyncEnabled(),
                config.getIntervalMinutes() == null ? 1440 : config.getIntervalMinutes(),
                config.getLastTestStatus(),
                config.getLastTestMessage(),
                config.getLastTestedAt(),
                config.getLastSyncAt()
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

    private String formatRegionErrors(Map<String, String> regionErrors) {
        if (regionErrors == null || regionErrors.isEmpty()) {
            return "";
        }
        return " Region errors: " + regionErrors.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .toList() + ".";
    }

    private AwsAuthType parseAuthType(String value) {
        try {
            return AwsAuthType.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new ResponseStatusException(BAD_REQUEST, "Unsupported AWS auth type: " + value);
        }
    }

    AwsDiscoveryConfig configWithDecryptedCredential(AwsDiscoveryConfig config) {
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
        String t = value.trim();
        return t.isEmpty() ? null : t;
    }

    private String defaultIfBlank(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }
}
