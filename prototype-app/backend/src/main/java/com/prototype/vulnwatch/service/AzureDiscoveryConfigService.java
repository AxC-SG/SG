package com.prototype.vulnwatch.service;

import com.azure.core.credential.TokenCredential;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AzureCredentialProvider;
import com.prototype.vulnwatch.client.AzureDiscoveryClient;
import com.prototype.vulnwatch.client.AzureDiscoveryClient.AzureConnectivityResult;
import com.prototype.vulnwatch.domain.AzureAuthType;
import com.prototype.vulnwatch.domain.AzureDiscoveryConfig;
import com.prototype.vulnwatch.domain.AzureDiscoveryTarget;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AzureConnectionTestResponse;
import com.prototype.vulnwatch.dto.AzureDiscoveryConfigRequest;
import com.prototype.vulnwatch.dto.AzureDiscoveryConfigResponse;
import com.prototype.vulnwatch.repo.AzureDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AzureDiscoveryTargetRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AzureDiscoveryConfigService {

    private final AzureDiscoveryConfigRepository repo;
    private final AzureDiscoveryTargetRepository targetRepository;
    private final AzureDiscoveryClient azureDiscoveryClient;
    private final ObjectMapper objectMapper;
    private final TenantQuotaService tenantQuotaService;
    private final CredentialEncryptionService credentialEncryptionService;

    public AzureDiscoveryConfigService(
            AzureDiscoveryConfigRepository repo,
            AzureDiscoveryTargetRepository targetRepository,
            AzureDiscoveryClient azureDiscoveryClient,
            ObjectMapper objectMapper,
            TenantQuotaService tenantQuotaService,
            CredentialEncryptionService credentialEncryptionService
    ) {
        this.repo = repo;
        this.targetRepository = targetRepository;
        this.azureDiscoveryClient = azureDiscoveryClient;
        this.objectMapper = objectMapper;
        this.tenantQuotaService = tenantQuotaService;
        this.credentialEncryptionService = credentialEncryptionService;
    }

    @Transactional(readOnly = true)
    public AzureDiscoveryConfigResponse get(Tenant tenant) {
        return toResponse(findConfig(tenant).orElse(null));
    }

    @Transactional
    public AzureDiscoveryConfigResponse save(Tenant tenant, AzureDiscoveryConfigRequest request) {
        GenericAzureDiscoveryPolicy.requireAvailable();

        AzureDiscoveryConfig config = findConfig(tenant)
                .orElseGet(() -> {
                    tenantQuotaService.assertCanCreateConnector(tenant, "azure");
                    AzureDiscoveryConfig c = new AzureDiscoveryConfig();
                    c.setTenant(tenant);
                    c.setSourceSystem("azure");
                    return c;
                });
        apply(config, request);
        config.touch();
        return toResponse(repo.save(config));
    }

    @Transactional
    public AzureConnectionTestResponse test(Tenant tenant) {
        GenericAzureDiscoveryPolicy.requireAvailable();

        AzureDiscoveryConfig config = requireConfig(tenant);
        Instant testedAt = Instant.now();
        AzureDiscoveryConfig runtimeConfig = configWithDecryptedCredential(config);

        TokenCredential credential;
        try {
            credential = AzureCredentialProvider.from(runtimeConfig);
        } catch (Exception e) {
            persistTestResult(config, "FAILED", e.getMessage(), testedAt);
            return failedResponse(e.getMessage(), testedAt);
        }

        List<AzureDiscoveryTarget> targets = resolveTargetsForValidation(config);
        AzureConnectionTestResponse response = targets.isEmpty()
                ? failedResponse("No Azure subscriptions configured. Add a subscription ID to test connectivity.", testedAt)
                : testTargets(credential, targets, testedAt);
        persistTestResult(config, response.status(), response.message(), testedAt);
        return response;
    }

    private List<AzureDiscoveryTarget> resolveTargetsForValidation(AzureDiscoveryConfig config) {
        List<AzureDiscoveryTarget> persisted =
                targetRepository.findByConfigAndEnabledTrueOrderBySubscriptionNameAscSubscriptionIdAsc(config);
        if (!persisted.isEmpty()) {
            return persisted;
        }
        List<AzureDiscoveryTarget> legacy = new ArrayList<>();
        for (String subscriptionId : parseList(config.getSubscriptionIdsJson())) {
            AzureDiscoveryTarget target = new AzureDiscoveryTarget();
            target.setTenant(config.getTenant());
            target.setConfig(config);
            target.setSubscriptionId(subscriptionId);
            target.setSubscriptionName("Subscription " + subscriptionId);
            target.setEnabled(true);
            target.setRegionsJson(config.getRegionsJson());
            legacy.add(target);
        }
        return legacy;
    }

    private AzureConnectionTestResponse testTargets(TokenCredential credential, List<AzureDiscoveryTarget> targets, Instant testedAt) {
        List<String> reachableSubscriptions = new ArrayList<>();
        Map<String, String> subscriptionErrors = new LinkedHashMap<>();
        for (AzureDiscoveryTarget target : targets) {
            AzureConnectivityResult result = azureDiscoveryClient.testConnectivity(credential, target.getSubscriptionId());
            if (result.success()) {
                reachableSubscriptions.add(hasText(result.subscriptionName()) ? result.subscriptionName() : result.subscriptionId());
            } else {
                subscriptionErrors.put(target.getSubscriptionId(), result.errorMessage());
            }
        }
        String status = reachableSubscriptions.isEmpty()
                ? "FAILED"
                : subscriptionErrors.isEmpty() ? "SUCCESS" : "SUCCESS_WITH_WARNINGS";
        StringBuilder message = new StringBuilder();
        if (!reachableSubscriptions.isEmpty()) {
            message.append("Azure connection succeeded. Reachable subscriptions: ")
                    .append(String.join(", ", reachableSubscriptions)).append(".");
        }
        if (!subscriptionErrors.isEmpty()) {
            if (message.length() > 0) {
                message.append(' ');
            }
            message.append("Failed subscriptions: ").append(String.join(" ", subscriptionErrors.values()));
        }
        return new AzureConnectionTestResponse(
                status,
                message.length() > 0 ? message.toString() : "Azure connection failed.",
                null,
                reachableSubscriptions,
                List.of(),
                subscriptionErrors,
                testedAt
        );
    }

    private AzureConnectionTestResponse failedResponse(String message, Instant testedAt) {
        return new AzureConnectionTestResponse("FAILED", message, null, List.of(), List.of(), Map.of(), testedAt);
    }

    Optional<AzureDiscoveryConfig> findConfig(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return Optional.empty();
        }
        return repo.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "azure");
    }

    AzureDiscoveryConfig requireConfig(Tenant tenant) {
        return findConfig(tenant).orElseThrow(() -> new ResponseStatusException(
                HttpStatus.BAD_REQUEST,
                "Azure Cloud Discovery connector is not configured yet"
        ));
    }

    AzureDiscoveryConfig runtimeConfig(AzureDiscoveryConfig config) {
        GenericAzureDiscoveryPolicy.requireAvailable();

        return configWithDecryptedCredential(config);
    }

    private void apply(AzureDiscoveryConfig config, AzureDiscoveryConfigRequest request) {
        if (request.authType() != null) {
            config.setAuthType(request.authType());
        }
        config.setAzureTenantId(trimToNull(request.azureTenantId()));
        config.setClientId(trimToNull(request.clientId()));
        if (hasText(request.credentialSecret())) {
            config.setClientSecret(credentialEncryptionService.encrypt(request.credentialSecret().trim()));
        }
        if (hasText(request.subscriptionIdsJson())) {
            config.setSubscriptionIdsJson(canonicalJsonArray(request.subscriptionIdsJson()));
        } else if (config.getSubscriptionIdsJson() == null) {
            config.setSubscriptionIdsJson("[]");
        }
        if (hasText(request.regionsJson())) {
            config.setRegionsJson(canonicalJsonArray(request.regionsJson()));
        } else if (config.getRegionsJson() == null) {
            config.setRegionsJson("[\"eastus2\"]");
        }
        config.setEnabled(request.enabled() == null || request.enabled());
        config.setAutoSyncEnabled(request.autoSyncEnabled() != null && request.autoSyncEnabled());
        config.setIntervalMinutes(request.intervalMinutes() == null ? 1440 : Math.max(5, request.intervalMinutes()));
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

    private AzureDiscoveryConfigResponse toResponse(AzureDiscoveryConfig config) {
        if (config == null) {
            return new AzureDiscoveryConfigResponse(
                    null,
                    "azure",
                    false,
                    AzureAuthType.CLIENT_SECRET.name(),
                    "",
                    "",
                    false,
                    "[]",
                    "[\"eastus2\"]",
                    true,
                    false,
                    1440,
                    null,
                    null,
                    null,
                    null
            );
        }
        return new AzureDiscoveryConfigResponse(
                config.getId(),
                config.getSourceSystem(),
                isConfigured(config),
                config.getAuthType() == null ? AzureAuthType.CLIENT_SECRET.name() : config.getAuthType().name(),
                nullToEmpty(config.getAzureTenantId()),
                nullToEmpty(config.getClientId()),
                credentialEncryptionService.isEncrypted(config.getClientSecret()),
                nullToEmpty(config.getSubscriptionIdsJson(), "[]"),
                nullToEmpty(config.getRegionsJson(), "[\"eastus2\"]"),
                false,
                false,
                config.getIntervalMinutes() == null ? 1440 : config.getIntervalMinutes(),
                "DISABLED",
                GenericAzureDiscoveryPolicy.MESSAGE,
                config.getLastTestedAt(),
                config.getLastSyncAt()
        );
    }

    private void persistTestResult(AzureDiscoveryConfig config, String status, String message, Instant testedAt) {
        config.setLastTestStatus(status);
        config.setLastTestMessage(message);
        config.setLastTestedAt(testedAt);
        config.touch();
        repo.save(config);
    }

    private boolean isConfigured(AzureDiscoveryConfig config) {
        if (config == null) {
            return false;
        }
        if (!hasText(config.getSubscriptionIdsJson()) || parseList(config.getSubscriptionIdsJson()).isEmpty()) {
            return false;
        }
        AzureAuthType authType = config.getAuthType() == null ? AzureAuthType.CLIENT_SECRET : config.getAuthType();
        return switch (authType) {
            case MANAGED_IDENTITY -> true;
            case CLIENT_SECRET -> hasText(config.getAzureTenantId())
                    && hasText(config.getClientId())
                    && hasText(config.getClientSecret());
        };
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

    private String canonicalJsonArray(String value) {
        try {
            List<String> values = parseList(value);
            return objectMapper.writeValueAsString(values);
        } catch (Exception e) {
            return "[]";
        }
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private String nullToEmpty(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
