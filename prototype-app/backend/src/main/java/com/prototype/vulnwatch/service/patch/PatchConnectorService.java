package com.prototype.vulnwatch.service.patch;

import com.prototype.vulnwatch.domain.PatchConnectorConfig;
import com.prototype.vulnwatch.domain.PatchProviderType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.PatchConnectionTestResponse;
import com.prototype.vulnwatch.dto.PatchConnectorConfigRequest;
import com.prototype.vulnwatch.dto.PatchConnectorConfigResponse;
import com.prototype.vulnwatch.repo.PatchConnectorConfigRepository;
import com.prototype.vulnwatch.service.CredentialEncryptionService;
import com.prototype.vulnwatch.service.TenantQuotaService;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

/**
 * Per-tenant patch tool connections: read, save and test.
 *
 * <p>Secrets are encrypted with {@link CredentialEncryptionService}, write-only through the API,
 * and never logged; error messages from a provider are stripped of anything secret-shaped before
 * they are stored or shown.
 */
@Service
public class PatchConnectorService {

    private static final Logger LOG = LoggerFactory.getLogger(PatchConnectorService.class);

    private final PatchConnectorConfigRepository configs;
    private final PatchProviderRegistry registry;
    private final CredentialEncryptionService encryption;
    private final TenantQuotaService quota;

    public PatchConnectorService(
            PatchConnectorConfigRepository configs,
            PatchProviderRegistry registry,
            CredentialEncryptionService encryption,
            TenantQuotaService quota
    ) {
        this.configs = configs;
        this.registry = registry;
        this.encryption = encryption;
        this.quota = quota;
    }

    @Transactional(readOnly = true)
    public PatchConnectorConfigResponse get(Tenant tenant, PatchProviderType type) {
        registry.require(type);
        return toResponse(type, findConfig(tenant, type).orElse(null));
    }

    @Transactional
    public PatchConnectorConfigResponse save(Tenant tenant, PatchProviderType type, PatchConnectorConfigRequest request) {
        PatchProvider provider = registry.require(type);
        PatchConnectorConfigRequest safe = request == null
                ? new PatchConnectorConfigRequest(null, null, null, null, null, null, null, null) : request;
        PatchConnectorConfig config = findConfig(tenant, type).orElseGet(() -> {
            quota.assertCanCreateConnector(tenant, "patch-" + type.name().toLowerCase(Locale.ROOT));
            PatchConnectorConfig created = new PatchConnectorConfig();
            created.setTenant(tenant);
            created.setProvider(type);
            created.setCreatedAt(Instant.now());
            return created;
        });
        config.setBaseUrl(trimToNull(safe.baseUrl()));
        config.setDirectoryId(trimToNull(safe.directoryId()));
        config.setClientId(trimToNull(safe.clientId()));
        config.setUsername(trimToNull(safe.username()));
        boolean newSecret = safe.secret() != null && !safe.secret().isBlank();
        try {
            provider.validate(config, newSecret || hasSecret(config));
        } catch (IllegalArgumentException invalid) {
            throw new ResponseStatusException(BAD_REQUEST, invalid.getMessage());
        }
        if (newSecret) {
            config.setCredentialSecret(encryption.encrypt(safe.secret().trim()));
        }
        config.setEnabled(safe.enabled() == null || safe.enabled());
        config.setAutoSyncEnabled(safe.autoSyncEnabled() != null && safe.autoSyncEnabled());
        config.setIntervalMinutes(safe.intervalMinutes() == null ? 1440 : Math.max(60, safe.intervalMinutes()));
        config.setUpdatedAt(Instant.now());
        return toResponse(type, configs.save(config));
    }

    @Transactional
    public PatchConnectionTestResponse test(Tenant tenant, PatchProviderType type) {
        PatchProvider provider = registry.require(type);
        PatchConnectorConfig config = requireConfig(tenant, type);
        Instant testedAt = Instant.now();
        PatchConnectionResult result;
        try {
            result = provider.test(tenant, config, secret(provider, config));
        } catch (RuntimeException failure) {
            LOG.warn("Patch connector test failed for tenant {} provider {}: {}", tenant.getId(), type, failure.getClass().getSimpleName());
            result = PatchConnectionResult.failed(sanitize(failure.getMessage()));
        }
        config.setLastTestStatus(result.status());
        config.setLastTestMessage(truncate(sanitize(result.message()), 2000));
        config.setLastTestedAt(testedAt);
        config.setUpdatedAt(testedAt);
        configs.save(config);
        return new PatchConnectionTestResponse(result.status(), sanitize(result.message()),
                result.checks().stream().map(c -> new PatchConnectionTestResponse.Check(c.name(), c.passed(), c.required(),
                        sanitize(c.detail()))).toList(), testedAt);
    }

    Optional<PatchConnectorConfig> findConfig(Tenant tenant, PatchProviderType type) {
        if (tenant == null || tenant.getId() == null) return Optional.empty();
        return configs.findByTenant_IdAndProvider(tenant.getId(), type);
    }

    PatchConnectorConfig requireConfig(Tenant tenant, PatchProviderType type) {
        return findConfig(tenant, type).orElseThrow(() -> new ResponseStatusException(BAD_REQUEST,
                type.displayName() + " patch connector is not configured yet"));
    }

    /** The decrypted secret, or null for a provider that does not use one. */
    String secret(PatchProvider provider, PatchConnectorConfig config) {
        if (!provider.requiresSecret()) return null;
        if (!hasSecret(config)) {
            throw new IllegalStateException(provider.type().displayName() + " credentials are not saved yet");
        }
        return encryption.decrypt(config.getCredentialSecret());
    }

    boolean isUsable(PatchProvider provider, PatchConnectorConfig config) {
        return config.isEnabled() && (!provider.requiresSecret() || hasSecret(config));
    }

    private static boolean hasSecret(PatchConnectorConfig config) {
        return config.getCredentialSecret() != null && !config.getCredentialSecret().isBlank();
    }

    private PatchConnectorConfigResponse toResponse(PatchProviderType type, PatchConnectorConfig config) {
        if (config == null) {
            return new PatchConnectorConfigResponse(null, type.name(), type.displayName(), false, false, null, null, null,
                    null, true, false, 1440, null, null, null, null);
        }
        PatchProvider provider = registry.require(type);
        return new PatchConnectorConfigResponse(
                config.getId(), type.name(), type.displayName(),
                !provider.requiresSecret() || hasSecret(config),
                hasSecret(config),
                config.getBaseUrl(), config.getDirectoryId(), config.getClientId(), config.getUsername(),
                config.isEnabled(), config.isAutoSyncEnabled(),
                config.getIntervalMinutes() == null ? 1440 : config.getIntervalMinutes(),
                config.getLastTestStatus(), config.getLastTestMessage(), config.getLastTestedAt(), config.getLastSyncAt());
    }

    /** Removes bearer tokens, passwords and secrets a remote error might have echoed back. */
    static String sanitize(String message) {
        if (message == null) return null;
        return message
                .replaceAll("(?i)(bearer\\s+)[A-Za-z0-9._~+/=-]+", "$1***")
                .replaceAll("(?i)(\"?(password|client_secret|secret|token|access_token|session)\"?\\s*[:=]\\s*\"?)[^\"&\\s,}]+", "$1***");
    }

    private static String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String truncate(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
