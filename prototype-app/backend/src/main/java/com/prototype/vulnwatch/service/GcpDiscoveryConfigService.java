package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.GcpServiceAccountKey;
import com.prototype.vulnwatch.domain.GcpDiscoveryConfig;
import com.prototype.vulnwatch.domain.GcpDiscoveryTarget;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.GcpDiscoveryConfigRequest;
import com.prototype.vulnwatch.dto.GcpDiscoveryConfigResponse;
import com.prototype.vulnwatch.repo.GcpDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.GcpDiscoveryTargetRepository;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

/**
 * Owns the tenant-level GCP connector and the customer's service account key.
 *
 * <p>The key is validated ({@link GcpServiceAccountKey}), encrypted, and never returned. Saving
 * without a key keeps the stored one, as for every other connector secret.
 */
@Service
public class GcpDiscoveryConfigService {

    /** Read-only roles the customer grants their service account on each project. */
    public static final List<String> REQUIRED_ROLES = List.of(
            "roles/browser",
            "roles/cloudasset.viewer",
            "roles/compute.viewer",
            "roles/osconfig.inventoryViewer");

    private final GcpDiscoveryConfigRepository repo;
    private final GcpDiscoveryTargetRepository targets;
    private final TenantQuotaService tenantQuotaService;
    private final CredentialEncryptionService encryption;
    private final ObjectMapper objectMapper;

    public GcpDiscoveryConfigService(
            GcpDiscoveryConfigRepository repo,
            GcpDiscoveryTargetRepository targets,
            TenantQuotaService tenantQuotaService,
            CredentialEncryptionService encryption,
            ObjectMapper objectMapper
    ) {
        this.repo = repo;
        this.targets = targets;
        this.tenantQuotaService = tenantQuotaService;
        this.encryption = encryption;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public GcpDiscoveryConfigResponse get(Tenant tenant) {
        return toResponse(findConfig(tenant).orElse(null));
    }

    @Transactional
    public GcpDiscoveryConfigResponse save(Tenant tenant, GcpDiscoveryConfigRequest request) {
        GcpDiscoveryConfigRequest safe = request == null ? new GcpDiscoveryConfigRequest(null, null, null, null) : request;
        GcpServiceAccountKey key = null;
        if (safe.credentialJson() != null && !safe.credentialJson().isBlank()) {
            try {
                key = GcpServiceAccountKey.parse(safe.credentialJson(), objectMapper);
            } catch (IllegalArgumentException invalid) {
                throw new ResponseStatusException(BAD_REQUEST, invalid.getMessage());
            }
        }
        boolean created = false;
        GcpDiscoveryConfig config = findConfig(tenant).orElse(null);
        if (config == null) {
            if (key == null) {
                throw new ResponseStatusException(BAD_REQUEST, "A GCP service account key (JSON) is required");
            }
            tenantQuotaService.assertCanCreateConnector(tenant, "gcp");
            config = new GcpDiscoveryConfig();
            config.setTenant(tenant);
            config.setSourceSystem("gcp");
            created = true;
        }
        if (key != null) {
            config.setCredentialSecret(encryption.encrypt(safe.credentialJson().trim()));
            config.setServiceAccountEmail(key.clientEmail());
            config.setKeyProjectId(key.projectId());
        }
        config.setEnabled(safe.enabled() == null || safe.enabled());
        config.setAutoSyncEnabled(safe.autoSyncEnabled() != null && safe.autoSyncEnabled());
        config.setIntervalMinutes(safe.intervalMinutes() == null ? 1440 : Math.max(60, safe.intervalMinutes()));
        config.touch();
        GcpDiscoveryConfig saved = repo.save(config);
        if (created && saved.getKeyProjectId() != null) {
            // The key's own project is the obvious first target; more can be added afterwards.
            GcpDiscoveryTarget target = new GcpDiscoveryTarget();
            target.setTenant(tenant);
            target.setConfig(saved);
            target.setProjectId(saved.getKeyProjectId());
            target.setResourceTypesJson(toJson(GcpResourceTypes.all()));
            targets.save(target);
        }
        return toResponse(saved);
    }

    /** The decrypted key for a usable connector; refuses a connector without one. */
    String credentialJson(GcpDiscoveryConfig config) {
        if (config.getCredentialSecret() == null || config.getCredentialSecret().isBlank()) {
            throw new IllegalStateException("The GCP connector has no service account key; save one first");
        }
        return encryption.decrypt(config.getCredentialSecret());
    }

    boolean hasCredential(GcpDiscoveryConfig config) {
        return config.getCredentialSecret() != null && !config.getCredentialSecret().isBlank();
    }

    Optional<GcpDiscoveryConfig> findConfig(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return Optional.empty();
        }
        return repo.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "gcp");
    }

    GcpDiscoveryConfig requireConfig(Tenant tenant) {
        return findConfig(tenant).orElseThrow(() -> new ResponseStatusException(BAD_REQUEST,
                "GCP Cloud Discovery connector is not configured yet"));
    }

    private GcpDiscoveryConfigResponse toResponse(GcpDiscoveryConfig config) {
        if (config == null) {
            return new GcpDiscoveryConfigResponse(null, false, false, null, null, true, false, 1440,
                    REQUIRED_ROLES, GcpResourceTypes.all(), null, null, null, null);
        }
        return new GcpDiscoveryConfigResponse(
                config.getId(),
                hasCredential(config),
                hasCredential(config),
                config.getServiceAccountEmail(),
                config.getKeyProjectId(),
                config.isEnabled(),
                config.isAutoSyncEnabled(),
                config.getIntervalMinutes() == null ? 1440 : config.getIntervalMinutes(),
                REQUIRED_ROLES,
                GcpResourceTypes.all(),
                config.getLastTestStatus(),
                config.getLastTestMessage(),
                config.getLastTestedAt(),
                config.getLastSyncAt());
    }

    private String toJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception impossible) {
            throw new IllegalStateException(impossible);
        }
    }
}
