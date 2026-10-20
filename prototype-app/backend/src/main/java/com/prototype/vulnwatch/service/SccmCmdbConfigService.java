package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.SccmAuthType;
import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SccmCmdbConfigRequest;
import com.prototype.vulnwatch.dto.SccmCmdbConfigResponse;
import com.prototype.vulnwatch.dto.SccmConnectionTestResponse;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

@Service
public class SccmCmdbConfigService {

    private final SccmCmdbConfigRepository sccmCmdbConfigRepository;
    private final SccmQueryService sccmQueryService;
    private final TenantQuotaService tenantQuotaService;
    private final CredentialEncryptionService credentialEncryptionService;

    public SccmCmdbConfigService(
            SccmCmdbConfigRepository sccmCmdbConfigRepository,
            SccmQueryService sccmQueryService,
            TenantQuotaService tenantQuotaService,
            CredentialEncryptionService credentialEncryptionService
    ) {
        this.sccmCmdbConfigRepository = sccmCmdbConfigRepository;
        this.sccmQueryService = sccmQueryService;
        this.tenantQuotaService = tenantQuotaService;
        this.credentialEncryptionService = credentialEncryptionService;
    }

    @Transactional(readOnly = true)
    public SccmCmdbConfigResponse get(Tenant tenant) {
        return toResponse(findConfig(tenant).orElse(null));
    }

    @Transactional
    public SccmCmdbConfigResponse save(Tenant tenant, SccmCmdbConfigRequest request) {
        SccmPilotPolicy.requireEnabled();
        SccmCmdbConfig config = findConfig(tenant)
                .orElseGet(() -> {
                    tenantQuotaService.assertCanCreateConnector(tenant, "sccm");
                    SccmCmdbConfig created = new SccmCmdbConfig();
                    created.setTenant(tenant);
                    created.setSourceSystem("sccm");
                    return created;
                });
        apply(config, request);
        config.touch();
        return toResponse(sccmCmdbConfigRepository.save(config));
    }

    @Transactional
    public SccmConnectionTestResponse test(Tenant tenant) {
        SccmPilotPolicy.requireEnabled();
        SccmCmdbConfig config = requireConfig(tenant);

        Instant testedAt = Instant.now();
        boolean[] results = sccmQueryService.testConnection(config);
        boolean systemViewReachable = results[0];
        boolean softwareViewReachable = results[1];
        boolean success = systemViewReachable && softwareViewReachable;

        String message;
        if (config.isMockMode()) {
            message = "SCCM mock mode: connection test always succeeds. No real SQL Server connection was attempted.";
        } else if (success) {
            message = "SCCM connection succeeded. v_R_System and v_GS_INSTALLED_SOFTWARE are reachable.";
        } else if (systemViewReachable) {
            message = "SCCM connection partial: v_R_System reachable but v_GS_INSTALLED_SOFTWARE was not.";
        } else {
            message = "SCCM connection failed: unable to reach v_R_System. Verify JDBC URL, credentials, and network access.";
        }

        config.setLastTestStatus(success ? "SUCCESS" : "FAILED");
        config.setLastTestMessage(message);
        config.setLastTestedAt(testedAt);
        config.touch();
        sccmCmdbConfigRepository.save(config);

        return new SccmConnectionTestResponse(
                success ? "SUCCESS" : "FAILED",
                message,
                systemViewReachable,
                softwareViewReachable,
                testedAt
        );
    }

    Optional<SccmCmdbConfig> findConfig(Tenant tenant) {
        if (tenant == null || tenant.getId() == null) {
            return Optional.empty();
        }
        return sccmCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm");
    }

    SccmCmdbConfig requireConfig(Tenant tenant) {
        return findConfig(tenant)
                .orElseThrow(() -> new ResponseStatusException(BAD_REQUEST, "SCCM connector is not configured yet"));
    }

    // ── Private helpers ────────────────────────────────────────────────────────────────────────

    private void apply(SccmCmdbConfig config, SccmCmdbConfigRequest request) {
        config.setJdbcUrl(trimToNull(request.jdbcUrl()));
        config.setAuthType(parseAuthType(request.authType()));
        config.setUsername(trimToNull(request.username()));
        if (hasText(request.credentialSecret())) {
            config.setCredentialSecret(credentialEncryptionService.encrypt(request.credentialSecret().trim()));
        }
        config.setSiteCode(trimToNull(request.siteCode()));
        config.setDatabaseName(defaultIfBlank(request.databaseName(), "CM_P01"));
        config.setFetchSize(request.fetchSize() == null ? 500 : Math.max(1, request.fetchSize()));
        config.setQueryTimeoutSeconds(request.queryTimeoutSeconds() == null ? 120 : Math.max(1, request.queryTimeoutSeconds()));
        config.setMockMode(request.mockMode() != null && request.mockMode());
        config.setEnabled(request.enabled() == null || request.enabled());
        config.setAutoSyncEnabled(request.autoSyncEnabled() != null && request.autoSyncEnabled());
        config.setIntervalMinutes(request.intervalMinutes() == null ? 1440 : Math.max(5, request.intervalMinutes()));
    }

    private SccmCmdbConfigResponse toResponse(SccmCmdbConfig config) {
        if (config == null) {
            return new SccmCmdbConfigResponse(
                    null,
                    "sccm",
                    false,
                    "",
                    SccmAuthType.SQL_AUTH.name(),
                    "",
                    false,
                    "",
                    "CM_P01",
                    500,
                    120,
                    false,
                    true,
                    false,
                    1440,
                    null,
                    null,
                    null,
                    null
            );
        }
        boolean configured = hasText(config.getJdbcUrl())
                && (config.isMockMode() || hasText(config.getCredentialSecret()));
        return new SccmCmdbConfigResponse(
                config.getId(),
                config.getSourceSystem(),
                configured,
                defaultIfBlank(config.getJdbcUrl(), ""),
                (config.getAuthType() == null ? SccmAuthType.SQL_AUTH : config.getAuthType()).name(),
                defaultIfBlank(config.getUsername(), ""),
                hasText(config.getCredentialSecret()),
                defaultIfBlank(config.getSiteCode(), ""),
                defaultIfBlank(config.getDatabaseName(), "CM_P01"),
                config.getFetchSize() == null ? 500 : config.getFetchSize(),
                config.getQueryTimeoutSeconds() == null ? 120 : config.getQueryTimeoutSeconds(),
                config.isMockMode(),
                config.isEnabled(),
                config.isAutoSyncEnabled(),
                config.getIntervalMinutes() == null ? 1440 : config.getIntervalMinutes(),
                config.getLastTestStatus(),
                config.getLastTestMessage(),
                config.getLastTestedAt(),
                config.getLastSyncAt()
        );
    }

    private SccmAuthType parseAuthType(String value) {
        if (!hasText(value)) {
            return SccmAuthType.SQL_AUTH;
        }
        String normalized = value.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        try {
            return SccmAuthType.valueOf(normalized);
        } catch (IllegalArgumentException ignored) {
            throw new ResponseStatusException(BAD_REQUEST, "Unsupported SCCM auth type: " + value);
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String trimToNull(String value) {
        if (value == null) {
            return null;
        }
        String trimmed = value.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private String defaultIfBlank(String value, String fallback) {
        return hasText(value) ? value.trim() : fallback;
    }

}
