package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.InventoryConnectorHealthResponse;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import com.prototype.vulnwatch.repo.ServiceNowCmdbConfigRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PlatformInventoryConnectorHealthService {

    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TenantSchemaService tenantSchemaService;
    private final ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository;
    private final SccmCmdbConfigRepository sccmCmdbConfigRepository;
    private final AwsDiscoveryConfigRepository awsDiscoveryConfigRepository;
    private com.prototype.vulnwatch.repo.GcpDiscoveryConfigRepository gcpDiscoveryConfigRepository;

    @Autowired
    public PlatformInventoryConnectorHealthService(
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            TenantSchemaService tenantSchemaService,
            ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository,
            SccmCmdbConfigRepository sccmCmdbConfigRepository,
            AwsDiscoveryConfigRepository awsDiscoveryConfigRepository
    ) {
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.tenantSchemaService = tenantSchemaService;
        this.serviceNowCmdbConfigRepository = serviceNowCmdbConfigRepository;
        this.sccmCmdbConfigRepository = sccmCmdbConfigRepository;
        this.awsDiscoveryConfigRepository = awsDiscoveryConfigRepository;
    }

    /** Compatibility constructor for focused unit tests that do not need schema existence checks. */
    public PlatformInventoryConnectorHealthService(
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository,
            SccmCmdbConfigRepository sccmCmdbConfigRepository,
            AwsDiscoveryConfigRepository awsDiscoveryConfigRepository
    ) {
        this(tenantService, tenantSchemaExecutionService, null,
                serviceNowCmdbConfigRepository, sccmCmdbConfigRepository, awsDiscoveryConfigRepository);
    }

    @Autowired(required = false)
    public void setGcpDiscoveryConfigRepository(com.prototype.vulnwatch.repo.GcpDiscoveryConfigRepository repository) {
        this.gcpDiscoveryConfigRepository = repository;
    }

    public List<InventoryConnectorHealthResponse> listInventoryConnectorHealth() {
        return TenantContext.runAsPlatform(() -> {
            List<InventoryConnectorHealthResponse> responses = new ArrayList<>();
            for (Tenant tenant : tenantService.listTenants()) {
                // A tenant can exist in the platform registry before the controlled
                // schema bootstrap has created its tenant schema. It has no connector
                // health to report yet and must not make the platform panel fail.
                if (!"ACTIVE".equalsIgnoreCase(tenant.getStatus())
                        || (tenantSchemaService != null && !tenantSchemaService.schemaExists(tenant.getSchemaName()))) {
                    continue;
                }
                tenantSchemaExecutionService.run(tenant, () -> {
                    serviceNowCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "servicenow")
                            .ifPresent(config -> responses.add(toResponse(tenant, "servicenow", config.isEnabled(),
                                    config.isAutoSyncEnabled(), config.getLastTestStatus(), config.getLastTestMessage(),
                                    config.getLastTestedAt(), config.getLastSyncAt())));
                    sccmCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm")
                            .ifPresent(config -> responses.add(toResponse(tenant, "sccm", config.isEnabled(),
                                    config.isAutoSyncEnabled(), config.getLastTestStatus(), config.getLastTestMessage(),
                                    config.getLastTestedAt(), config.getLastSyncAt())));
                    awsDiscoveryConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws")
                            .ifPresent(config -> responses.add(toResponse(tenant, "aws", config.isEnabled(),
                                    config.isAutoSyncEnabled(), config.getLastTestStatus(), config.getLastTestMessage(),
                                    config.getLastTestedAt(), config.getLastSyncAt())));
                    if (gcpDiscoveryConfigRepository != null) {
                        gcpDiscoveryConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "gcp")
                                .ifPresent(config -> responses.add(toResponse(tenant, "gcp", config.isEnabled(),
                                        config.isAutoSyncEnabled(), config.getLastTestStatus(), config.getLastTestMessage(),
                                        config.getLastTestedAt(), config.getLastSyncAt())));
                    }
                    return null;
                });
            }
            responses.sort(Comparator
                    .comparing(InventoryConnectorHealthResponse::tenantName, Comparator.nullsLast(String::compareToIgnoreCase))
                    .thenComparing(InventoryConnectorHealthResponse::connectorKey, Comparator.nullsLast(String::compareToIgnoreCase)));
            return responses;
        });
    }

    private InventoryConnectorHealthResponse toResponse(
            Tenant tenant,
            String connectorKey,
            boolean enabled,
            boolean autoSyncEnabled,
            String lastTestStatus,
            String lastTestMessage,
            Instant lastTestedAt,
            Instant lastSyncAt
    ) {
        return new InventoryConnectorHealthResponse(
                tenant.getId(),
                tenant.getName(),
                connectorKey,
                enabled,
                autoSyncEnabled,
                lastTestStatus,
                sanitize(lastTestMessage),
                lastTestedAt,
                lastSyncAt,
                deriveHealthState(enabled, lastTestStatus, lastSyncAt)
        );
    }

    private String deriveHealthState(boolean enabled, String lastTestStatus, Instant lastSyncAt) {
        if (!enabled) {
            return "DISABLED";
        }
        if (lastTestStatus != null && lastTestStatus.equalsIgnoreCase("FAILED")) {
            return "ERROR";
        }
        if (lastSyncAt == null) {
            return "PENDING";
        }
        return "HEALTHY";
    }

    private String sanitize(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String sanitized = value.trim();
        return sanitized.length() > 240 ? sanitized.substring(0, 240) + "..." : sanitized;
    }
}
