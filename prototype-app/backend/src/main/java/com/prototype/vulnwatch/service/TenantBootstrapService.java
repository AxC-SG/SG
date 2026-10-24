package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class TenantBootstrapService {

    private static final Logger log = LoggerFactory.getLogger(TenantBootstrapService.class);

    private final TenantRepository tenantRepository;
    private final TenantSchemaService tenantSchemaService;
    private final TenantSchemaMigrationService tenantSchemaMigrationService;
    private final boolean synchronousTenantProvisioningEnabled;

    @Autowired
    public TenantBootstrapService(
            TenantRepository tenantRepository,
            TenantSchemaService tenantSchemaService,
            TenantSchemaMigrationService tenantSchemaMigrationService,
            @Value("${app.demo.synchronous-tenant-provisioning-enabled:false}") boolean synchronousTenantProvisioningEnabled
    ) {
        this.tenantRepository = tenantRepository;
        this.tenantSchemaService = tenantSchemaService;
        this.tenantSchemaMigrationService = tenantSchemaMigrationService;
        this.synchronousTenantProvisioningEnabled = synchronousTenantProvisioningEnabled;
    }

    /** Compatibility constructor for focused unit tests that only verify default-tenant repair. */
    public TenantBootstrapService(TenantRepository tenantRepository, TenantSchemaService tenantSchemaService) {
        this(tenantRepository, tenantSchemaService, null, false);
    }

    @EventListener(ApplicationReadyEvent.class)
    @Order(0)
    public void ensureBootstrapTenant() {
        TenantContext.runAsPlatform(() -> {
            Tenant defaultTenant = tenantRepository.findBySchemaName(TenantService.DEFAULT_TENANT_SCHEMA)
                    .filter(Tenant::isInternal)
                    .orElseThrow(() -> new IllegalStateException("Run the installation bootstrap to register SG Internal"));
            String normalizedDefaultSchema = TenantService.DEFAULT_TENANT_SCHEMA;
            warnIfNotReady(defaultTenant, normalizedDefaultSchema);

            for (Tenant tenant : tenantRepository.findAll()) {
                String normalizedSchema = tenant.getSchemaName() == null || tenant.getSchemaName().isBlank()
                        ? tenantSchemaService.deriveSchemaName(tenant.getSlug())
                        : tenantSchemaService.normalizeSchemaName(tenant.getSchemaName());
                if (!normalizedSchema.equals(tenant.getSchemaName())) {
                    tenant.setSchemaName(normalizedSchema);
                    tenant.setUpdatedAt(Instant.now());
                    tenantRepository.save(tenant);
                }
                if ("ACTIVE".equalsIgnoreCase(tenant.getStatus())) {
                    warnIfNotReady(tenant, tenant.getSchemaName());
                }
            }
            if (synchronousTenantProvisioningEnabled && tenantSchemaMigrationService != null) {
                tenantRepository.findAllByOrderByCreatedAtAsc().stream()
                        .filter(tenant -> "PROVISIONING".equalsIgnoreCase(tenant.getStatus()))
                        .forEach(this::provisionIfNeeded);
            }
        });
    }

    private void provisionIfNeeded(Tenant tenant) {
        try {
            tenantSchemaMigrationService.provisionNewTenant(tenant);
            log.info("Provisioned tenant schema tenantId={} schema={}", tenant.getId(), tenant.getSchemaName());
        } catch (RuntimeException ex) {
            log.error("Tenant schema provisioning failed tenantId={} schema={}: {}",
                    tenant.getId(), tenant.getSchemaName(), ex.getMessage());
        }
    }

    private void warnIfNotReady(Tenant tenant, String schemaName) {
        try {
            tenantSchemaService.assertSchemaReady(schemaName);
        } catch (RuntimeException ex) {
            log.warn("Tenant schema is not ready; runtime remains alive and tenant access stays blocked"
                            + " tenantId={} schema={} reason={}",
                    tenant.getId(), schemaName, ex.getMessage());
        }
    }
}
