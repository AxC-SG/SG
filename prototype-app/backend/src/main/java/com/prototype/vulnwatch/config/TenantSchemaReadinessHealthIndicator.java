package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantSchemaStatusService;
import com.prototype.vulnwatch.migration.PackagedMigrationCatalog;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "app.tenancy.enforce-schema-version", havingValue = "true")
public class TenantSchemaReadinessHealthIndicator implements HealthIndicator {

    private final TenantSchemaStatusService service;
    private final int packagedTenantTarget;

    public TenantSchemaReadinessHealthIndicator(
            TenantSchemaStatusService service,
            PackagedMigrationCatalog migrationCatalog
    ) {
        this.service = service;
        this.packagedTenantTarget = migrationCatalog.tenantTarget();
    }

    @Override
    public Health health() {
        try {
            long failures = service.readinessFailures(packagedTenantTarget);
            // A customer's migration state controls that customer's eligibility. The control
            // plane query failing still removes the instance from service.
            return Health.up().withDetail("unreadyTenantCount",failures)
                    .withDetail("supportedTenantVersions", service.supportedTenantVersions())
                    .withDetail("packagedTenantTarget",packagedTenantTarget).build();
        } catch (RuntimeException ex) {
            return Health.down().withDetail("reason", "tenant schema control plane unavailable").build();
        }
    }
}
