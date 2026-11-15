package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.migration.PackagedMigrationCatalog;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.TenantSchemaStatusService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Live schema-state evidence for releases: readiness stays UP while tenants are unready, so the
 * worker logs the control plane's view once a minute for release verification to read without
 * database or owner credentials.
 */
@Component
@ConditionalOnProperty(name = "app.tenancy.enforce-schema-version", havingValue = "true")
public class TenantSchemaStateReporter {

    static final String PHRASE = "tenant_schema_state";

    private static final Logger LOG = LoggerFactory.getLogger(TenantSchemaStateReporter.class);

    private final TenantSchemaStatusService status;
    private final BackgroundTaskExecutionPolicy backgroundTasks;
    private final int packagedTenantTarget;

    public TenantSchemaStateReporter(
            TenantSchemaStatusService status,
            PackagedMigrationCatalog migrationCatalog,
            BackgroundTaskExecutionPolicy backgroundTasks
    ) {
        this.status = status;
        this.backgroundTasks = backgroundTasks;
        this.packagedTenantTarget = migrationCatalog.tenantTarget();
    }

    @Scheduled(zone = "UTC", cron = "${app.observability.tenant-schema-state.cron:45 * * * * *}")
    public void report() {
        if (!backgroundTasks.allowsBackgroundTask("tenant-schema-state")) {
            return;
        }
        try {
            LOG.info("{} unready_tenants={} supported={} active_versions={} packaged_target={}", PHRASE,
                    status.readinessFailures(packagedTenantTarget), status.supportedTenantVersions(),
                    status.activeTenantVersions(), packagedTenantTarget);
        } catch (RuntimeException failure) {
            LOG.warn("{} unavailable: {}", PHRASE, failure.getMessage());
        }
    }
}
