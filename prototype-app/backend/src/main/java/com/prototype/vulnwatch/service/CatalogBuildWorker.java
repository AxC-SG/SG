package com.prototype.vulnwatch.service;

import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/** Uses the established runtime-role and tenant schema runner; one bounded batch per tenant per sweep. */
@Service
public class CatalogBuildWorker {
    private static final Logger LOG=LoggerFactory.getLogger(CatalogBuildWorker.class);
    private final JdbcTemplate jdbc;
    private final TenantSchemaExecutionService schemas;
    private final CatalogBuildService builds;
    private final BackgroundTaskExecutionPolicy background;
    public CatalogBuildWorker(JdbcTemplate jdbc,TenantSchemaExecutionService schemas,CatalogBuildService builds,BackgroundTaskExecutionPolicy background) {
        this.jdbc=jdbc; this.schemas=schemas; this.builds=builds; this.background=background;
    }
    @Scheduled(fixedDelayString="${app.intelligence.catalog-build-poll-ms:3000}")
    public synchronized void poll() {
        if(!background.allowsBackgroundTask("intelligence.catalog-build")) return;
        TenantContext.runAsPlatform(() -> {
            var tenants=jdbc.queryForList("""
                    select q.tenant_id from platform.tenant_catalog_build_queue q
                    join platform.tenants t on t.id=q.tenant_id
                    where q.status='PENDING' and q.available_at<=now() and t.status='ACTIVE'
                    order by q.available_at,q.updated_at,q.tenant_id limit 10
                    """,UUID.class);
            for(UUID tenant:tenants) {
                if(!background.allowsBackgroundTask("intelligence.catalog-build")) break;
                try { schemas.run(tenant,builds::processNext); }
                catch(CatalogBuildService.BatchFailure failure) {
                    try { schemas.run(tenant,() -> { builds.recordWorkerFailure(failure.buildId(),failure.checkpoint()); return null; }); }
                    catch(RuntimeException ignored) { LOG.warn("Catalog build retry state unavailable for tenant {}",tenant); }
                    LOG.warn("Catalog build batch rolled back for tenant {}",tenant);
                } catch(RuntimeException failure) {
                    // No raw exception/message logging: request metadata and source payloads may contain secrets.
                    LOG.warn("Catalog build tenant unavailable: {}",tenant);
                }
            }
        });
    }
}
