package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

/**
 * Daily job that polls ServiceNow for the current status of every incident
 * that was linked to a finding, and writes the result back to {@code findings.incident_status}.
 *
 * <p>Runs once per day at 07:00 (configurable via the cron expression).
 */
@Service
public class FindingIncidentSyncService {

    private static final Logger log = LoggerFactory.getLogger(FindingIncidentSyncService.class);

    private final FindingRepository findingRepository;
    private final ServiceNowIncidentService serviceNowIncidentService;
    private final ServiceNowCmdbConfigService serviceNowCmdbConfigService;
    private final TenantWorkRunner tenantWorkRunner;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();

    public FindingIncidentSyncService(
            FindingRepository findingRepository,
            ServiceNowIncidentService serviceNowIncidentService,
            ServiceNowCmdbConfigService serviceNowCmdbConfigService,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.findingRepository = findingRepository;
        this.serviceNowIncidentService = serviceNowIncidentService;
        this.serviceNowCmdbConfigService = serviceNowCmdbConfigService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    /** Scheduled daily at 07:00 to sync ServiceNow incident statuses back to findings. */
    @Scheduled(zone = "UTC", cron = "0 0 7 * * *")
    public void syncIncidentStatuses() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("finding-incident-sync.sync-incident-statuses")) {
            return;
        }
        log.info("Starting ServiceNow incident status sync for all linked findings");
        try {
            syncAll();
        } catch (Exception e) {
            log.error("ServiceNow incident status sync failed", e);
        }
    }

    /** Can also be invoked on-demand (e.g. from an admin endpoint). */
    public SyncResult syncAll() {
        SyncAccumulator accumulator = new SyncAccumulator();
        tenantWorkRunner.forEachActiveTenant(tenant -> accumulator.add(syncCurrentTenant()));
        SyncResult result = accumulator.toResult();
        log.info("ServiceNow incident status sync complete — updated={}, unchanged={}, failed={}",
                result.updated(), result.unchanged(), result.failed());
        return result;
    }

    private SyncResult syncCurrentTenant() {
        List<Finding> findingsWithIncident = findingRepository.findAllWithIncidentId();
        if (findingsWithIncident.isEmpty()) {
            log.info("No findings with linked ServiceNow incidents — nothing to sync");
            return new SyncResult(0, 0, 0);
        }

        // Group by tenant to resolve one config per tenant
        Map<Tenant, List<Finding>> byTenant = findingsWithIncident.stream()
                .collect(Collectors.groupingBy(Finding::getTenant));

        int synced = 0;
        int unchanged = 0;
        int failed = 0;

        for (Map.Entry<Tenant, List<Finding>> entry : byTenant.entrySet()) {
            Tenant tenant = entry.getKey();
            List<Finding> tenantFindings = entry.getValue();

            var configOpt = serviceNowCmdbConfigService.resolveRuntimeConfig(tenant);
            if (configOpt.isEmpty()) {
                log.warn("ServiceNow not configured for tenant {} — skipping {} findings",
                        tenant.getId(), tenantFindings.size());
                failed += tenantFindings.size();
                continue;
            }
            var config = configOpt.get();

            // Group by incident ID to avoid redundant API calls for the same incident
            Map<String, List<Finding>> byIncident = tenantFindings.stream()
                    .collect(Collectors.groupingBy(Finding::getIncidentId));

            for (Map.Entry<String, List<Finding>> incEntry : byIncident.entrySet()) {
                String incidentNumber = incEntry.getKey();
                String newStatus = serviceNowIncidentService.getIncidentStatus(config, incidentNumber);

                if (newStatus == null) {
                    log.warn("Could not fetch status for incident {} — skipping", incidentNumber);
                    failed += incEntry.getValue().size();
                    continue;
                }

                for (Finding f : incEntry.getValue()) {
                    if (!newStatus.equals(f.getIncidentStatus())) {
                        f.setIncidentStatus(newStatus);
                        f.touch();
                        synced++;
                    } else {
                        unchanged++;
                    }
                }
                findingRepository.saveAll(incEntry.getValue());
            }
        }

        return new SyncResult(synced, unchanged, failed);
    }

    public record SyncResult(int updated, int unchanged, int failed) {}

    private static final class SyncAccumulator {
        private int updated;
        private int unchanged;
        private int failed;

        void add(SyncResult result) {
            updated += result.updated();
            unchanged += result.unchanged();
            failed += result.failed();
        }

        SyncResult toResult() {
            return new SyncResult(updated, unchanged, failed);
        }
    }
}
