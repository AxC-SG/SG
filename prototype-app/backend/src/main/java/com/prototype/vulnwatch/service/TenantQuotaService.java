package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.AuditEventRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryConfigRepository;
import com.prototype.vulnwatch.repo.AwsDiscoveryTargetRepository;
import com.prototype.vulnwatch.repo.IngestionJobRepository;
import com.prototype.vulnwatch.repo.JiraTicketingConfigRepository;
import com.prototype.vulnwatch.repo.SccmCmdbConfigRepository;
import com.prototype.vulnwatch.repo.ServiceAccountRepository;
import com.prototype.vulnwatch.repo.ServiceNowCmdbConfigRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TenantQuotaService {

    private final AwsDiscoveryConfigRepository awsDiscoveryConfigRepository;
    private final AwsDiscoveryTargetRepository awsDiscoveryTargetRepository;
    private final SccmCmdbConfigRepository sccmCmdbConfigRepository;
    private final ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository;
    private final JiraTicketingConfigRepository jiraTicketingConfigRepository;
    private final ServiceAccountRepository serviceAccountRepository;
    private final AuditEventRepository auditEventRepository;
    private final IngestionJobRepository ingestionJobRepository;
    private final TenantRepository tenantRepository;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final AuditEventService auditEventService;
    private final IngestionJobMetricsService ingestionJobMetricsService;
    private com.prototype.vulnwatch.repo.GcpDiscoveryConfigRepository gcpDiscoveryConfigRepository;
    private com.prototype.vulnwatch.repo.GcpDiscoveryTargetRepository gcpDiscoveryTargetRepository;
    private com.prototype.vulnwatch.repo.PatchConnectorConfigRepository patchConnectorConfigRepository;
    private final int sbomRateLimitWindowSeconds;
    private final int sbomRateLimitMaxAcceptedJobs;
    private final int sbomAdmissionMaxActiveJobs;

    public TenantQuotaService(
            AwsDiscoveryConfigRepository awsDiscoveryConfigRepository,
            AwsDiscoveryTargetRepository awsDiscoveryTargetRepository,
            SccmCmdbConfigRepository sccmCmdbConfigRepository,
            ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository,
            JiraTicketingConfigRepository jiraTicketingConfigRepository,
            ServiceAccountRepository serviceAccountRepository,
            AuditEventRepository auditEventRepository,
            IngestionJobRepository ingestionJobRepository,
            TenantRepository tenantRepository,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            AuditEventService auditEventService,
            IngestionJobMetricsService ingestionJobMetricsService,
            @org.springframework.beans.factory.annotation.Value("${app.ingestion.admission.rate-limit-window-seconds:300}") int sbomRateLimitWindowSeconds,
            @org.springframework.beans.factory.annotation.Value("${app.ingestion.admission.max-accepted-jobs-per-window:10}") int sbomRateLimitMaxAcceptedJobs,
            @org.springframework.beans.factory.annotation.Value("${app.ingestion.admission.max-active-jobs-per-tenant:1}") int sbomAdmissionMaxActiveJobs
    ) {
        this.awsDiscoveryConfigRepository = awsDiscoveryConfigRepository;
        this.awsDiscoveryTargetRepository = awsDiscoveryTargetRepository;
        this.sccmCmdbConfigRepository = sccmCmdbConfigRepository;
        this.serviceNowCmdbConfigRepository = serviceNowCmdbConfigRepository;
        this.jiraTicketingConfigRepository = jiraTicketingConfigRepository;
        this.serviceAccountRepository = serviceAccountRepository;
        this.auditEventRepository = auditEventRepository;
        this.ingestionJobRepository = ingestionJobRepository;
        this.tenantRepository = tenantRepository;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.auditEventService = auditEventService;
        this.ingestionJobMetricsService = ingestionJobMetricsService;
        this.sbomRateLimitWindowSeconds = Math.max(1, sbomRateLimitWindowSeconds);
        this.sbomRateLimitMaxAcceptedJobs = Math.max(1, sbomRateLimitMaxAcceptedJobs);
        this.sbomAdmissionMaxActiveJobs = Math.max(1, sbomAdmissionMaxActiveJobs);
    }

    public void assertCanCreateConnector(Tenant tenant, String connectorType) {
        if (isUnlimitedConnectorMode(tenant)) {
            return;
        }
        int max = safeLimit(tenant.getMaxConnectorCount());
        long current = countConnectors(tenant);
        if (current >= max) {
            throw new QuotaExceededException(
                    "TENANT_CONNECTOR_LIMIT_EXCEEDED",
                    "Tenant connector limit exceeded for " + connectorType + " (" + current + "/" + max + ")"
            );
        }
    }

    public void assertCanCreateServiceAccount(Tenant tenant) {
        int max = safeLimit(tenant.getMaxServiceAccountCount());
        long current = tenantSchemaExecutionService.run(tenant, (Supplier<Long>) serviceAccountRepository::count);
        if (current >= max) {
            throw new QuotaExceededException(
                    "TENANT_SERVICE_ACCOUNT_LIMIT_EXCEEDED",
                    "Tenant service account limit exceeded (" + current + "/" + max + ")"
            );
        }
    }

    public void assertCanRefreshTenantExposure(Tenant tenant) {
        int max = safeLimit(tenant.getMaxDailyExposureRefreshes());
        Instant since = Instant.now().minus(24, ChronoUnit.HOURS);
        long current = auditEventRepository.countByTenant_IdAndActionAndOccurredAtAfter(
                tenant.getId(),
                "tenant.org_cves.refresh",
                since);
        if (current >= max) {
            throw new QuotaExceededException(
                    "TENANT_EXPOSURE_REFRESH_DAILY_LIMIT_EXCEEDED",
                    "Tenant exposure refresh daily limit exceeded (" + current + "/" + max + ")"
            );
        }
    }

    public void assertCanCreateSbomIngestionJob(Tenant tenant, String sourceType) {
        int max = safeLimit(tenant.getMaxDailySbomUploads());
        int rateLimitWindowSeconds = effectiveTenantLimit(tenant.getSbomRateLimitWindowSeconds(), sbomRateLimitWindowSeconds);
        int maxAcceptedJobsPerWindow = effectiveTenantLimit(tenant.getMaxSbomJobsPerRateLimitWindow(), sbomRateLimitMaxAcceptedJobs);
        int maxActiveSbomJobs = effectiveTenantLimit(tenant.getMaxActiveSbomJobs(), sbomAdmissionMaxActiveJobs);
        Instant since = Instant.now().minus(24, ChronoUnit.HOURS);
        long current = tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.countAcceptedSince(since));
        if (current >= max) {
            recordSbomAdmissionFailure(
                    "ingestion.job.quota_denied",
                    sourceType,
                    "{\"reason\":\"daily_quota\",\"acceptedInLast24Hours\":" + current + ",\"limit\":" + max + "}"
            );
            ingestionJobMetricsService.recordQuotaRejected(sourceType);
            throw new QuotaExceededException(
                    "TENANT_SBOM_DAILY_LIMIT_EXCEEDED",
                    "Tenant SBOM ingestion daily limit exceeded (" + current + "/" + max + ")",
                    3600
            );
        }

        Instant burstSince = Instant.now().minus(rateLimitWindowSeconds, ChronoUnit.SECONDS);
        long acceptedInWindow = tenantSchemaExecutionService.run(tenant, () -> ingestionJobRepository.countAcceptedSince(burstSince));
        if (acceptedInWindow >= maxAcceptedJobsPerWindow) {
            recordSbomAdmissionFailure(
                    "ingestion.job.rate_limited",
                    sourceType,
                    "{\"reason\":\"rate_limit\",\"acceptedInWindow\":" + acceptedInWindow
                            + ",\"windowSeconds\":" + rateLimitWindowSeconds
                            + ",\"limit\":" + maxAcceptedJobsPerWindow + "}"
            );
            ingestionJobMetricsService.recordRateLimited(sourceType);
            throw new QuotaExceededException(
                    "TENANT_SBOM_RATE_LIMIT_EXCEEDED",
                    "Tenant SBOM ingestion rate limit exceeded (" + acceptedInWindow + "/" + maxAcceptedJobsPerWindow
                            + " in " + rateLimitWindowSeconds + "s)",
                    rateLimitWindowSeconds
            );
        }

        long activeJobs = tenantSchemaExecutionService.run(
                tenant,
                () -> ingestionJobRepository.countByStatusIn(List.of("QUEUED", "RUNNING"))
        );
        if (activeJobs >= maxActiveSbomJobs) {
            recordSbomAdmissionFailure(
                    "ingestion.job.admission_denied",
                    sourceType,
                    "{\"reason\":\"active_job_limit\",\"activeJobs\":" + activeJobs + ",\"limit\":" + maxActiveSbomJobs + "}"
            );
            ingestionJobMetricsService.recordAdmissionRejected(sourceType);
            throw new QuotaExceededException(
                    "TENANT_SBOM_ACTIVE_JOB_LIMIT_EXCEEDED",
                    "Tenant SBOM ingestion backlog is full (" + activeJobs + "/" + maxActiveSbomJobs + ")",
                    60
            );
        }
    }

    public void assertCanExportRows(Tenant tenant, long requestedRows) {
        int max = safeLimit(tenant.getMaxExportRows());
        if (requestedRows > max) {
            throw new QuotaExceededException(
                    "TENANT_EXPORT_ROW_LIMIT_EXCEEDED",
                    "Tenant export row limit exceeded (" + requestedRows + "/" + max + ")"
            );
        }
    }

    public void assertCanExportRows(UUID tenantId, long requestedRows) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        assertCanExportRows(tenant, requestedRows);
    }

    /** GCP repositories are injected after construction so existing callers keep their signature. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setGcpDiscoveryRepositories(
            com.prototype.vulnwatch.repo.GcpDiscoveryConfigRepository configs,
            com.prototype.vulnwatch.repo.GcpDiscoveryTargetRepository targets
    ) {
        this.gcpDiscoveryConfigRepository = configs;
        this.gcpDiscoveryTargetRepository = targets;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setPatchConnectorConfigRepository(com.prototype.vulnwatch.repo.PatchConnectorConfigRepository repository) {
        this.patchConnectorConfigRepository = repository;
    }

    private long countConnectors(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () ->
                (awsDiscoveryConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws").isPresent() ? 1L : 0L)
                        + awsDiscoveryTargetRepository.countByTenant_Id(tenant.getId())
                        + (sccmCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm").isPresent() ? 1L : 0L)
                        + (serviceNowCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "servicenow").isPresent() ? 1L : 0L)
                        // Ticketing connectors consume the tenant's connector allowance too;
                        // omitting Jira here would let a tenant at its limit add one for free.
                        + jiraTicketingConfigRepository.countByTenant_Id(tenant.getId())
                        // GCP counts like AWS: the connector plus each project target.
                        + (gcpDiscoveryConfigRepository == null ? 0L : gcpDiscoveryConfigRepository.countByTenant_Id(tenant.getId()))
                        + (gcpDiscoveryTargetRepository == null ? 0L : gcpDiscoveryTargetRepository.countByTenant_Id(tenant.getId()))
                        + (patchConnectorConfigRepository == null ? 0L : patchConnectorConfigRepository.countByTenant_Id(tenant.getId()))
        );
    }

    private int safeLimit(Integer value) {
        return value == null ? 0 : Math.max(0, value);
    }

    private int effectiveTenantLimit(Integer tenantValue, int fallbackValue) {
        return tenantValue == null ? fallbackValue : Math.max(0, tenantValue);
    }

    /**
     * Temporary policy: a connector limit of zero means "unlimited" rather than
     * "none allowed", so older demo tenants and any manually provisioned tenant
     * with a zero quota do not get blocked from configuring integrations.
     */
    private boolean isUnlimitedConnectorMode(Tenant tenant) {
        return tenant != null && safeLimit(tenant.getMaxConnectorCount()) == 0;
    }

    private void recordSbomAdmissionFailure(String action, String sourceType, String detailsJson) {
        String details = detailsJson == null
                ? null
                : detailsJson.substring(0, detailsJson.length() - 1)
                + ",\"sourceType\":\"" + escapeJson(sourceType) + "\"}";
        auditEventService.record(action, "tenant", null, details);
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"");
    }
}
