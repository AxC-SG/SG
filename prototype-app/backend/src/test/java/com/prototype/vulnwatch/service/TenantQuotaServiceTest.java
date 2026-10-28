package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

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
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TenantQuotaServiceTest {

    @Mock
    AwsDiscoveryConfigRepository awsDiscoveryConfigRepository;
    @Mock
    AwsDiscoveryTargetRepository awsDiscoveryTargetRepository;
    @Mock
    SccmCmdbConfigRepository sccmCmdbConfigRepository;
    @Mock
    ServiceNowCmdbConfigRepository serviceNowCmdbConfigRepository;

    @Mock
    private JiraTicketingConfigRepository jiraTicketingConfigRepository;
    @Mock
    ServiceAccountRepository serviceAccountRepository;
    @Mock
    AuditEventRepository auditEventRepository;
    @Mock
    IngestionJobRepository ingestionJobRepository;
    @Mock
    TenantRepository tenantRepository;
    @Mock
    TenantSchemaExecutionService tenantSchemaExecutionService;
    @Mock
    AuditEventService auditEventService;
    @Mock
    IngestionJobMetricsService ingestionJobMetricsService;

    TenantQuotaService service;

    @BeforeEach
    void setUp() {
        service = new TenantQuotaService(
                awsDiscoveryConfigRepository,
                awsDiscoveryTargetRepository,
                sccmCmdbConfigRepository,
                serviceNowCmdbConfigRepository,
                jiraTicketingConfigRepository,
                serviceAccountRepository,
                auditEventRepository,
                ingestionJobRepository,
                tenantRepository,
                tenantSchemaExecutionService,
                auditEventService,
                ingestionJobMetricsService,
                300,
                10,
                1);
        lenient().when(tenantSchemaExecutionService.run(any(Tenant.class), any(Supplier.class)))
                .thenAnswer(invocation -> ((Supplier<?>) invocation.getArgument(1)).get());
    }

    @Test
    void assertCanCreateConnectorAllowsWhenBelowLimit() {
        Tenant tenant = tenant(3);
        when(awsDiscoveryConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws")).thenReturn(java.util.Optional.of(new com.prototype.vulnwatch.domain.AwsDiscoveryConfig()));
        when(awsDiscoveryTargetRepository.countByTenant_Id(tenant.getId())).thenReturn(1L);
        when(sccmCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm")).thenReturn(java.util.Optional.empty());
        when(serviceNowCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "servicenow")).thenReturn(java.util.Optional.empty());

        assertDoesNotThrow(() -> service.assertCanCreateConnector(tenant, "aws-target"));
    }

    @Test
    void assertCanCreateConnectorRejectsWhenAtLimit() {
        Tenant tenant = tenant(2);
        when(awsDiscoveryConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "aws")).thenReturn(java.util.Optional.of(new com.prototype.vulnwatch.domain.AwsDiscoveryConfig()));
        when(awsDiscoveryTargetRepository.countByTenant_Id(tenant.getId())).thenReturn(1L);
        when(sccmCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "sccm")).thenReturn(java.util.Optional.empty());
        when(serviceNowCmdbConfigRepository.findByTenant_IdAndSourceSystemIgnoreCase(tenant.getId(), "servicenow")).thenReturn(java.util.Optional.empty());

        QuotaExceededException ex = assertThrows(
                QuotaExceededException.class,
                () -> service.assertCanCreateConnector(tenant, "servicenow"));

        assertEquals("TENANT_CONNECTOR_LIMIT_EXCEEDED", ex.getQuotaCode());
    }

    @Test
    void assertCanCreateConnectorAllowsWhenLimitIsZero() {
        Tenant tenant = tenant(0);
        tenant.setPlanCode("pilot");
        assertDoesNotThrow(() -> service.assertCanCreateConnector(tenant, "servicenow"));
    }

    @Test
    void assertCanCreateServiceAccountRejectsWhenAtLimit() {
        Tenant tenant = tenant(10);
        tenant.setMaxServiceAccountCount(1);
        when(serviceAccountRepository.count()).thenReturn(1L);

        QuotaExceededException ex = assertThrows(
                QuotaExceededException.class,
                () -> service.assertCanCreateServiceAccount(tenant));

        assertEquals("TENANT_SERVICE_ACCOUNT_LIMIT_EXCEEDED", ex.getQuotaCode());
    }

    @Test
    void assertCanRefreshTenantExposureAllowsWhenBelowDailyLimit() {
        Tenant tenant = tenant(10);
        tenant.setMaxDailyExposureRefreshes(3);
        when(auditEventRepository.countByTenant_IdAndActionAndOccurredAtAfter(
                eq(tenant.getId()),
                eq("tenant.org_cves.refresh"),
                any(Instant.class))).thenReturn(2L);

        assertDoesNotThrow(() -> service.assertCanRefreshTenantExposure(tenant));
    }

    @Test
    void assertCanRefreshTenantExposureRejectsWhenAtDailyLimit() {
        Tenant tenant = tenant(10);
        tenant.setMaxDailyExposureRefreshes(2);
        when(auditEventRepository.countByTenant_IdAndActionAndOccurredAtAfter(
                eq(tenant.getId()),
                eq("tenant.org_cves.refresh"),
                any(Instant.class))).thenReturn(2L);

        QuotaExceededException ex = assertThrows(
                QuotaExceededException.class,
                () -> service.assertCanRefreshTenantExposure(tenant));

        assertEquals("TENANT_EXPOSURE_REFRESH_DAILY_LIMIT_EXCEEDED", ex.getQuotaCode());
    }

    @Test
    void assertCanExportRowsRejectsWhenAboveLimit() {
        Tenant tenant = tenant(10);
        tenant.setMaxExportRows(5);

        QuotaExceededException ex = assertThrows(
                QuotaExceededException.class,
                () -> service.assertCanExportRows(tenant, 6));

        assertEquals("TENANT_EXPORT_ROW_LIMIT_EXCEEDED", ex.getQuotaCode());
    }

    @Test
    void assertCanCreateSbomIngestionJobRejectsWhenBurstRateLimitExceeded() {
        Tenant tenant = tenant(10);
        when(ingestionJobRepository.countAcceptedSince(any(Instant.class))).thenReturn(2L, 10L);

        QuotaExceededException ex = assertThrows(
                QuotaExceededException.class,
                () -> service.assertCanCreateSbomIngestionJob(tenant, "remote-endpoint"));

        assertEquals("TENANT_SBOM_RATE_LIMIT_EXCEEDED", ex.getQuotaCode());
        assertEquals(300, ex.getRetryAfterSeconds());
        verify(ingestionJobMetricsService).recordRateLimited("remote-endpoint");
    }

    @Test
    void assertCanCreateSbomIngestionJobRejectsWhenActiveJobBacklogIsFull() {
        Tenant tenant = tenant(10);
        when(ingestionJobRepository.countAcceptedSince(any(Instant.class))).thenReturn(2L, 1L);
        when(ingestionJobRepository.countByStatusIn(any())).thenReturn(1L);

        QuotaExceededException ex = assertThrows(
                QuotaExceededException.class,
                () -> service.assertCanCreateSbomIngestionJob(tenant, "github"));

        assertEquals("TENANT_SBOM_ACTIVE_JOB_LIMIT_EXCEEDED", ex.getQuotaCode());
        assertEquals(60, ex.getRetryAfterSeconds());
        verify(ingestionJobMetricsService).recordAdmissionRejected("github");
    }

    @Test
    void assertCanCreateSbomIngestionJobUsesTenantSpecificAdmissionOverrides() {
        Tenant tenant = tenant(10);
        tenant.setSbomRateLimitWindowSeconds(30);
        tenant.setMaxSbomJobsPerRateLimitWindow(2);
        tenant.setMaxActiveSbomJobs(3);
        when(ingestionJobRepository.countAcceptedSince(any(Instant.class))).thenReturn(1L, 2L);

        QuotaExceededException ex = assertThrows(
                QuotaExceededException.class,
                () -> service.assertCanCreateSbomIngestionJob(tenant, "remote-endpoint"));

        assertEquals("TENANT_SBOM_RATE_LIMIT_EXCEEDED", ex.getQuotaCode());
        assertEquals(30, ex.getRetryAfterSeconds());
    }

    private Tenant tenant(int maxConnectorCount) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setName("Acme");
        tenant.setSlug("acme");
        tenant.setMaxConnectorCount(maxConnectorCount);
        tenant.setMaxServiceAccountCount(25);
        tenant.setMaxDailySbomUploads(100);
        tenant.setMaxDailyExposureRefreshes(25);
        return tenant;
    }
}
