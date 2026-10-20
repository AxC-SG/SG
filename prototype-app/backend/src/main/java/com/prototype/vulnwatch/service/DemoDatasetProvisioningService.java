package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DemoDatasetProvisioningService {

    private static final Logger LOG = LoggerFactory.getLogger(DemoDatasetProvisioningService.class);
    public static final String REQUESTED_MARKER = "CUSTOMER_DATASET_REQUESTED";
    public static final String SEEDING_MARKER = "CUSTOMER_DATASET_SEEDING";
    public static final String SEEDED_V1_MARKER = "CUSTOMER_DATASET_V1_SEEDED";
    public static final String SEEDED_MARKER = "CUSTOMER_DATASET_V2_SEEDED";

    private final TenantRepository tenantRepository;
    private final JdbcTemplate jdbcTemplate;
    private final CustomerDemoDatasetService datasetService;

    public DemoDatasetProvisioningService(
            TenantRepository tenantRepository,
            JdbcTemplate jdbcTemplate,
            CustomerDemoDatasetService datasetService
    ) {
        this.tenantRepository = tenantRepository;
        this.jdbcTemplate = jdbcTemplate;
        this.datasetService = datasetService;
    }

    private TenantSchemaExecutionService tenantExecution;
    private org.springframework.transaction.support.TransactionTemplate seedTransaction;
    @org.springframework.beans.factory.annotation.Autowired
    void configureSeedTransactions(TenantSchemaExecutionService tenantExecution,
                                   org.springframework.transaction.PlatformTransactionManager manager) {
        this.tenantExecution = tenantExecution;
        this.seedTransaction = new org.springframework.transaction.support.TransactionTemplate(manager);
    }

    @Transactional
    public Tenant request(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        tenant.setDemoSource(REQUESTED_MARKER);
        tenant.setUpdatedAt(Instant.now());
        return tenantRepository.save(tenant);
    }

    public CustomerDemoDatasetService.DemoDatasetSummary requestAndSeed(UUID tenantId) {
        request(tenantId);
        return seedIfReady(tenantId);
    }

    public boolean needsRepair(Tenant tenant) {
        return datasetService.needsRepair(tenant);
    }

    private com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy backgroundPolicy=com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy.allowAll();
    @org.springframework.beans.factory.annotation.Autowired
    void configureBackgroundPolicy(com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy policy) { backgroundPolicy=policy; }

    @Scheduled(initialDelayString = "${app.demo-data.initial-delay-ms:15000}",
            fixedDelayString = "${app.demo-data.poll-delay-ms:30000}")
    public void seedRequestedTenants() {
        if (!backgroundPolicy.allowsBackgroundTask("seedRequestedTenants")) return;
        tenantRepository.findAllByOrderByCreatedAtAsc().stream()
                .filter(DemoDatasetProvisioningService::isRequested)
                .filter(tenant -> "ACTIVE".equalsIgnoreCase(tenant.getStatus()))
                .filter(tenant -> !CustomerDemoDatasetService.DATASET_VERSION.equals(version(tenant)))
                .forEach(tenant -> {
                    try {
                        seedIfReady(tenant.getId());
                    } catch (RuntimeException ex) {
                        LOG.error("Demo dataset seed failed for tenant {}", tenant.getId(), ex);
                    }
                });
    }

    public CustomerDemoDatasetService.DemoDatasetSummary seedIfReady(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        if (!"ACTIVE".equalsIgnoreCase(tenant.getStatus())) {
            throw new IllegalStateException("Tenant must be ACTIVE before demo data can be seeded");
        }
        try {
            return tenantExecution.run(tenant, () -> seedTransaction.execute(status -> {
                // NOWAIT preserves a healthy seed; process death rolls back data and releases the lock.
                String currentStatus = jdbcTemplate.queryForObject(
                        "select status from platform.tenants where id=? for update nowait", String.class, tenantId);
                if (!"ACTIVE".equalsIgnoreCase(currentStatus)) {
                    throw new IllegalStateException("Tenant must remain ACTIVE while demo data is seeded");
                }
                jdbcTemplate.update("update platform.tenants set demo_source=?,updated_at=clock_timestamp() where id=?",
                        SEEDING_MARKER, tenantId);
                CustomerDemoDatasetService.DemoDatasetSummary summary = datasetService.seed(tenant);
                jdbcTemplate.update("update platform.tenants set demo_source=?,updated_at=clock_timestamp() where id=?",
                        SEEDED_MARKER, tenantId);
                return summary;
            }));
        } catch (org.springframework.dao.DataAccessException failure) {
            if (failure.getMostSpecificCause() instanceof java.sql.SQLException sql
                    && "55P03".equals(sql.getSQLState())) {
                throw new IllegalStateException("Demo data seed is already running", failure);
            }
            throw failure;
        }
    }

    public static boolean isRequested(Tenant tenant) {
        String source = tenant.getDemoSource();
        return REQUESTED_MARKER.equals(source) || SEEDING_MARKER.equals(source)
                || SEEDED_V1_MARKER.equals(source) || SEEDED_MARKER.equals(source);
    }

    public static String status(Tenant tenant) {
        return switch (tenant.getDemoSource() == null ? "" : tenant.getDemoSource()) {
            case REQUESTED_MARKER -> "REQUESTED";
            case SEEDING_MARKER -> "SEEDING";
            case SEEDED_V1_MARKER -> "SEEDED";
            case SEEDED_MARKER -> "SEEDED";
            default -> "NOT_REQUESTED";
        };
    }

    public static String version(Tenant tenant) {
        if (SEEDED_MARKER.equals(tenant.getDemoSource())) {
            return CustomerDemoDatasetService.DATASET_VERSION;
        }
        return SEEDED_V1_MARKER.equals(tenant.getDemoSource()) ? "customer-demo-v1" : null;
    }
}
