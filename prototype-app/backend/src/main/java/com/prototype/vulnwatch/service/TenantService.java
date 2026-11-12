package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.TenantQuotaUpdateRequest;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.NOT_FOUND;

@Service
public class TenantService {

    public static final String DEFAULT_TENANT_NAME = "SG Internal";
    public static final String DEFAULT_TENANT_SCHEMA = "tenant_default";
    public static final String DEFAULT_PLAN_CODE = "ENTERPRISE";

    private final TenantRepository tenantRepository;
    private final TenantSchemaService tenantSchemaService;
    private final TransactionTemplate registryReadTransactions;

    public TenantService(
            TenantRepository tenantRepository,
            TenantSchemaService tenantSchemaService,
            PlatformTransactionManager transactionManager
    ) {
        this.tenantRepository = tenantRepository;
        this.tenantSchemaService = tenantSchemaService;
        this.registryReadTransactions = new TransactionTemplate(transactionManager);
        this.registryReadTransactions.setReadOnly(true);
    }

    @Transactional
    public Tenant getDefaultTenant() {
        return tenantRepository.findBySchemaName(DEFAULT_TENANT_SCHEMA)
                .filter(Tenant::isInternal)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Reserved SG Internal tenant not found"));
    }

    @Transactional(readOnly = true)
    public Tenant resolveTenant(Long legacyTenantId) {
        if (legacyTenantId == null) {
            throw new ResponseStatusException(NOT_FOUND, "Tenant is required");
        }
        UUID legacyTenantUuid = new UUID(0L, legacyTenantId);
        return tenantRepository.findById(legacyTenantUuid)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Tenant not found"));
    }

    @Transactional(readOnly = true)
    public Tenant resolveTenantUuid(UUID tenantId) {
        if (tenantId == null) {
            throw new ResponseStatusException(NOT_FOUND, "Tenant is required");
        }
        return tenantRepository.findById(tenantId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Tenant not found"));
    }

    @Transactional(readOnly = true)
    public Tenant requireTenantUuid(UUID tenantId) {
        return resolveTenantUuid(tenantId);
    }

    @Transactional(readOnly = true)
    public Tenant resolveActiveTenantForBackgroundWork(UUID tenantId) {
        Tenant tenant = resolveTenantUuid(tenantId);
        String schema = tenant.getSchemaName();
        if (!isActiveTenantForBackgroundWork(tenant)
                || schema == null || schema.isBlank()
                || (DEFAULT_TENANT_SCHEMA.equalsIgnoreCase(schema.trim()) && !tenant.isInternal())) {
            throw new ResponseStatusException(org.springframework.http.HttpStatus.FORBIDDEN,
                    "Tenant is unavailable for background work");
        }
        return tenant;
    }

    @Transactional(readOnly = true)
    public List<Tenant> listTenants() {
        return tenantRepository.findAllByOrderByCreatedAtAsc();
    }

    /**
     * Reads the platform tenant registry for background fan-out.
     *
     * <p>Deliberately not {@code @Transactional}: the tenant-aware datasource configures a
     * connection when the transaction acquires it, so platform scope must be established
     * before the read-only transaction opens. A caller that already holds a transaction must
     * have opened it in platform scope; switching scope now cannot reconfigure its connection.
     */
    public List<Tenant> listActiveTenants() {
        List<Tenant> registry;
        if (TransactionSynchronizationManager.isActualTransactionActive()) {
            if (!TenantContext.isPlatformContext()) {
                throw new IllegalStateException(
                        "The tenant registry must be read in platform scope; open the caller's transaction inside TenantContext.runAsPlatform");
            }
            registry = tenantRepository.findAllByOrderByCreatedAtAsc();
        } else {
            registry = TenantContext.runAsPlatform(() ->
                    registryReadTransactions.execute(status -> tenantRepository.findAllByOrderByCreatedAtAsc()));
        }
        return registry.stream()
                .filter(this::isActiveTenantForBackgroundWork)
                .toList();
    }

    public Tenant createTenant(String name, String slug, String planCode, String billingRef) {
        return createTenant(name, slug, planCode, billingRef, false);
    }

    public Tenant createTenant(String name, String slug, String planCode, String billingRef, boolean addDemoData) {
        Tenant tenant = new Tenant();
        tenant.setName(requireText(name, "name"));
        tenant.setSlug(normalizeSlug(slug == null || slug.isBlank() ? name : slug));
        tenant.setSchemaName(tenantSchemaService.deriveSchemaName(tenant.getSlug()));
        if ("SG Internal".equalsIgnoreCase(tenant.getName())
                || java.util.Set.of("default-workspace", "sg-internal").contains(tenant.getSlug())
                || DEFAULT_TENANT_SCHEMA.equals(tenant.getSchemaName())) {
            throw new IllegalArgumentException("Reserved internal tenant identity");
        }
        tenant.setClassification("CUSTOMER");
        tenant.setPlanCode(normalizePlanCode(planCode));
        tenant.setBillingRef(billingRef == null || billingRef.isBlank() ? null : billingRef.trim());
        tenant.setStatus("PROVISIONING");
        if (addDemoData) {
            tenant.setDemoSource(DemoDatasetProvisioningService.REQUESTED_MARKER);
            tenant.setDemoExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
            tenant.setDemoCreatedBy("platform-console");
        }
        return tenantRepository.save(tenant);
    }

    @Transactional
    public Tenant retryProvisioning(UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        if (!"PROVISIONING_FAILED".equalsIgnoreCase(tenant.getStatus())) {
            throw new IllegalArgumentException("Only PROVISIONING_FAILED tenants can be retried");
        }
        tenant.setStatus("PROVISIONING");
        tenant.setUpdatedAt(Instant.now());
        return tenantRepository.save(tenant);
    }

    @Transactional
    public Tenant updateStatus(UUID tenantId, String status) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        String normalizedStatus = requireText(status, "status").toUpperCase();
        if (tenant.isInternal() && java.util.Set.of("DELETED", "EXPIRED", "PURGING", "PURGED").contains(normalizedStatus)) {
            throw new IllegalArgumentException("SG Internal cannot expire or be deleted");
        }
        if ("ACTIVE".equals(normalizedStatus)
                && tenant.getDemoExpiresAt() != null
                && !tenant.getDemoExpiresAt().isAfter(Instant.now())) {
            throw new IllegalArgumentException("Extend the demo expiration before restoring tenant access");
        }
        tenant.setStatus(normalizedStatus);
        tenant.setUpdatedAt(Instant.now());
        tenant.setSuspendedAt("SUSPENDED".equals(normalizedStatus) ? Instant.now() : null);
        return tenantRepository.save(tenant);
    }

    @Transactional
    public Tenant extendDemoExpiry(UUID tenantId, Instant expiresAt) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        Instant now = Instant.now();
        if (expiresAt == null || !expiresAt.isAfter(now)) {
            throw new IllegalArgumentException("expiresAt must be in the future");
        }
        if (!isDemoTenant(tenant)) {
            throw new IllegalArgumentException("Only demo tenants can be extended");
        }
        if (tenant.getPurgeStartedAt() != null
                || tenant.getPurgedAt() != null
                || "PURGING".equalsIgnoreCase(tenant.getStatus())
                || "DELETED".equalsIgnoreCase(tenant.getStatus())) {
            throw new IllegalStateException("Tenant deletion has started and cannot be reversed");
        }
        if (!tenantSchemaService.schemaExists(tenant.getSchemaName())) {
            throw new IllegalStateException("Tenant schema is not provisioned: " + tenant.getSchemaName());
        }

        tenant.setDemoExpiresAt(expiresAt);
        tenant.setExpiredAt(null);
        if ("EXPIRED".equalsIgnoreCase(tenant.getStatus())) {
            tenant.setStatus("ACTIVE");
            tenant.setSuspendedAt(null);
        }
        tenant.setUpdatedAt(now);
        return tenantRepository.save(tenant);
    }

    @Transactional
    public Tenant updateDemoOwnerEmail(UUID tenantId, String ownerEmail) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        tenant.setDemoOwnerEmail(ownerEmail == null || ownerEmail.isBlank() ? null : ownerEmail.trim().toLowerCase(Locale.ROOT));
        tenant.setUpdatedAt(Instant.now());
        return tenantRepository.save(tenant);
    }

    @Transactional
    public Tenant updateQuotas(UUID tenantId, TenantQuotaUpdateRequest request) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        tenant.setMaxConnectorCount(nonNegative(request.maxConnectorCount(), "maxConnectorCount"));
        tenant.setMaxServiceAccountCount(nonNegative(request.maxServiceAccountCount(), "maxServiceAccountCount"));
        tenant.setMaxDailySbomUploads(nonNegative(request.maxDailySbomUploads(), "maxDailySbomUploads"));
        tenant.setMaxExportRows(nonNegative(request.maxExportRows(), "maxExportRows"));
        tenant.setMaxDailyExposureRefreshes(nonNegative(request.maxDailyExposureRefreshes(), "maxDailyExposureRefreshes"));
        tenant.setSbomRateLimitWindowSeconds(nullableNonNegative(request.sbomRateLimitWindowSeconds(), "sbomRateLimitWindowSeconds"));
        tenant.setMaxSbomJobsPerRateLimitWindow(nullableNonNegative(request.maxSbomJobsPerRateLimitWindow(), "maxSbomJobsPerRateLimitWindow"));
        tenant.setMaxActiveSbomJobs(nullableNonNegative(request.maxActiveSbomJobs(), "maxActiveSbomJobs"));
        tenant.setUpdatedAt(Instant.now());
        return tenantRepository.save(tenant);
    }
    private String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(field + " is required");
        }
        return value.trim();
    }

    private String normalizeSlug(String value) {
        String slug = requireText(value, "slug")
                .toLowerCase()
                .replaceAll("[^a-z0-9]+", "-")
                .replaceAll("(^-|-$)", "");
        if (slug.isBlank()) {
            throw new IllegalArgumentException("slug must contain at least one letter or digit");
        }
        return slug;
    }

    private Integer nonNegative(Integer value, String field) {
        if (value == null) {
            throw new IllegalArgumentException(field + " is required");
        }
        if (value < 0) {
            throw new IllegalArgumentException(field + " must be >= 0");
        }
        return value;
    }

    private Integer nullableNonNegative(Integer value, String field) {
        if (value == null) {
            return null;
        }
        if (value < 0) {
            throw new IllegalArgumentException(field + " must be >= 0");
        }
        return value;
    }

    private String normalizePlanCode(String planCode) {
        if (planCode == null || planCode.isBlank()) {
            return DEFAULT_PLAN_CODE;
        }
        return planCode.trim().toUpperCase();
    }

    private boolean isDemoTenant(Tenant tenant) {
        return tenant != null && !tenant.isInternal()
                && (tenant.getDemoExpiresAt() != null
                || (tenant.getDemoSource() != null && !tenant.getDemoSource().isBlank())
                || DemoLifecycleService.DEMO_PLAN_CODE.equalsIgnoreCase(tenant.getPlanCode()));
    }

    private boolean isActiveTenantForBackgroundWork(Tenant tenant) {
        if (tenant == null) {
            return false;
        }
        String status = tenant.getStatus() == null ? "" : tenant.getStatus().trim().toUpperCase(Locale.ROOT);
        return "ACTIVE".equals(status)
                && tenant.getDeletedAt() == null
                && tenant.getExpiredAt() == null
                && tenant.getPurgeStartedAt() == null
                && tenant.getPurgedAt() == null;
    }
}
