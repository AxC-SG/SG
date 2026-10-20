package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.TenantQuotaUpdateRequest;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class TenantAdministrationService {

    private final TenantService tenantService;
    private final DemoTenantPurgeService demoTenantPurgeService;
    private final TenantSchemaMigrationService tenantSchemaMigrationService;
    private final IdentityAdministrationService identityAdministrationService;
    private final AuditEventService auditEventService;
    private final boolean synchronousTenantProvisioningEnabled;

    public TenantAdministrationService(
            TenantService tenantService,
            DemoTenantPurgeService demoTenantPurgeService,
            TenantSchemaMigrationService tenantSchemaMigrationService,
            IdentityAdministrationService identityAdministrationService,
            AuditEventService auditEventService,
            @Value("${app.demo.synchronous-tenant-provisioning-enabled:false}") boolean synchronousTenantProvisioningEnabled
    ) {
        this.tenantService = tenantService;
        this.demoTenantPurgeService = demoTenantPurgeService;
        this.tenantSchemaMigrationService = tenantSchemaMigrationService;
        this.identityAdministrationService = identityAdministrationService;
        this.auditEventService = auditEventService;
        this.synchronousTenantProvisioningEnabled = synchronousTenantProvisioningEnabled;
    }

    public List<Tenant> listTenants() {
        return tenantService.listTenants();
    }

    public Tenant getTenant(UUID tenantId) {
        return tenantService.requireTenantUuid(tenantId);
    }

    public Tenant createTenant(String name, String slug, String planCode, String billingRef, boolean addDemoData) {
        return createTenant(name, slug, planCode, billingRef, addDemoData, null, null);
    }

    @Transactional
    public Tenant createTenant(
            String name,
            String slug,
            String planCode,
            String billingRef,
            boolean addDemoData,
            String ownerEmail,
            String ownerPassword
    ) {
        boolean hasOwnerEmail = ownerEmail != null && !ownerEmail.isBlank();
        boolean hasOwnerPassword = ownerPassword != null && !ownerPassword.isBlank();
        if (hasOwnerEmail != hasOwnerPassword) {
            throw new IllegalArgumentException("Owner email and owner password must be provided together");
        }
        if (hasOwnerEmail) {
            identityAdministrationService.assertOwnerCredentialProvisioningAllowed(ownerEmail);
        }
        Tenant tenant = tenantService.createTenant(name, slug, planCode, billingRef, addDemoData);
        if (synchronousTenantProvisioningEnabled) {
            tenantSchemaMigrationService.provisionNewTenant(tenant);
        }
        if (hasOwnerEmail) {
            identityAdministrationService.provisionTenantOwner(
                    tenant.getId(), ownerEmail, ownerPassword, ownerEmail);
            tenant = tenantService.updateDemoOwnerEmail(tenant.getId(), ownerEmail);
        }
        auditEventService.record("tenant.provisioning.requested", "tenant", tenant.getId().toString(), null);
        if (hasOwnerEmail) {
            auditEventService.record("tenant.owner.credential_provisioned", "tenant", tenant.getId().toString(),
                    "{\"credentialProvided\":true}");
        }
        return tenant;
    }

    public Tenant retryProvisioning(UUID tenantId) {
        return tenantService.retryProvisioning(tenantId);
    }

    @Transactional
    public Tenant recoverTenantOwner(UUID tenantId, String ownerEmail, String ownerPassword) {
        Tenant tenant = tenantService.requireTenantUuid(tenantId);
        if (!"ACTIVE".equalsIgnoreCase(tenant.getStatus())) {
            throw new IllegalArgumentException("Tenant owner recovery requires an ACTIVE tenant");
        }
        if (tenant.getDemoExpiresAt() == null && (tenant.getDemoSource() == null || tenant.getDemoSource().isBlank())
                && !DemoLifecycleService.DEMO_PLAN_CODE.equalsIgnoreCase(tenant.getPlanCode())) {
            throw new IllegalArgumentException("Tenant owner recovery is only available for demo tenants");
        }
        if (tenant.getExpiredAt() != null || (tenant.getDemoExpiresAt() != null && !tenant.getDemoExpiresAt().isAfter(Instant.now()))) {
            throw new IllegalArgumentException("Tenant owner recovery is unavailable for an expired demo tenant");
        }
        identityAdministrationService.provisionTenantOwner(tenantId, ownerEmail, ownerPassword, ownerEmail);
        Tenant updated = tenantService.updateDemoOwnerEmail(tenantId, ownerEmail);
        auditEventService.record("tenant.owner.credential_recovered", "tenant", tenantId.toString(),
                "{\"credentialUpdated\":true}");
        return updated;
    }

    public Tenant updateStatus(UUID tenantId, String status) {
        return tenantService.updateStatus(tenantId, status);
    }

    public Tenant extendDemoExpiry(UUID tenantId, Instant expiresAt) {
        return tenantService.extendDemoExpiry(tenantId, expiresAt);
    }

    public Tenant updateQuotas(UUID tenantId, TenantQuotaUpdateRequest request) {
        return tenantService.updateQuotas(tenantId, request);
    }

    public void deleteTenant(UUID tenantId) {
        ManualTenantDeletionPolicy.requirePermitted();
        demoTenantPurgeService.deleteTenant(tenantId, Instant.now());
    }
}
