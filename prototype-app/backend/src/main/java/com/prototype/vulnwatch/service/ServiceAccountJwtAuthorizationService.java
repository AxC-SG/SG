package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.repo.ServiceAccountRepository;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

/** Registry metadata constrains a verified JWT; a key ID is never a credential. */
@Service
public class ServiceAccountJwtAuthorizationService {
    private final ServiceAccountRepository accounts;
    private final TenantService tenants;
    private final TenantLifecycleGuardService lifecycle;
    private final TenantWorkRunner work;

    public ServiceAccountJwtAuthorizationService(ServiceAccountRepository accounts, TenantService tenants,
            TenantLifecycleGuardService lifecycle, TenantWorkRunner work) {
        this.accounts = accounts;
        this.tenants = tenants;
        this.lifecycle = lifecycle;
        this.work = work;
    }

    public AuthenticatedTenantActor authenticate(String verifiedSubject, UUID tenantId) {
        var tenant = tenants.resolveTenantUuid(tenantId);
        lifecycle.assertTenantAccessible(tenant);
        return work.runScoped(tenant, () -> {
            var account = accounts.findByKeyId(verifiedSubject).orElseThrow(this::denied);
            if (!"ACTIVE".equals(account.getStatus()) || !"SERVICE_ACCOUNT".equals(account.getRole())
                    || account.getTenant() == null || !tenantId.equals(account.getTenant().getId())) {
                throw denied();
            }
            account.setLastUsedAt(java.time.Instant.now());
            accounts.save(account);
            return new AuthenticatedTenantActor(verifiedSubject, account.getId(), null, account.getName(),
                    tenantId, tenant.getName(), tenant.getSchemaName(), Set.of("SERVICE_ACCOUNT"),
                    TenantAccessMode.SERVICE_ACCOUNT, account.getId(), null);
        });
    }

    private ResponseStatusException denied() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, "Active same-tenant service-account registration is required");
    }
}
