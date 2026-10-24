package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantSupportGrant;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class TenantAccessResolutionService {

    public static final String PLAYGROUND_SLUG = "default-workspace";
    public static final String PLAYGROUND_PROVENANCE = "PLAYGROUND_BOOTSTRAP";

    private final TenantRepository tenantRepository;
    private final TenantMembershipRepository membershipRepository;
    private final TenantSupportGrantService supportGrantService;
    private final TenantLifecycleGuardService lifecycleGuardService;

    public TenantAccessResolutionService(
            TenantRepository tenantRepository,
            TenantMembershipRepository membershipRepository,
            TenantSupportGrantService supportGrantService,
            TenantLifecycleGuardService lifecycleGuardService
    ) {
        this.tenantRepository = tenantRepository;
        this.membershipRepository = membershipRepository;
        this.supportGrantService = supportGrantService;
        this.lifecycleGuardService = lifecycleGuardService;
    }

    @Transactional(readOnly = true)
    public TenantAccessResolution resolve(String subject, UUID tenantId) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new ResponseStatusException(
                        HttpStatus.FORBIDDEN,
                        "No active tenant-authorized access exists for this workspace"));
        lifecycleGuardService.assertTenantAccessible(tenant);

        TenantMembership membership = membershipRepository
                .findFirstByUserExternalSubjectAndTenantIdAndStatus(subject, tenantId, "ACTIVE")
                .orElse(null);
        if (membership != null && !PLAYGROUND_PROVENANCE.equalsIgnoreCase(membership.getProvenance())) {
            boolean playground = PLAYGROUND_SLUG.equalsIgnoreCase(tenant.getSlug())
                    && PLAYGROUND_PROVENANCE.equalsIgnoreCase(membership.getProvenance());
            return new TenantAccessResolution(
                    tenant,
                    playground ? TenantAccessMode.DIRECT_PLAYGROUND_MEMBERSHIP : TenantAccessMode.TENANT_MEMBERSHIP,
                    membership.getId(),
                    TenantRolePolicy.forAuthorization(membership.getRole()),
                    null);
        }

        TenantSupportGrant grant = supportGrantService.findActiveGrant(subject, tenantId).orElse(null);
        if (grant != null) {
            TenantAccessMode mode = TenantSupportGrantService.ACCESS_MODE_WRITE_ENABLED.equalsIgnoreCase(grant.getAccessMode())
                    ? TenantAccessMode.SUPPORT_WRITE_ENABLED
                    : TenantAccessMode.SUPPORT_READ_ONLY;
            return new TenantAccessResolution(tenant, mode, grant.getId(), "PLATFORM_OWNER", grant.getExpiresAt());
        }
        throw new ResponseStatusException(HttpStatus.FORBIDDEN, "No active tenant-authorized access exists for this workspace");
    }

    @Transactional(readOnly = true)
    public TenantAccessResolution revalidate(
            String subject,
            UUID tenantId,
            TenantAccessMode claimedMode,
            UUID claimedReference
    ) {
        if (claimedMode == null || claimedReference == null) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant access mode and reference are required");
        }
        TenantAccessResolution current = resolve(subject, tenantId);
        if (current.mode() != claimedMode || !current.referenceId().equals(claimedReference)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant authorization changed; sign in again");
        }
        return current;
    }

    @Transactional(readOnly = true)
    public List<TenantAccessResolution> listAuthorized(String subject) {
        java.util.LinkedHashMap<UUID, TenantAccessResolution> results = new java.util.LinkedHashMap<>();
        membershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(subject, "ACTIVE").stream()
                .filter(membership -> !PLAYGROUND_PROVENANCE.equalsIgnoreCase(membership.getProvenance()))
                .filter(membership -> lifecycleGuardService.isTenantAccessible(membership.getTenant()))
                .forEach(membership -> {
                    Tenant tenant = membership.getTenant();
                    boolean playground = PLAYGROUND_SLUG.equalsIgnoreCase(tenant.getSlug())
                            && PLAYGROUND_PROVENANCE.equalsIgnoreCase(membership.getProvenance());
                    results.put(tenant.getId(), new TenantAccessResolution(
                            tenant,
                            playground ? TenantAccessMode.DIRECT_PLAYGROUND_MEMBERSHIP : TenantAccessMode.TENANT_MEMBERSHIP,
                            membership.getId(),
                            TenantRolePolicy.forAuthorization(membership.getRole()),
                            null));
                });
        supportGrantService.listActiveGrantsForPlatformOwner(subject).stream()
                .filter(grant -> lifecycleGuardService.isTenantAccessible(grant.getTenant()))
                .forEach(grant -> results.putIfAbsent(grant.getTenant().getId(), new TenantAccessResolution(
                        grant.getTenant(),
                        TenantSupportGrantService.ACCESS_MODE_WRITE_ENABLED.equalsIgnoreCase(grant.getAccessMode())
                                ? TenantAccessMode.SUPPORT_WRITE_ENABLED : TenantAccessMode.SUPPORT_READ_ONLY,
                        grant.getId(),
                        "PLATFORM_OWNER",
                        grant.getExpiresAt())));
        return results.values().stream()
                .sorted(java.util.Comparator.comparing(result -> result.tenant().getName(), String.CASE_INSENSITIVE_ORDER))
                .toList();
    }

}
