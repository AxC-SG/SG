package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.dto.AllowedTenantResponse;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.Map;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import java.util.List;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AllowedTenantContextService {

    private final TenantMembershipRepository tenantMembershipRepository;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final TenantSupportGrantService tenantSupportGrantService;

    public AllowedTenantContextService(
            TenantMembershipRepository tenantMembershipRepository,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            TenantSupportGrantService tenantSupportGrantService
    ) {
        this.tenantMembershipRepository = tenantMembershipRepository;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.tenantSupportGrantService = tenantSupportGrantService;
    }

    @Transactional(readOnly = true)
    public List<AllowedTenantResponse> listAllowedTenants(RequestActor actor) {
        if (actor == null) {
            return List.of();
        }
        if (actor.hasRole("PLATFORM_OWNER")) {
            Map<String, AllowedTenantResponse> allowedTenants = new LinkedHashMap<>();
            tenantMembershipRepository.findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(actor.userId(), "ACTIVE").stream()
                    .filter(membership -> tenantLifecycleGuardService.isTenantAccessible(membership.getTenant()))
                    .forEach(membership -> {
                        boolean bootstrapPlayground = TenantAccessResolutionService.PLAYGROUND_SLUG
                                .equalsIgnoreCase(membership.getTenant().getSlug())
                                && TenantAccessResolutionService.PLAYGROUND_PROVENANCE
                                .equalsIgnoreCase(membership.getProvenance());
                        allowedTenants.put(membership.getTenant().getId().toString(), new AllowedTenantResponse(
                                    membership.getTenant().getId().toString(),
                                    membership.getTenant().getName(),
                                    membership.getTenant().getSlug(),
                                    TenantRolePolicy.forAuthorization(membership.getRole()),
                                    bootstrapPlayground
                                            ? TenantAccessMode.DIRECT_PLAYGROUND_MEMBERSHIP.name()
                                            : TenantAccessMode.TENANT_MEMBERSHIP.name(),
                                    membership.getId(),
                                    null,
                                    !bootstrapPlayground));
                    });
            tenantSupportGrantService.listActiveGrantsForPlatformOwner(actor.userId()).stream()
                    .filter(grant -> tenantLifecycleGuardService.isTenantAccessible(grant.getTenant()))
                    .forEach(grant -> allowedTenants.putIfAbsent(
                            grant.getTenant().getId().toString(),
                            new AllowedTenantResponse(
                                    grant.getTenant().getId().toString(),
                                    grant.getTenant().getName(),
                                    grant.getTenant().getSlug(),
                                    "PLATFORM_OWNER",
                                    TenantSupportGrantService.ACCESS_MODE_WRITE_ENABLED.equalsIgnoreCase(grant.getAccessMode())
                                            ? TenantAccessMode.SUPPORT_WRITE_ENABLED.name()
                                            : TenantAccessMode.SUPPORT_READ_ONLY.name(),
                                    grant.getId(),
                                    grant.getExpiresAt(),
                                    true)));
            return allowedTenants.values().stream()
                    .sorted(Comparator.comparing(AllowedTenantResponse::name, String.CASE_INSENSITIVE_ORDER))
                    .toList();
        }
        List<AllowedTenantResponse> allowedTenants = tenantMembershipRepository
                .findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(actor.userId(), "ACTIVE").stream()
                .filter(membership -> tenantLifecycleGuardService.isTenantAccessible(membership.getTenant()))
                .map(membership -> new AllowedTenantResponse(
                        membership.getTenant().getId().toString(),
                        membership.getTenant().getName(),
                        membership.getTenant().getSlug(),
                        TenantRolePolicy.forAuthorization(membership.getRole()),
                        TenantAccessMode.TENANT_MEMBERSHIP.name(),
                        membership.getId(),
                        null,
                        true))
                .toList();
        if (allowedTenants.size() > 1) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Multiple active tenant memberships found. Contact support.");
        }
        return allowedTenants;
    }
}
