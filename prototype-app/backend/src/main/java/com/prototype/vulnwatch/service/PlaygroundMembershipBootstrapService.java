package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.config.PlaygroundMembershipProperties;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Locale;
import java.util.Set;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Service;

@Service
public class PlaygroundMembershipBootstrapService {
    private static final Set<String> ALLOWED_ROLES = Set.of(
            "TENANT_ADMIN", "INVENTORY_ADMIN", "SECURITY_ANALYST", "READ_ONLY_AUDITOR");

    private final PlaygroundMembershipProperties properties;
    private final TenantRepository tenantRepository;
    private final AppUserRepository userRepository;
    private final TenantMembershipRepository membershipRepository;
    private final AppUserGlobalRoleService globalRoleService;
    private final AuditEventService auditEventService;
    private final TenantWorkRunner tenantWorkRunner;

    public PlaygroundMembershipBootstrapService(
            PlaygroundMembershipProperties properties,
            TenantRepository tenantRepository,
            AppUserRepository userRepository,
            TenantMembershipRepository membershipRepository,
            AppUserGlobalRoleService globalRoleService,
            AuditEventService auditEventService,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.properties = properties;
        this.tenantRepository = tenantRepository;
        this.userRepository = userRepository;
        this.membershipRepository = membershipRepository;
        this.globalRoleService = globalRoleService;
        this.auditEventService = auditEventService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    @EventListener(ApplicationReadyEvent.class)
    @Order(20)
    public void reconcile() {
        TenantContext.runAsPlatform(this::reconcileInPlatformScope);
    }

    private void reconcileInPlatformScope() {
        for (TenantMembership membership : membershipRepository
                .findByProvenance(TenantAccessResolutionService.PLAYGROUND_PROVENANCE)) {
            if ("ACTIVE".equalsIgnoreCase(membership.getStatus())) {
                tenantWorkRunner.runScoped(membership.getTenant(), () -> {
                    membership.setStatus("SUSPENDED");
                    membership.setUpdatedAt(Instant.now());
                    audit("playground.membership.suspended", membershipRepository.save(membership));
                });
            }
        }
    }

    private void audit(String action, TenantMembership membership) {
        auditEventService.recordExplicitActor(
                membership.getTenant().getId(),
                "system:playground-bootstrap",
                "PLATFORM_OWNER",
                action,
                "tenant_membership",
                membership.getId().toString(),
                "{\"subject\":\"" + membership.getUser().getExternalSubject() + "\",\"role\":\"" + membership.getRole() + "\"}",
                "SUCCESS");
    }

    private String normalizeRole(String value) {
        return value == null ? "TENANT_ADMIN" : value.trim().toUpperCase(Locale.ROOT)
                .replace('-', '_').replace(' ', '_').replaceFirst("^ROLE_", "");
    }

    private boolean hasText(String value) { return value != null && !value.isBlank(); }
}
