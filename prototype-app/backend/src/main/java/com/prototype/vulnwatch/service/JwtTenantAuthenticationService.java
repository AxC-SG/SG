package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.time.Instant;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

@Service
public class JwtTenantAuthenticationService {

    private final AppUserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final TenantMembershipRepository membershipRepository;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final AppUserGlobalRoleService appUserGlobalRoleService;
    private final TenantSupportGrantService tenantSupportGrantService;
    private final TenantAccessResolutionService accessResolutionService;
    private final String subjectClaim;
    private final String tenantIdClaim;
    private final String activeTenantIdClaim;
    private final String tenantSlugClaim;
    private final String emailClaim;
    private final String nameClaim;
    private final String rolesClaim;
    private final String keycloakClientId;
    private ServiceAccountJwtAuthorizationService machineAuthorization;
    private org.springframework.transaction.support.TransactionTemplate authenticationTransactions;

    @org.springframework.beans.factory.annotation.Autowired
    public void configureAuthorization(ServiceAccountJwtAuthorizationService machineAuthorization,
            org.springframework.transaction.PlatformTransactionManager manager) {
        this.machineAuthorization = machineAuthorization;
        this.authenticationTransactions = new org.springframework.transaction.support.TransactionTemplate(manager);
    }

    public JwtTenantAuthenticationService(
            AppUserRepository userRepository,
            TenantRepository tenantRepository,
            TenantMembershipRepository membershipRepository,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            AppUserGlobalRoleService appUserGlobalRoleService,
            TenantSupportGrantService tenantSupportGrantService,
            @Value("${app.security.jwt.subject-claim:sub}") String subjectClaim,
            @Value("${app.security.jwt.tenant-id-claim:tenant_id}") String tenantIdClaim,
            @Value("${app.security.jwt.active-tenant-id-claim:active_tenant_id}") String activeTenantIdClaim,
            @Value("${app.security.jwt.tenant-slug-claim:tenant_slug}") String tenantSlugClaim,
            @Value("${app.security.jwt.email-claim:email}") String emailClaim,
            @Value("${app.security.jwt.name-claim:name}") String nameClaim,
            @Value("${app.security.jwt.roles-claim:roles}") String rolesClaim,
            @Value("${app.security.jwt.keycloak-client-id:}") String keycloakClientId
    ) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.membershipRepository = membershipRepository;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.appUserGlobalRoleService = appUserGlobalRoleService;
        this.tenantSupportGrantService = tenantSupportGrantService;
        this.accessResolutionService = new TenantAccessResolutionService(
                tenantRepository,
                membershipRepository,
                tenantSupportGrantService,
                tenantLifecycleGuardService);
        this.subjectClaim = subjectClaim;
        this.tenantIdClaim = tenantIdClaim;
        this.activeTenantIdClaim = activeTenantIdClaim;
        this.tenantSlugClaim = tenantSlugClaim;
        this.emailClaim = emailClaim;
        this.nameClaim = nameClaim;
        this.rolesClaim = rolesClaim;
        this.keycloakClientId = keycloakClientId;
    }

    public AuthenticatedTenantActor authenticate(Jwt jwt) {
        return authenticate(jwt, null);
    }

    public AuthenticatedTenantActor authenticate(Jwt jwt, String requestUri) {
        Set<String> claimedRoles = extractJwtRoles(jwt);
        if (claimedRoles.contains("SERVICE_ACCOUNT")) {
            if (!claimedRoles.equals(Set.of("SERVICE_ACCOUNT")) || machineAuthorization == null) {
                throw new ResponseStatusException(FORBIDDEN, "Service-account token authority is invalid");
            }
            String tenantId = claimAsString(jwt, activeTenantIdClaim);
            if (!hasText(tenantId)) tenantId = claimAsString(jwt, tenantIdClaim);
            if (!hasText(tenantId)) throw new ResponseStatusException(FORBIDDEN, "Service-account token requires an explicit tenant");
            return machineAuthorization.authenticate(resolveSubject(jwt), parseUuid(tenantId));
        }
        return authenticationTransactions == null ? authenticateHuman(jwt, requestUri)
                : authenticationTransactions.execute(status -> authenticateHuman(jwt, requestUri));
    }

    private AuthenticatedTenantActor authenticateHuman(Jwt jwt, String requestUri) {
        String subject = resolveSubject(jwt);
        AppUser user = userRepository.findByExternalSubjectForUpdate(subject)
                .orElseGet(() -> createUser(subject));
        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            throw new ResponseStatusException(UNAUTHORIZED, "User account is inactive");
        }
        user.setEmail(claimAsString(jwt, emailClaim));
        user.setDisplayName(claimAsString(jwt, nameClaim));
        user.setLastSeenAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        Set<String> jwtRoles = extractJwtRoles(jwt);
        Set<String> roles = new LinkedHashSet<>();
        appUserGlobalRoleService.rolesForUser(user.getId()).forEach(role ->
                roles.add(TenantRolePolicy.canonicalRole(role)));
        if (jwtRoles.contains("PLATFORM_OWNER") && !roles.contains("PLATFORM_OWNER")) {
            throw new ResponseStatusException(FORBIDDEN, "Platform authorization changed; sign in again");
        }
        TenantAccessResolution access = resolveTenantAccess(jwt, subject, roles, requestUri);
        Tenant tenant = access == null ? null : access.tenant();

        if (access != null && !access.mode().isSupport()) {
            roles.add(TenantRolePolicy.forAuthorization(access.role()));
        }

        if (roles.isEmpty()) {
            roles.add("SECURITY_ANALYST");
        }

        return new AuthenticatedTenantActor(
                subject,
                user.getId(),
                user.getEmail(),
                user.getDisplayName(),
                tenant == null ? null : tenant.getId(),
                tenant == null ? null : tenant.getName(),
                tenant == null ? null : tenant.getSchemaName(),
                Set.copyOf(roles),
                access == null ? null : access.mode(),
                access == null ? null : access.referenceId(),
                access == null ? null : access.expiresAt());
    }

    private TenantAccessResolution resolveTenantAccess(Jwt jwt, String subject, Set<String> roles, String requestUri) {
        String activeTenantId = claimAsString(jwt, activeTenantIdClaim);
        if (activeTenantId != null) {
            UUID tenantId = parseUuid(activeTenantId);
            return requireSelectedTenantAccess(jwt, tenantId, subject, roles);
        }

        String tenantId = claimAsString(jwt, tenantIdClaim);
        if (tenantId != null) {
            return requireSelectedTenantAccess(jwt, parseUuid(tenantId), subject, roles);
        }

        String tenantSlug = claimAsString(jwt, tenantSlugClaim);
        if (tenantSlug != null) {
            Tenant tenant = tenantRepository.findBySlugIgnoreCase(tenantSlug)
                    .orElseThrow(() -> new ResponseStatusException(FORBIDDEN, "JWT tenant_slug is not registered"));
            return requireSelectedTenantAccess(jwt, tenant.getId(), subject, roles);
        }

        if (roles.contains("PLATFORM_OWNER")) {
            return null;
        }

        List<TenantMembership> memberships = membershipRepository
                .findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(subject, "ACTIVE");
        if (memberships.size() == 1) {
            return accessResolutionService.resolve(subject, memberships.get(0).getTenant().getId());
        }
        if (memberships.size() > 1) {
            throw new ResponseStatusException(FORBIDDEN, "JWT user has multiple active tenant memberships");
        }
        throw new ResponseStatusException(FORBIDDEN, "JWT user does not have an active tenant membership");
    }

    private TenantAccessResolution requireSelectedTenantAccess(
            Jwt jwt,
            UUID tenantId,
            String subject,
            Set<String> roles
    ) {
        String modeClaim = claimAsString(jwt, "tenant_access_mode");
        String referenceClaim = claimAsString(jwt, "tenant_access_ref");
        if (roles.contains("PLATFORM_OWNER") && (!hasText(modeClaim) || !hasText(referenceClaim))) {
            throw new ResponseStatusException(FORBIDDEN, "Platform-owner tenant tokens require explicit authorized access");
        }
        TenantAccessResolution access = hasText(modeClaim) && hasText(referenceClaim)
                ? accessResolutionService.revalidate(subject, tenantId, parseAccessMode(modeClaim), parseUuid(referenceClaim))
                : accessResolutionService.resolve(subject, tenantId);
        if (!access.mode().isSupport()) {
            roles.add(access.role());
        }
        return access;
    }

    private TenantAccessMode parseAccessMode(String value) {
        try {
            return TenantAccessMode.valueOf(value.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(UNAUTHORIZED, "JWT tenant_access_mode is invalid");
        }
    }

    private AppUser createUser(String subject) {
        AppUser user = new AppUser();
        user.setExternalSubject(subject);
        return user;
    }

    private String resolveSubject(Jwt jwt) {
        String configuredSubject = claimAsString(jwt, subjectClaim);
        if (hasText(configuredSubject)) {
            return configuredSubject;
        }
        return requireText(jwt.getSubject(), "JWT subject is required");
    }

    private Set<String> extractJwtRoles(Jwt jwt) {
        LinkedHashSet<String> roles = new LinkedHashSet<>(normalizeRoles(jwt.getClaim(rolesClaim)));
        if (!"roles".equals(rolesClaim)) {
            roles.addAll(normalizeRoles(jwt.getClaim("roles")));
        }
        // Some identity providers inject roles under a namespaced URI claim (e.g. https://example.com/roles).
        // Fall back to scanning all claims whose name ends with "/roles" when the configured claim yields nothing.
        if (roles.isEmpty()) {
            roles.addAll(extractNamespacedRoles(jwt));
        }
        roles.addAll(extractKeycloakRealmRoles(jwt));
        roles.addAll(extractKeycloakClientRoles(jwt));
        return roles;
    }

    private Set<String> extractNamespacedRoles(Jwt jwt) {
        Set<String> roles = new LinkedHashSet<>();
        jwt.getClaims().forEach((claimName, value) -> {
            if (claimName.endsWith("/roles")) {
                roles.addAll(normalizeRoles(value));
            }
        });
        return roles;
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractKeycloakRealmRoles(Jwt jwt) {
        Object claim = jwt.getClaim("realm_access");
        if (!(claim instanceof Map<?, ?> access)) {
            return Set.of();
        }
        Object roles = access.get("roles");
        return normalizeRoles(roles);
    }

    @SuppressWarnings("unchecked")
    private Set<String> extractKeycloakClientRoles(Jwt jwt) {
        if (!hasText(keycloakClientId)) {
            return Set.of();
        }
        Object claim = jwt.getClaim("resource_access");
        if (!(claim instanceof Map<?, ?> access)) {
            return Set.of();
        }
        Object clientEntry = access.get(keycloakClientId);
        if (!(clientEntry instanceof Map<?, ?> clientAccess)) {
            return Set.of();
        }
        Object roles = clientAccess.get("roles");
        return normalizeRoles(roles);
    }

    private UUID parseUuid(String value) {
        try {
            return UUID.fromString(value.trim());
        } catch (IllegalArgumentException ex) {
            throw new ResponseStatusException(UNAUTHORIZED, "JWT tenant_id is not a UUID");
        }
    }

    private Set<String> normalizeRoles(Object claim) {
        Set<String> roles = new LinkedHashSet<>();
        if (claim instanceof String value) {
            for (String part : value.split("[, ]+")) {
                addRole(roles, part);
            }
        } else if (claim instanceof Collection<?> values) {
            values.forEach(value -> addRole(roles, String.valueOf(value)));
        }
        return roles;
    }

    private void addRole(Set<String> roles, String role) {
        if (role == null || role.isBlank()) {
            return;
        }
        roles.add(TenantRolePolicy.canonicalRole(role));
    }

    private String claimAsString(Jwt jwt, String claimName) {
        Object value = jwt.getClaim(claimName);
        if (value == null) {
            return null;
        }
        String text = String.valueOf(value).trim();
        return text.isEmpty() ? null : text;
    }

    private String requireText(String value, String message) {
        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(UNAUTHORIZED, message);
        }
        return value.trim();
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
