package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class LocalCredentialAuthService {

    private final AppUserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final TenantMembershipRepository membershipRepository;
    private final AuthTokenService authTokenService;
    private final TenantSupportGrantService tenantSupportGrantService;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final AppUserGlobalRoleService appUserGlobalRoleService;
    private final AuditEventService auditEventService;
    private final TenantWorkRunner tenantWorkRunner;
    private final TenantAccessResolutionService accessResolutionService;
    private final boolean requireProductionSecrets;
    private final boolean sharedLocalhostLoginEnabled;
    private final String sharedLocalhostTenantAdminEmail;
    private final String sharedLocalhostTenantAdminPasswordHash;
    private final boolean sharedLocalhostEnvironment;

    public LocalCredentialAuthService(
            AppUserRepository userRepository,
            TenantRepository tenantRepository,
            TenantMembershipRepository membershipRepository,
            AuthTokenService authTokenService,
            TenantSupportGrantService tenantSupportGrantService,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            AppUserGlobalRoleService appUserGlobalRoleService,
            AuditEventService auditEventService,
            TenantWorkRunner tenantWorkRunner,
            @Value("${app.security.require-production-secrets:false}") boolean requireProductionSecrets,
            @Value("${app.security.local-auth.shared-localhost-login-enabled:false}") boolean sharedLocalhostLoginEnabled,
            @Value("${app.security.local-auth.shared-localhost-tenant-admin-email:}") String sharedLocalhostTenantAdminEmail,
            @Value("${app.security.local-auth.shared-localhost-tenant-admin-password-hash:}") String sharedLocalhostTenantAdminPasswordHash,
            @Value("${app.cors.allowed-origins:}") String corsAllowedOrigins
    ) {
        this.userRepository = userRepository;
        this.tenantRepository = tenantRepository;
        this.membershipRepository = membershipRepository;
        this.authTokenService = authTokenService;
        this.tenantSupportGrantService = tenantSupportGrantService;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.appUserGlobalRoleService = appUserGlobalRoleService;
        this.auditEventService = auditEventService;
        this.tenantWorkRunner = tenantWorkRunner;
        this.accessResolutionService = new TenantAccessResolutionService(
                tenantRepository,
                membershipRepository,
                tenantSupportGrantService,
                tenantLifecycleGuardService);
        this.requireProductionSecrets = requireProductionSecrets;
        this.sharedLocalhostLoginEnabled = sharedLocalhostLoginEnabled;
        this.sharedLocalhostTenantAdminEmail = sharedLocalhostTenantAdminEmail == null
                ? "" : sharedLocalhostTenantAdminEmail.trim();
        this.sharedLocalhostTenantAdminPasswordHash = sharedLocalhostTenantAdminPasswordHash == null
                ? "" : sharedLocalhostTenantAdminPasswordHash.trim();
        this.sharedLocalhostEnvironment = detectSharedLocalhostEnvironment(corsAllowedOrigins);
    }

    @Transactional
    public AuthTokenResponse login(String email, String password) {
        String normalizedEmail = normalizeEmail(email);
        String rawPassword = requirePassword(password);
        AppUser user = userRepository.findByEmailIgnoreCaseForUpdate(normalizedEmail).orElse(null);
        if (user != null) {
            requireActiveUser(user);
        }
        if (user != null && hasText(user.getPasswordHash())) {
            verifyPassword(rawPassword, user.getPasswordHash());
            if (isCurrentPlatformOwner(user)) {
                return issuePlatformOwnerToken(user);
            }
            return loginTenantScopedUser(user);
        }

        if (matchesSharedLocalhostTenantAdmin(normalizedEmail)) {
            verifyPassword(rawPassword, sharedLocalhostTenantAdminPasswordHash);
            return loginSharedLocalhostTenantAdmin(normalizedEmail, sharedLocalhostTenantAdminPasswordHash);
        }

        if (user == null) {
            throw invalidCredentials();
        }
        if (!hasText(user.getPasswordHash())) {
            throw invalidCredentials();
        }
        verifyPassword(rawPassword, user.getPasswordHash());
        return loginTenantScopedUser(user);
    }

    private AuthTokenResponse loginTenantScopedUser(AppUser user) {
        List<TenantMembership> memberships = membershipRepository
                .findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(user.getExternalSubject(), "ACTIVE");
        if (memberships.isEmpty()) {
            List<TenantMembership> suspended = membershipRepository
                    .findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(user.getExternalSubject(), "SUSPENDED");
            if (!suspended.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                        "Your account has been suspended. Contact your administrator to restore access.");
            }
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "No active tenant membership found for this account.");
        }
        if (memberships.size() > 1) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Multiple active tenant memberships found. Contact support.");
        }
        TenantMembership membership = memberships.get(0);
        tenantLifecycleGuardService.assertTenantAccessible(membership.getTenant());
        user.setLastSeenAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        TenantAccessResolution access = accessResolutionService.resolve(user.getExternalSubject(), membership.getTenant().getId());
        return authTokenService.issueToken(user, Set.of(normalizeRole(membership.getRole())), membership.getTenant(), access);
    }

    private AuthTokenResponse loginSharedLocalhostTenantAdmin(String normalizedEmail, String passwordHash) {
        Tenant tenant = tenantRepository.findBySchemaName(TenantService.DEFAULT_TENANT_SCHEMA)
                .filter(Tenant::isInternal)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.CONFLICT, "Default workspace is not bootstrapped"));
        tenantLifecycleGuardService.assertTenantAccessible(tenant);

        AppUser user = userRepository.findByExternalSubjectForUpdate(normalizedEmail)
                .or(() -> userRepository.findByEmailIgnoreCaseForUpdate(normalizedEmail))
                .orElseGet(() -> createUser(normalizedEmail));
        requireActiveUser(user);
        user.setEmail(normalizedEmail);
        user.setDisplayName(user.getDisplayName() == null || user.getDisplayName().isBlank() ? "Local Tenant Admin" : user.getDisplayName());
        user.setStatus("ACTIVE");
        user.setPasswordHash(passwordHash);
        user.setPasswordSetAt(user.getPasswordSetAt() == null ? Instant.now() : user.getPasswordSetAt());
        user.setLastSeenAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);

        TenantMembership membership = membershipRepository
                .findFirstByUserExternalSubjectAndTenantIdAndStatus(user.getExternalSubject(), tenant.getId(), "ACTIVE")
                .map(existing -> {
                    existing.setRole("TENANT_ADMIN");
                    existing.setUpdatedAt(Instant.now());
                    return membershipRepository.save(existing);
                })
                .orElseGet(() -> {
                    TenantMembership created = new TenantMembership();
                    created.setTenant(tenant);
                    created.setUser(user);
                    created.setRole("TENANT_ADMIN");
                    return membershipRepository.save(created);
                });
        TenantAccessResolution access = accessResolutionService.resolve(user.getExternalSubject(), tenant.getId());
        return authTokenService.issueToken(user, Set.of(normalizeRole(membership.getRole())), tenant, access);
    }

    @Transactional
    public AuthTokenResponse setupPassword(String setupToken, String password) {
        if (!hasText(setupToken)) {
            throw invalidSetupToken();
        }
        String normalizedToken = setupToken.trim();
        AppUser user = userRepository.findByPasswordSetupTokenHashForUpdate(hashToken(normalizedToken))
                .orElseThrow(this::invalidSetupToken);
        requireActiveUser(user);
        if (user.getPasswordSetupTokenExpiresAt() == null || !user.getPasswordSetupTokenExpiresAt().isAfter(Instant.now())) {
            clearSetupToken(user);
            throw invalidSetupToken();
        }
        user.setPasswordHash(BCrypt.hashpw(requirePassword(password), BCrypt.gensalt(10)));
        user.setPasswordSetAt(Instant.now());
        clearSetupToken(user);
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        if (isCurrentPlatformOwner(user)) {
            auditEventService.recordExplicitActor(
                    null,
                    user.getExternalSubject(),
                    "PLATFORM_OWNER",
                    "platform.user.setup_completed",
                    "app_user",
                    user.getId().toString(),
                    "{\"mode\":\"self_service\"}",
                    "SUCCESS"
            );
            return issuePlatformOwnerToken(user);
        }

        List<TenantMembership> memberships = membershipRepository
                .findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(user.getExternalSubject(), "ACTIVE");
        if (memberships.isEmpty()) {
            List<TenantMembership> suspended = membershipRepository
                    .findByUserExternalSubjectAndStatusOrderByCreatedAtAsc(user.getExternalSubject(), "SUSPENDED");
            if (!suspended.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                        "Your account has been suspended. Contact your administrator to restore access.");
            }
            throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                    "No active tenant membership found for this account.");
        }
        if (memberships.size() > 1) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Multiple active tenant memberships found. Contact support.");
        }
        TenantMembership membership = memberships.get(0);
        tenantLifecycleGuardService.assertTenantAccessible(membership.getTenant());
        TenantAccessResolution access = accessResolutionService.resolve(user.getExternalSubject(), membership.getTenant().getId());
        return authTokenService.issueToken(user, Set.of(normalizeRole(membership.getRole())), membership.getTenant(), access);
    }

    public AuthTokenResponse switchTenantContext(String subject, UUID tenantId) {
        return TenantContext.runAsPlatform(() -> switchTenantContextInPlatformScope(subject, tenantId));
    }

    private AuthTokenResponse switchTenantContextInPlatformScope(String subject, UUID tenantId) {
        AppUser user = userRepository.findByExternalSubject(requireText(subject, "subject"))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authenticated user is not registered"));
        requireCurrentPlatformOwner(user);
        TenantAccessResolution access = accessResolutionService.resolve(user.getExternalSubject(), tenantId);
        Set<String> roles = access.mode().isSupport()
                ? Set.of("PLATFORM_OWNER")
                : Set.of("PLATFORM_OWNER", normalizeRole(access.role()));
        tenantWorkRunner.runScoped(access.tenant(), () ->
                auditEventService.recordExplicitActor(
                        tenantId,
                        user.getExternalSubject(),
                        "PLATFORM_OWNER",
                        "tenant.context.entered",
                        "tenant_access",
                        access.referenceId().toString(),
                        "{\"mode\":\"" + access.mode().name() + "\"}",
                        "SUCCESS"));
        return authTokenService.issueToken(user, roles, access.tenant(), access);
    }

    public AuthTokenResponse clearTenantContext(String subject) {
        UUID exitedTenantId = TenantContext.getCurrentTenantId();
        return TenantContext.runAsPlatform(() -> clearTenantContextInPlatformScope(subject, exitedTenantId));
    }

    private AuthTokenResponse clearTenantContextInPlatformScope(String subject, UUID exitedTenantId) {
        AppUser user = userRepository.findByExternalSubject(requireText(subject, "subject"))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Authenticated user is not registered"));
        requireCurrentPlatformOwner(user);
        if (exitedTenantId != null) {
            tenantWorkRunner.runScoped(exitedTenantId, () ->
                    auditEventService.recordExplicitActor(
                            exitedTenantId,
                            user.getExternalSubject(),
                            "PLATFORM_OWNER",
                            "tenant.context.exited",
                            "app_user",
                            user.getId().toString(),
                            null,
                            "SUCCESS"));
        }
        return authTokenService.issueToken(user, Set.of("PLATFORM_OWNER"), null);
    }

    @Transactional
    public String issuePasswordSetupToken(String subject) {
        AppUser user = userRepository.findByExternalSubjectForUpdate(requireText(subject, "subject"))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "Invited user not found"));
        String token = UUID.randomUUID() + "-" + UUID.randomUUID();
        user.setPasswordSetupTokenHash(hashToken(token));
        user.setPasswordSetupTokenExpiresAt(Instant.now().plus(30, ChronoUnit.MINUTES));
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        return token;
    }

    @Transactional
    public String exchangePasswordSetupToken(String setupToken) {
        if (!hasText(setupToken)) {
            throw invalidSetupToken();
        }
        AppUser user = userRepository.findByPasswordSetupTokenHashForUpdate(hashToken(setupToken.trim()))
                .orElseThrow(this::invalidSetupToken);
        if (user.getPasswordSetupTokenExpiresAt() == null || !user.getPasswordSetupTokenExpiresAt().isAfter(Instant.now())) {
            clearSetupToken(user);
            throw invalidSetupToken();
        }
        String sessionToken = UUID.randomUUID() + "-" + UUID.randomUUID();
        user.setPasswordSetupTokenHash(hashToken(sessionToken));
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        return sessionToken;
    }

    private AuthTokenResponse issuePlatformOwnerToken(AppUser user) {
        user.setLastSeenAt(Instant.now());
        user.setUpdatedAt(Instant.now());
        userRepository.save(user);
        return authTokenService.issueToken(user, Set.of("PLATFORM_OWNER"), null);
    }

    private void clearSetupToken(AppUser user) {
        user.setPasswordSetupTokenHash(null);
        user.setPasswordSetupTokenExpiresAt(null);
    }

    private boolean matchesSharedLocalhostTenantAdmin(String email) {
        return sharedLocalhostEnvironment
                && hasText(sharedLocalhostTenantAdminEmail)
                && hasText(sharedLocalhostTenantAdminPasswordHash)
                && sharedLocalhostTenantAdminEmail.equalsIgnoreCase(email);
    }

    private boolean detectSharedLocalhostEnvironment(String corsAllowedOrigins) {
        if (requireProductionSecrets || !sharedLocalhostLoginEnabled) {
            return false;
        }
        if (corsAllowedOrigins == null || corsAllowedOrigins.isBlank()) {
            return false;
        }
        return List.of(corsAllowedOrigins.split(",")).stream()
                .map(String::trim)
                .filter(origin -> !origin.isBlank())
                .allMatch(this::isLoopbackOrigin);
    }

    private boolean isLoopbackOrigin(String origin) {
        try {
            URI uri = URI.create(origin);
            return isLoopbackHost(uri.getHost());
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private boolean isLoopbackHost(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        String normalized = value.trim().toLowerCase(Locale.ROOT);
        return "localhost".equals(normalized)
                || "127.0.0.1".equals(normalized)
                || "::1".equals(normalized)
                || "0:0:0:0:0:0:0:1".equals(normalized)
                || "[::1]".equals(normalized);
    }

    private void verifyPassword(String rawPassword, String passwordHash) {
        if (!BCrypt.checkpw(rawPassword, passwordHash)) {
            throw invalidCredentials();
        }
    }

    private AppUser createUser(String externalSubject) {
        AppUser user = new AppUser();
        user.setExternalSubject(externalSubject);
        return user;
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String normalizeRole(String role) {
        return TenantRolePolicy.forAuthorization(role);
    }

    private void requireActiveUser(AppUser user) {
        if (!"ACTIVE".equalsIgnoreCase(user.getStatus())) {
            throw invalidCredentials();
        }
    }

    private boolean isCurrentPlatformOwner(AppUser user) {
        return user.isPlatformOwner()
                || appUserGlobalRoleService.rolesForUser(user.getId()).contains("PLATFORM_OWNER");
    }

    private void requireCurrentPlatformOwner(AppUser user) {
        requireActiveUser(user);
        if (!isCurrentPlatformOwner(user)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Current platform-owner access is required");
        }
    }

    private String normalizeEmail(String value) {
        return requireText(value, "email").toLowerCase();
    }

    private String requirePassword(String value) {
        if (value == null || value.isBlank()) {
            throw invalidCredentials();
        }
        return value;
    }

    private String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, field + " is required");
        }
        return value.trim();
    }

    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to issue password setup token");
        }
    }

    private ResponseStatusException invalidCredentials() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid email or password");
    }

    private ResponseStatusException invalidSetupToken() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password setup token is invalid or expired");
    }
}
