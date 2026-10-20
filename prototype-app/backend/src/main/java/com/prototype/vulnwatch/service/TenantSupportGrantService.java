package com.prototype.vulnwatch.service;

import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.NOT_FOUND;
import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantSupportGrant;
import com.prototype.vulnwatch.dto.TenantSupportGrantRequest;
import com.prototype.vulnwatch.dto.TenantSupportGrantResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.repo.TenantSupportGrantRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class TenantSupportGrantService {

    public static final String ACCESS_MODE_READ_ONLY = "READ_ONLY";
    public static final String ACCESS_MODE_WRITE_ENABLED = "WRITE_ENABLED";

    private final TenantSupportGrantRepository tenantSupportGrantRepository;
    private final TenantRepository tenantRepository;
    private final AppUserRepository appUserRepository;
    private final TenantLifecycleGuardService tenantLifecycleGuardService;
    private final AppUserGlobalRoleService globalRoleService;

    @Value("${app.security.support-access.default-hours:24}")
    private long defaultHours = 24;

    @Value("${app.security.support-access.maximum-days:30}")
    private long maximumDays = 30;

    @Value("${app.security.support-access.allow-non-expiring:false}")
    private boolean allowNonExpiring;

    public TenantSupportGrantService(
            TenantSupportGrantRepository tenantSupportGrantRepository,
            TenantRepository tenantRepository,
            AppUserRepository appUserRepository,
            TenantLifecycleGuardService tenantLifecycleGuardService,
            AppUserGlobalRoleService globalRoleService
    ) {
        this.tenantSupportGrantRepository = tenantSupportGrantRepository;
        this.tenantRepository = tenantRepository;
        this.appUserRepository = appUserRepository;
        this.tenantLifecycleGuardService = tenantLifecycleGuardService;
        this.globalRoleService = globalRoleService;
    }

    @Transactional(readOnly = true)
    public List<TenantSupportGrantResponse> listForTenant(UUID tenantId) {
        return tenantSupportGrantRepository.findByTenant_IdOrderByRequestedAtDesc(tenantId).stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public List<TenantSupportGrantResponse> listForPlatformOwner(String subject) {
        return tenantSupportGrantRepository.findByInvitedPlatformSubjectIgnoreCaseOrderByRequestedAtDesc(normalizeSubject(subject)).stream()
                .map(this::refreshExpiredStatus)
                .sorted(Comparator.comparing(TenantSupportGrant::getRequestedAt).reversed())
                .map(this::toResponse)
                .toList();
    }

    @Transactional
    public TenantSupportGrantResponse create(UUID tenantId, String grantedBySubject, TenantSupportGrantRequest request) {
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Tenant not found"));
        AppUser grantedBy = appUserRepository.findByExternalSubject(requireText(grantedBySubject, "grantedBySubject"))
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Authenticated user is not registered"));
        String invitedSubject = normalizeSubject(request.invitedPlatformSubject());
        AppUser invitedOwner = appUserRepository.findByExternalSubject(invitedSubject)
                .or(() -> appUserRepository.findByEmailIgnoreCase(invitedSubject))
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Invited platform owner is not registered"));
        if (!globalRoleService.rolesForUser(invitedOwner.getId()).contains("PLATFORM_OWNER")
                || !"ACTIVE".equalsIgnoreCase(invitedOwner.getStatus())) {
            throw new ResponseStatusException(FORBIDDEN, "Support access may be granted only to an active platform owner");
        }

        Instant expiresAt = request.expiresAt();
        if (expiresAt == null && !allowNonExpiring) {
            expiresAt = Instant.now().plus(Math.max(1, defaultHours), ChronoUnit.HOURS);
        }
        if (expiresAt != null) {
            if (!expiresAt.isAfter(Instant.now())) {
                throw new ResponseStatusException(FORBIDDEN, "Support access expiry must be in the future");
            }
            if (expiresAt.isAfter(Instant.now().plus(Math.max(1, maximumDays), ChronoUnit.DAYS))) {
                throw new ResponseStatusException(FORBIDDEN, "Support access exceeds the configured maximum duration");
            }
        }

        TenantSupportGrant grant = new TenantSupportGrant();
        grant.setTenant(tenant);
        grant.setGrantedBy(grantedBy);
        grant.setInvitedPlatformSubject(invitedOwner.getExternalSubject().toLowerCase(Locale.ROOT));
        grant.setReason(requireText(request.reason(), "reason"));
        grant.setScope(blankToNull(request.scope()));
        grant.setAccessMode(normalizeAccessMode(request.accessMode()));
        grant.setStatus("PENDING");
        grant.setRequestedAt(Instant.now());
        grant.setExpiresAt(expiresAt);
        grant.setUpdatedAt(Instant.now());
        return toResponse(tenantSupportGrantRepository.save(grant));
    }

    @Transactional
    public TenantSupportGrantResponse accept(UUID grantId, String platformSubject) {
        TenantSupportGrant grant = tenantSupportGrantRepository.findByIdForUpdate(grantId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Support grant not found"));
        refreshExpiredStatus(grant);
        String normalizedSubject = normalizeSubject(platformSubject);
        if (!normalizedSubject.equalsIgnoreCase(grant.getInvitedPlatformSubject())) {
            throw new ResponseStatusException(FORBIDDEN, "Support grant is not assigned to the current platform owner");
        }
        if (!"PENDING".equalsIgnoreCase(grant.getStatus()) && !"ACTIVE".equalsIgnoreCase(grant.getStatus())) {
            throw new ResponseStatusException(FORBIDDEN, "Support grant is not available for acceptance");
        }
        if (grant.getExpiresAt() != null && !grant.getExpiresAt().isAfter(Instant.now())) {
            markExpired(grant);
            throw new ResponseStatusException(FORBIDDEN, "Support grant has expired");
        }
        AppUser acceptedBy = appUserRepository.findByExternalSubject(normalizedSubject)
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Authenticated platform owner is not registered"));
        if (!isCurrentActiveOwner(acceptedBy)) {
            throw new ResponseStatusException(FORBIDDEN, "Current active platform-owner access is required");
        }
        grant.setAcceptedBy(acceptedBy);
        if (grant.getAcceptedAt() == null) {
            grant.setAcceptedAt(Instant.now());
        }
        grant.setStatus("ACTIVE");
        grant.setUpdatedAt(Instant.now());
        return toResponse(tenantSupportGrantRepository.save(grant));
    }

    @Transactional
    public TenantSupportGrantResponse revoke(UUID tenantId, UUID grantId, String revokedBySubject) {
        TenantSupportGrant grant = tenantSupportGrantRepository.findByIdForUpdate(grantId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Support grant not found"));
        if (!grant.getTenant().getId().equals(tenantId)) {
            throw new ResponseStatusException(FORBIDDEN, "Support grant does not belong to the selected tenant");
        }
        AppUser revokedBy = appUserRepository.findByExternalSubject(requireText(revokedBySubject, "revokedBySubject"))
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Authenticated user is not registered"));
        grant.setRevokedBy(revokedBy);
        grant.setRevokedAt(Instant.now());
        grant.setStatus("REVOKED");
        grant.setUpdatedAt(Instant.now());
        return toResponse(tenantSupportGrantRepository.save(grant));
    }

    @Transactional(readOnly = true)
    public List<TenantSupportGrant> listActiveGrantsForPlatformOwner(String subject) {
        if (!hasCurrentOwnerAuthority(subject)) {
            return List.of();
        }
        return tenantSupportGrantRepository.findActiveByInvitedPlatformSubject(normalizeSubject(subject), Instant.now()).stream()
                .map(this::refreshExpiredStatus)
                .filter(grant -> "ACTIVE".equalsIgnoreCase(grant.getStatus()))
                .sorted(activeGrantPrecedence())
                .toList();
    }

    @Transactional(readOnly = true)
    public Optional<TenantSupportGrant> findActiveGrant(String subject, UUID tenantId) {
        if (!hasCurrentOwnerAuthority(subject)) {
            return Optional.empty();
        }
        return tenantSupportGrantRepository.findActiveByInvitedPlatformSubjectAndTenantId(
                        normalizeSubject(subject),
                        tenantId,
                        Instant.now())
                .stream()
                .map(this::refreshExpiredStatus)
                .filter(grant -> tenantLifecycleGuardService.isTenantAccessible(grant.getTenant()))
                .filter(grant -> "ACTIVE".equalsIgnoreCase(grant.getStatus()))
                .sorted(activeGrantPrecedence())
                .findFirst();
    }

    @Transactional(readOnly = true)
    public boolean hasActiveGrant(String subject, UUID tenantId) {
        return findActiveGrant(subject, tenantId).isPresent();
    }

    private boolean hasCurrentOwnerAuthority(String subject) {
        return appUserRepository.findByExternalSubject(normalizeSubject(subject))
                .filter(this::isCurrentActiveOwner).isPresent();
    }

    private boolean isCurrentActiveOwner(AppUser user) {
        return "ACTIVE".equalsIgnoreCase(user.getStatus())
                && globalRoleService.rolesForUser(user.getId()).contains("PLATFORM_OWNER");
    }

    @Transactional
    public void requireActiveGrant(String subject, UUID tenantId) {
        if (tenantId == null || !hasActiveGrant(subject, tenantId)) {
            throw new ResponseStatusException(FORBIDDEN, "Platform owner does not have active support access for this tenant");
        }
    }

    @Transactional
    public TenantSupportGrant requireActiveGrantForWrite(String subject, UUID tenantId) {
        TenantSupportGrant grant = findActiveGrant(subject, tenantId)
                .orElseThrow(() -> new ResponseStatusException(
                        FORBIDDEN,
                        "Platform owner does not have active support access for this tenant"));
        if (!isWriteEnabled(grant.getAccessMode())) {
            throw new ResponseStatusException(
                    FORBIDDEN,
                    "This support session is read-only. Request a write-enabled support grant to modify tenant data.");
        }
        return grant;
    }

    public boolean isWriteEnabled(String accessMode) {
        return ACCESS_MODE_WRITE_ENABLED.equals(normalizeAccessMode(accessMode));
    }

    private Comparator<TenantSupportGrant> activeGrantPrecedence() {
        return Comparator.comparingInt((TenantSupportGrant grant) -> isWriteEnabled(grant.getAccessMode()) ? 0 : 1)
                .thenComparing(TenantSupportGrant::getRequestedAt,
                        Comparator.nullsLast(Comparator.reverseOrder()));
    }

    @Transactional
    public TenantSupportGrant ensureLocalDevelopmentWriteGrant(Tenant tenant, AppUser platformOwner) {
        TenantSupportGrant existing = findActiveGrant(platformOwner.getExternalSubject(), tenant.getId()).orElse(null);
        if (existing != null && isWriteEnabled(existing.getAccessMode())) {
            return existing;
        }
        Instant now = Instant.now();
        TenantSupportGrant grant = new TenantSupportGrant();
        grant.setTenant(tenant);
        grant.setGrantedBy(platformOwner);
        grant.setAcceptedBy(platformOwner);
        grant.setInvitedPlatformSubject(normalizeSubject(platformOwner.getExternalSubject()));
        grant.setReason("Localhost development bootstrap access");
        grant.setScope("LOCALHOST_BOOTSTRAP");
        grant.setAccessMode(ACCESS_MODE_WRITE_ENABLED);
        grant.setStatus("ACTIVE");
        grant.setRequestedAt(now);
        grant.setAcceptedAt(now);
        grant.setExpiresAt(now.plus(3650, ChronoUnit.DAYS));
        grant.setUpdatedAt(now);
        return tenantSupportGrantRepository.save(grant);
    }

    private TenantSupportGrant refreshExpiredStatus(TenantSupportGrant grant) {
        if (grant.getRevokedAt() == null
                && grant.getExpiresAt() != null
                && !grant.getExpiresAt().isAfter(Instant.now())
                && !"EXPIRED".equalsIgnoreCase(grant.getStatus())) {
            markExpired(grant);
        }
        return grant;
    }

    private void markExpired(TenantSupportGrant grant) {
        grant.setStatus("EXPIRED");
        grant.setUpdatedAt(Instant.now());
        tenantSupportGrantRepository.save(grant);
    }

    private TenantSupportGrantResponse toResponse(TenantSupportGrant grant) {
        return new TenantSupportGrantResponse(
                grant.getId(),
                grant.getTenant().getId(),
                grant.getTenant().getName(),
                grant.getInvitedPlatformSubject(),
                grant.getReason(),
                grant.getScope(),
                grant.getAccessMode(),
                grant.getStatus(),
                grant.getGrantedBy() == null ? null : grant.getGrantedBy().getExternalSubject(),
                grant.getAcceptedBy() == null ? null : grant.getAcceptedBy().getExternalSubject(),
                grant.getRevokedBy() == null ? null : grant.getRevokedBy().getExternalSubject(),
                grant.getRequestedAt(),
                grant.getAcceptedAt(),
                grant.getExpiresAt(),
                grant.getRevokedAt()
        );
    }

    private String normalizeSubject(String subject) {
        return requireText(subject, "invitedPlatformSubject").toLowerCase(Locale.ROOT);
    }

    private String normalizeAccessMode(String accessMode) {
        String normalized = blankToNull(accessMode);
        if (normalized == null) {
            return ACCESS_MODE_READ_ONLY;
        }
        String canonical = normalized.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        if (ACCESS_MODE_READ_ONLY.equals(canonical) || ACCESS_MODE_WRITE_ENABLED.equals(canonical)) {
            return canonical;
        }
        throw new ResponseStatusException(FORBIDDEN, "accessMode must be READ_ONLY or WRITE_ENABLED");
    }

    private String blankToNull(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        return value.trim();
    }

    private String requireText(String value, String field) {
        if (value == null || value.isBlank()) {
            throw new ResponseStatusException(FORBIDDEN, field + " is required");
        }
        return value.trim();
    }
}
