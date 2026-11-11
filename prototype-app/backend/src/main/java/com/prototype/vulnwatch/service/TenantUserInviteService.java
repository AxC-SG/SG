package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.ResendEmailClient;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantUserInvite;
import com.prototype.vulnwatch.dto.TenantInviteValidationResponse;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Locale;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class TenantUserInviteService {

    private final IdentityAdministrationService identityAdministrationService;
    private final TenantInviteEmailService tenantInviteEmailService;
    private final LocalCredentialAuthService localCredentialAuthService;
    private final AppUserRepository appUserRepository;
    private final TenantRepository tenantRepository;
    private final AuditEventService auditEventService;
    private final TenantWorkRunner tenantWorkRunner;
    private final SecureRandom secureRandom = new SecureRandom();

    public TenantUserInviteService(
            IdentityAdministrationService identityAdministrationService,
            TenantInviteEmailService tenantInviteEmailService,
            LocalCredentialAuthService localCredentialAuthService,
            AppUserRepository appUserRepository,
            TenantRepository tenantRepository,
            AuditEventService auditEventService,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.identityAdministrationService = identityAdministrationService;
        this.tenantInviteEmailService = tenantInviteEmailService;
        this.localCredentialAuthService = localCredentialAuthService;
        this.appUserRepository = appUserRepository;
        this.tenantRepository = tenantRepository;
        this.auditEventService = auditEventService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    @Transactional(readOnly = true)
    public java.util.List<TenantUserInvite> listInvites(UUID tenantId) {
        return identityAdministrationService.listInvites(tenantId);
    }

    @Transactional
    public TenantUserInvite createInvite(UUID tenantId, String email, String displayName, String role, String invitedBySubject) {
        String tenantRole = TenantRolePolicy.forAssignment(role);
        Tenant tenant = tenantRepository.findById(tenantId)
                .orElseThrow(() -> new IllegalArgumentException("Unknown tenant: " + tenantId));
        String normalizedEmail = normalizeEmail(email);
        String externalSubject = normalizeSubject(normalizedEmail);
        identityAdministrationService.loadOrCreateEligibleLockedUser(tenantId, externalSubject, normalizedEmail, displayName);
        if (identityAdministrationService.hasOpenInvite(tenantId, normalizedEmail)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "An active invite already exists for this email");
        }
        if (identityAdministrationService.hasActiveMembership(tenantId, externalSubject)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "This user already has active tenant access");
        }

        TenantUserInvite invite = new TenantUserInvite();
        invite.setTenant(tenant);
        invite.setEmail(normalizedEmail);
        invite.setDisplayName(trimToNull(displayName));
        invite.setExternalSubject(externalSubject);
        invite.setRole(tenantRole);
        invite.setToken(newToken());
        invite.setStatus("READY");
        invite.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
        invite.setInvitedBy(resolveInvitedBy(invitedBySubject));
        identityAdministrationService.saveInvite(invite);
        auditEventService.record("member.invited", "tenant_user_invite", invite.getId().toString(),
                "{\"tenantId\":\"" + tenantId + "\",\"role\":\"" + invite.getRole() + "\",\"email\":\"" + normalizedEmail + "\"}");
        return deliverInvite(invite);
    }

    @Transactional
    public TenantUserInvite resendInvite(UUID tenantId, UUID inviteId) {
        TenantUserInvite invite = identityAdministrationService.findInviteForUpdate(tenantId, inviteId);
        TenantRolePolicy.forAuthorization(invite.getRole());
        if ("ACCEPTED".equalsIgnoreCase(invite.getStatus()) || invite.getAcceptedAt() != null) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Invite has already been accepted");
        }
        if ("CANCELLED".equalsIgnoreCase(invite.getStatus())) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Invite has been cancelled");
        }
        invite.setToken(newToken());
        invite.setExpiresAt(Instant.now().plus(7, ChronoUnit.DAYS));
        invite.setUpdatedAt(Instant.now());
        auditEventService.record("member.invite.resent", "tenant_user_invite", invite.getId().toString(), null);
        return deliverInvite(invite);
    }

    @Transactional
    public void cancelInvite(UUID tenantId, UUID inviteId) {
        TenantUserInvite invite = identityAdministrationService.findInviteForUpdate(tenantId, inviteId);
        invite.setStatus("CANCELLED");
        invite.setUpdatedAt(Instant.now());
        identityAdministrationService.saveInvite(invite);
        auditEventService.record("member.invite.cancelled", "tenant_user_invite", invite.getId().toString(), null);
    }

    @Transactional(readOnly = true)
    public TenantInviteValidationResponse validateInvite(String token) {
        TenantUserInvite invite = findInvite(token);
        return toValidationResponse(invite, null, null);
    }

    public TenantInviteValidationResponse acceptInvite(String token) {
        UUID tenantId = identityAdministrationService.findInviteTenantId(token);
        return tenantWorkRunner.runScoped(
                tenantId,
                () -> acceptInviteInTenantScope(token));
    }

    private TenantInviteValidationResponse acceptInviteInTenantScope(String token) {
        TenantUserInvite invite = identityAdministrationService.findInviteByTokenForUpdate(token);
        assertAcceptable(invite);
        TenantMembership membership = activateInvitation(invite);
        String setupToken = localCredentialAuthService.issuePasswordSetupToken(invite.getExternalSubject());
        recordAcceptance(invite, membership);
        return toValidationResponse(invite, "Invite accepted", setupToken);
    }

    void assertAcceptable(TenantUserInvite invite) {
        TenantInviteValidationResponse validation = toValidationResponse(invite, null, null);
        if (!validation.valid()) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, validation.message());
        }
    }

    TenantMembership activateInvitation(TenantUserInvite invite) {
        TenantMembership membership = identityAdministrationService.activateInvitedMembership(
                invite.getTenant().getId(),
                invite.getExternalSubject(),
                invite.getEmail(),
                invite.getDisplayName(),
                TenantRolePolicy.forAuthorization(invite.getRole()),
                invite.getInvitedBy()
        );
        invite.setStatus("ACCEPTED");
        invite.setAcceptedAt(Instant.now());
        identityAdministrationService.saveInvite(invite);
        return membership;
    }

    void recordAcceptance(TenantUserInvite invite, TenantMembership membership) {
        auditEventService.recordExplicitActor(
                invite.getTenant().getId(),
                invite.getExternalSubject(),
                membership.getRole(),
                "member.invite.accepted",
                "tenant_user_invite",
                invite.getId().toString(),
                "{\"tenantId\":\"" + invite.getTenant().getId() + "\",\"membershipId\":\"" + membership.getId() + "\"}",
                "SUCCESS");
    }

    private TenantUserInvite deliverInvite(TenantUserInvite invite) {
        TenantRolePolicy.forAuthorization(invite.getRole());
        ResendEmailClient.DeliveryResult deliveryResult = tenantInviteEmailService.sendInvite(invite);
        if (deliveryResult.state() == ResendEmailClient.DeliveryState.QUEUED) {
            invite.setStatus("QUEUED");
            invite.setDeliveryDetail(deliveryResult.detail());
            auditEventService.record("member.invite.email.queued","tenant_user_invite",invite.getId().toString(),null);
        } else if (deliveryResult.state() == ResendEmailClient.DeliveryState.SENT) {
            invite.setStatus("SENT");
            invite.setLastSentAt(Instant.now());
            invite.setProviderMessageId(deliveryResult.providerMessageId());
            invite.setDeliveryDetail(null);
            auditEventService.record("member.invite.sent", "tenant_user_invite", invite.getId().toString(), null);
        } else if (deliveryResult.state() == ResendEmailClient.DeliveryState.SKIPPED) {
            invite.setStatus("DELIVERY_ERROR");
            invite.setDeliveryDetail(deliveryResult.detail());
            auditEventService.record("member.invite.email.skipped", "tenant_user_invite", invite.getId().toString(), detailJson(deliveryResult.detail()));
        } else {
            invite.setStatus("DELIVERY_ERROR");
            invite.setDeliveryDetail(deliveryResult.detail());
            auditEventService.record("member.invite.email.failed", "tenant_user_invite", invite.getId().toString(), detailJson(deliveryResult.detail()));
        }
        invite.setUpdatedAt(Instant.now());
        return identityAdministrationService.saveInvite(invite);
    }

    private TenantUserInvite findInvite(String token) {
        return identityAdministrationService.findInviteByToken(token);
    }

    private TenantInviteValidationResponse toValidationResponse(TenantUserInvite invite, String overrideMessage, String setupToken) {
        Instant now = Instant.now();
        Tenant tenant = invite.getTenant();
        boolean inviteExpired = invite.getExpiresAt() == null || !invite.getExpiresAt().isAfter(now);
        boolean accepted = invite.getAcceptedAt() != null || "ACCEPTED".equalsIgnoreCase(invite.getStatus());
        boolean cancelled = "CANCELLED".equalsIgnoreCase(invite.getStatus());
        boolean deliveryError = "DELIVERY_ERROR".equalsIgnoreCase(invite.getStatus());
        boolean valid = !inviteExpired && !accepted && !cancelled && tenant != null && "ACTIVE".equalsIgnoreCase(tenant.getStatus());
        String status = accepted
                ? "ACCEPTED"
                : cancelled
                ? "CANCELLED"
                : inviteExpired
                ? "INVITE_EXPIRED"
                : deliveryError
                ? "DELIVERY_ERROR"
                : invite.getStatus();
        String message = overrideMessage != null
                ? overrideMessage
                : deliveryError
                ? "Email delivery failed, but this invite is still valid. Continue here to set your password manually."
                : accepted
                ? "This invite has already been accepted"
                : cancelled
                ? "This invite has been cancelled"
                : inviteExpired
                ? "This invite has expired"
                : "Invite ready";
        return new TenantInviteValidationResponse(
                valid,
                status,
                invite.getEmail(),
                tenant == null ? null : tenant.getId().toString(),
                tenant == null ? null : tenant.getName(),
                invite.getDisplayName(),
                TenantRolePolicy.forAuthorization(invite.getRole()),
                invite.getExpiresAt(),
                message,
                setupToken
        );
    }

    private String detailJson(String detail) {
        return "{\"detail\":\"" + escapeJson(detail) + "\"}";
    }

    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private AppUser resolveInvitedBy(String invitedBySubject) {
        if (invitedBySubject == null || invitedBySubject.isBlank()) {
            return null;
        }
        return appUserRepository.findByExternalSubject(invitedBySubject.trim()).orElse(null);
    }

    private String normalizeEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("email is required");
        }
        return email.trim().toLowerCase(Locale.ROOT);
    }

    private String normalizeSubject(String email) {
        return normalizeEmail(email);
    }

    private String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private String newToken() {
        byte[] bytes = new byte[48];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
