package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.http.CognitoBrowserIdentityClient.Identity;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.repo.AppUserRepository;
import com.prototype.vulnwatch.repo.TenantMembershipRepository;
import java.util.Locale;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@ConditionalOnProperty(name = "app.security.managed-auth.enabled", havingValue = "true")
class ManagedTenantInviteService {
    private final IdentityAdministrationService identities;
    private final TenantUserInviteService invites;
    private final TenantWorkRunner tenantWork;
    private final AppUserRepository users;
    private final TenantMembershipRepository memberships;
    private final AppUserGlobalRoleService roles;
    private final ManagedBrowserSessionStore store;

    ManagedTenantInviteService(IdentityAdministrationService identities, TenantUserInviteService invites,
                               TenantWorkRunner tenantWork, AppUserRepository users, TenantMembershipRepository memberships,
                               AppUserGlobalRoleService roles, ManagedBrowserSessionStore store) {
        this.identities = identities;
        this.invites = invites;
        this.tenantWork = tenantWork;
        this.users = users;
        this.memberships = memberships;
        this.roles = roles;
        this.store = store;
    }

    <T> T accept(String inviteHash, String issuer, Identity identity, Supplier<T> issueSession) {
        if (identity.verifiedEmail() == null) {
            throw denied();
        }
        UUID tenantId = TenantContext.runAsPlatform(() -> identities.findInviteTenantIdByHash(inviteHash))
                .orElseThrow(ManagedTenantInviteService::denied);
        return tenantWork.runScoped(tenantId, () -> {
            var invite = identities.findInviteByHashForUpdate(inviteHash).orElseThrow(ManagedTenantInviteService::denied);
            if (!tenantId.equals(invite.getTenant().getId()) || !matchesEmail(invite.getEmail(), identity.verifiedEmail())) {
                throw denied();
            }
            invites.assertAcceptable(invite);
            AppUser user = users.findByExternalSubjectForUpdate(invite.getExternalSubject())
                    .orElseThrow(ManagedTenantInviteService::denied);
            if (!"ACTIVE".equalsIgnoreCase(user.getStatus()) || !matchesEmail(invite.getEmail(), user.getEmail())
                    || identities.hasActiveMembership(tenantId, user.getExternalSubject())) {
                throw denied();
            }
            linkOrCheck(user, issuer, identity.subject());
            var membership = invites.activateInvitation(invite);
            T session = issueSession.get();
            invites.recordAcceptance(invite, membership);
            return session;
        });
    }

    private void linkOrCheck(AppUser user, String issuer, String subject) {
        var linkedUser = store.findLinkedUser(issuer, subject);
        if (linkedUser.isPresent()) {
            if (!user.getId().equals(linkedUser.get())) {
                throw denied();
            }
            return;
        }

        // Only an invitation placeholder can receive its first managed identity.
        // Existing accounts require an operator-reviewed binding.
        if (user.getPasswordHash() != null || user.getPasswordSetAt() != null
                || user.getPasswordSetupTokenHash() != null || user.getLastSeenAt() != null || user.isPlatformOwner()
                || memberships.existsByUser_Id(user.getId()) || !roles.rolesForUser(user.getId()).isEmpty()
                || !store.linkNewIdentity(issuer, subject, user.getId())) {
            throw denied();
        }
    }

    private static boolean matchesEmail(String invitedEmail, String email) {
        return email != null && invitedEmail.toLowerCase(Locale.ROOT).equals(email.toLowerCase(Locale.ROOT));
    }

    private static ResponseStatusException denied() {
        return new ResponseStatusException(HttpStatus.FORBIDDEN, "Managed invitation could not be accepted");
    }
}
