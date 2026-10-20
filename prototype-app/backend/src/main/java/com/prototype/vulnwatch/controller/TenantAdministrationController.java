package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.TenantMembership;
import com.prototype.vulnwatch.domain.TenantUserInvite;
import com.prototype.vulnwatch.dto.InventoryConnectorHealthResponse;
import com.prototype.vulnwatch.dto.TenantBulkInviteItemResponse;
import com.prototype.vulnwatch.dto.TenantBulkInviteRequest;
import com.prototype.vulnwatch.dto.TenantBulkInviteResponse;
import com.prototype.vulnwatch.dto.TenantCreateRequest;
import com.prototype.vulnwatch.dto.TenantDemoExpiryRequest;
import com.prototype.vulnwatch.dto.TenantInviteRequest;
import com.prototype.vulnwatch.dto.TenantInviteResponse;
import com.prototype.vulnwatch.dto.TenantMemberRequest;
import com.prototype.vulnwatch.dto.TenantMemberResponse;
import com.prototype.vulnwatch.dto.TenantMemberUpdateRequest;
import com.prototype.vulnwatch.dto.PlatformUserRequest;
import com.prototype.vulnwatch.dto.PlatformUserResponse;
import com.prototype.vulnwatch.dto.PlatformUserSetupLinkResponse;
import com.prototype.vulnwatch.dto.TenantQuotaUpdateRequest;
import com.prototype.vulnwatch.dto.TenantResponse;
import com.prototype.vulnwatch.dto.TenantOwnerRecoveryRequest;
import com.prototype.vulnwatch.dto.TenantStatusRequest;
import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.IdentityAdministrationService;
import com.prototype.vulnwatch.service.PlatformInventoryConnectorHealthService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantAccessControlService;
import com.prototype.vulnwatch.service.TenantAdministrationService;
import com.prototype.vulnwatch.service.DemoDatasetProvisioningService;
import com.prototype.vulnwatch.service.TenantUserInviteService;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.DeleteMapping;

@RestController
@RequestMapping("/api")
public class TenantAdministrationController {

    private final TenantAdministrationService tenantAdministrationService;
    private final IdentityAdministrationService identityAdministrationService;
    private final AuditEventService auditEventService;
    private final RequestActorService requestActorService;
    private final TenantAccessControlService tenantAccessControlService;
    private final PlatformInventoryConnectorHealthService platformInventoryConnectorHealthService;
    private final TenantUserInviteService tenantUserInviteService;

    public TenantAdministrationController(
            TenantAdministrationService tenantAdministrationService,
            IdentityAdministrationService identityAdministrationService,
            AuditEventService auditEventService,
            RequestActorService requestActorService,
            TenantAccessControlService tenantAccessControlService,
            PlatformInventoryConnectorHealthService platformInventoryConnectorHealthService,
            TenantUserInviteService tenantUserInviteService
    ) {
        this.tenantAdministrationService = tenantAdministrationService;
        this.identityAdministrationService = identityAdministrationService;
        this.auditEventService = auditEventService;
        this.requestActorService = requestActorService;
        this.tenantAccessControlService = tenantAccessControlService;
        this.platformInventoryConnectorHealthService = platformInventoryConnectorHealthService;
        this.tenantUserInviteService = tenantUserInviteService;
    }

    @GetMapping("/tenants")
    public List<TenantResponse> listTenants() {
        var actor = requestActorService.currentActor();
        if (!actor.hasRole("PLATFORM_OWNER") && actor.tenantId() == null) {
            return List.of();
        }
        if (!actor.hasRole("PLATFORM_OWNER")) {
            return tenantAdministrationService.listTenants().stream()
                    .filter(tenant -> actor.tenantId().equals(tenant.getId()))
                    .map(this::toTenantResponse)
                    .toList();
        }
        return tenantAdministrationService.listTenants().stream().map(this::toTenantResponse).toList();
    }

    @PostMapping("/platform/tenants")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public ResponseEntity<TenantResponse> createTenant(@Valid @RequestBody TenantCreateRequest request) {
        Tenant tenant = tenantAdministrationService.createTenant(
                request.name(), request.slug(), request.planCode(), request.billingRef(), request.addDemoData(),
                request.ownerEmail(), request.ownerPassword());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(toTenantResponse(tenant));
    }

    @PostMapping("/platform/tenants/{tenantId}/provisioning-retry")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public ResponseEntity<TenantResponse> retryTenantProvisioning(@PathVariable UUID tenantId) {
        Tenant tenant = tenantAdministrationService.retryProvisioning(tenantId);
        auditEventService.record("tenant.provisioning.retry_requested", "tenant", tenant.getId().toString(), null);
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(toTenantResponse(tenant));
    }

    @GetMapping("/platform/tenants/{tenantId}")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public TenantResponse getTenant(@PathVariable UUID tenantId) {
        return toTenantResponse(tenantAdministrationService.getTenant(tenantId));
    }

    @PostMapping("/platform/tenants/{tenantId}/owner-recovery")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public TenantResponse recoverTenantOwner(
            @PathVariable UUID tenantId,
            @Valid @RequestBody TenantOwnerRecoveryRequest request
    ) {
        Tenant tenant = tenantAdministrationService.recoverTenantOwner(
                tenantId, request.ownerEmail(), request.ownerPassword());
        return toTenantResponse(tenant);
    }

    @PatchMapping("/platform/tenants/{tenantId}/status")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public TenantResponse updateTenantStatus(@PathVariable UUID tenantId, @RequestBody TenantStatusRequest request) {
        Tenant tenant = tenantAdministrationService.updateStatus(tenantId, request.status());
        auditEventService.record("tenant.status.updated", "tenant", tenant.getId().toString(),
                "{\"status\":\"" + tenant.getStatus() + "\"}");
        return toTenantResponse(tenant);
    }

    @PatchMapping("/platform/tenants/{tenantId}/demo-expiry")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public TenantResponse extendTenantDemoExpiry(
            @PathVariable UUID tenantId,
            @Valid @RequestBody TenantDemoExpiryRequest request
    ) {
        Tenant tenant = tenantAdministrationService.extendDemoExpiry(tenantId, request.expiresAt());
        auditEventService.record("tenant.demo_expiry.extended", "tenant", tenant.getId().toString(),
                "{\"expiresAt\":\"" + tenant.getDemoExpiresAt() + "\"}");
        return toTenantResponse(tenant);
    }

    @PatchMapping("/platform/tenants/{tenantId}/quotas")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public TenantResponse updateTenantQuotas(@PathVariable UUID tenantId, @RequestBody TenantQuotaUpdateRequest request) {
        Tenant tenant = tenantAdministrationService.updateQuotas(tenantId, request);
        auditEventService.record("tenant.quotas.updated", "tenant", tenant.getId().toString(),
                "{"
                        + "\"maxDailySbomUploads\":" + tenant.getMaxDailySbomUploads() + ","
                        + "\"sbomRateLimitWindowSeconds\":" + number(tenant.getSbomRateLimitWindowSeconds()) + ","
                        + "\"maxSbomJobsPerRateLimitWindow\":" + number(tenant.getMaxSbomJobsPerRateLimitWindow()) + ","
                        + "\"maxActiveSbomJobs\":" + number(tenant.getMaxActiveSbomJobs())
                        + "}");
        return toTenantResponse(tenant);
    }

    @DeleteMapping("/platform/tenants/{tenantId}")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public ResponseEntity<Void> deleteTenant(@PathVariable UUID tenantId) {
        com.prototype.vulnwatch.service.ManualTenantDeletionPolicy.requirePermitted();
        tenantAdministrationService.deleteTenant(tenantId);
        auditEventService.record(
                "tenant.delete.requested",
                "tenant",
                tenantId.toString(),
                "{\"actor\":\"" + requestActorService.currentActor().userId() + "\"}");
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/platform/users")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public List<PlatformUserResponse> listPlatformUsers() {
        return identityAdministrationService.listPlatformUsers();
    }

    @GetMapping("/platform/inventory-connectors/health")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public List<InventoryConnectorHealthResponse> listInventoryConnectorHealth() {
        return platformInventoryConnectorHealthService.listInventoryConnectorHealth();
    }

    @PostMapping("/platform/users")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public PlatformUserResponse upsertPlatformUser(@RequestBody PlatformUserRequest request) {
        PlatformUserResponse response = identityAdministrationService.upsertPlatformUserRole(
                request.externalSubject(),
                request.email(),
                request.displayName(),
                request.role()
        );
        auditEventService.record(
                "platform.user.role.granted",
                "app_user",
                response.userId().toString(),
                "{\"role\":\"" + (request.role() == null ? "" : request.role()) + "\"}"
        );
        return response;
    }

    @DeleteMapping("/platform/users/{userId}/roles/{role}")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public void revokePlatformUserRole(@PathVariable UUID userId, @PathVariable String role) {
        identityAdministrationService.revokePlatformUserRole(userId, role);
        auditEventService.record(
                "platform.user.role.revoked",
                "app_user",
                userId.toString(),
                "{\"role\":\"" + role + "\"}"
        );
    }

    @PostMapping("/platform/users/{userId}/setup-link")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public PlatformUserSetupLinkResponse issuePlatformUserSetupLink(@PathVariable UUID userId) {
        PlatformUserSetupLinkResponse response = identityAdministrationService.issuePlatformUserSetupLink(userId);
        auditEventService.record(
                "platform.user.setup_issued",
                "app_user",
                userId.toString(),
                "{\"actor\":\"" + requestActorService.currentActor().userId() + "\"}"
        );
        return response;
    }

    @GetMapping("/tenants/{tenantId}/members")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    public List<TenantMemberResponse> listMembers(@PathVariable UUID tenantId) {
        assertSameTenantOrPlatformOwner(tenantId);
        return identityAdministrationService.listMembers(tenantId).stream()
                .map(this::toMemberResponse)
                .toList();
    }

    @PostMapping("/tenants/{tenantId}/members")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("tenant.member.added")
    public TenantMemberResponse addMember(@PathVariable UUID tenantId, @RequestBody TenantMemberRequest request) {
        assertSameTenantOrPlatformOwner(tenantId);
        TenantMembership membership = identityAdministrationService.addMember(
                tenantId,
                request.subject(),
                request.email(),
                request.displayName(),
                request.role());
        auditEventService.record("tenant.member.added", "tenant_membership", membership.getId().toString(),
                "{\"tenantId\":\"" + tenantId + "\",\"role\":\"" + membership.getRole() + "\"}");
        return toMemberResponse(membership);
    }

    @PatchMapping("/tenants/{tenantId}/members/{memberId}")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("member.updated")
    public TenantMemberResponse updateMember(
            @PathVariable UUID tenantId,
            @PathVariable UUID memberId,
            @RequestBody TenantMemberUpdateRequest request
    ) {
        assertSameTenantOrPlatformOwner(tenantId);
        TenantMembership previous = identityAdministrationService.findMember(tenantId, memberId);
        String previousRole = previous.getRole();
        String previousStatus = previous.getStatus();
        TenantMembership membership = identityAdministrationService.updateMember(tenantId, memberId, request.role(), request.status());
        if (!java.util.Objects.equals(previousRole, membership.getRole())) {
            auditEventService.record("member.role.changed", "tenant_membership", memberId.toString(),
                    "{\"tenantId\":\"" + tenantId + "\",\"before\":\"" + previousRole + "\",\"after\":\"" + membership.getRole() + "\"}");
        }
        if (!java.util.Objects.equals(previousStatus, membership.getStatus())) {
            String action = switch (membership.getStatus()) {
                case "SUSPENDED" -> "member.suspended";
                case "ACTIVE" -> "member.reactivated";
                default -> "member.status.changed";
            };
            auditEventService.record(action, "tenant_membership", memberId.toString(),
                    "{\"tenantId\":\"" + tenantId + "\",\"before\":\"" + previousStatus + "\",\"after\":\"" + membership.getStatus() + "\"}");
        }
        return toMemberResponse(membership);
    }

    @DeleteMapping("/tenants/{tenantId}/members/{memberId}")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("member.removed")
    public void removeMember(@PathVariable UUID tenantId, @PathVariable UUID memberId) {
        assertSameTenantOrPlatformOwner(tenantId);
        identityAdministrationService.removeMember(tenantId, memberId);
        auditEventService.record("member.removed", "tenant_membership", memberId.toString(),
                "{\"tenantId\":\"" + tenantId + "\"}");
    }

    @GetMapping("/tenants/{tenantId}/invites")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    public List<TenantInviteResponse> listInvites(@PathVariable UUID tenantId) {
        assertSameTenantOrPlatformOwner(tenantId);
        return tenantUserInviteService.listInvites(tenantId).stream()
                .map(this::toInviteResponse)
                .toList();
    }

    @PostMapping("/tenants/{tenantId}/invites")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("member.invited")
    public TenantInviteResponse createInvite(@PathVariable UUID tenantId, @RequestBody TenantInviteRequest request) {
        assertSameTenantOrPlatformOwner(tenantId);
        TenantUserInvite invite = tenantUserInviteService.createInvite(
                tenantId,
                request.email(),
                request.displayName(),
                request.role(),
                requestActorService.currentActor().userId()
        );
        return toInviteResponse(invite);
    }

    @PostMapping("/tenants/{tenantId}/invites/bulk")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("member.invited")
    public TenantBulkInviteResponse createBulkInvites(
            @PathVariable UUID tenantId,
            @RequestBody TenantBulkInviteRequest request
    ) {
        assertSameTenantOrPlatformOwner(tenantId);
        List<TenantInviteRequest> rows = request.invites() == null ? List.of() : request.invites();
        List<TenantBulkInviteItemResponse> results = rows.stream()
                .map(row -> {
                    try {
                        TenantUserInvite invite = tenantUserInviteService.createInvite(
                                tenantId,
                                row.email(),
                                row.displayName(),
                                row.role(),
                                requestActorService.currentActor().userId()
                        );
                        return new TenantBulkInviteItemResponse(
                                row.email(),
                                row.displayName(),
                                row.role(),
                                "INVITED",
                                "Invite sent",
                                toInviteResponse(invite)
                        );
                    } catch (ResponseStatusException | IllegalArgumentException exception) {
                        return new TenantBulkInviteItemResponse(
                                row.email(),
                                row.displayName(),
                                row.role(),
                                "FAILED",
                                normalizeBulkInviteError(exception),
                                null
                        );
                    }
                })
                .toList();
        int invitedCount = (int) results.stream().filter(result -> "INVITED".equals(result.status())).count();
        return new TenantBulkInviteResponse(rows.size(), invitedCount, rows.size() - invitedCount, results);
    }

    @PostMapping("/tenants/{tenantId}/invites/{inviteId}/resend")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("member.invite.resent")
    public TenantInviteResponse resendInvite(@PathVariable UUID tenantId, @PathVariable UUID inviteId) {
        assertSameTenantOrPlatformOwner(tenantId);
        return toInviteResponse(tenantUserInviteService.resendInvite(tenantId, inviteId));
    }

    @DeleteMapping("/tenants/{tenantId}/invites/{inviteId}")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("member.invite.cancelled")
    public void cancelInvite(@PathVariable UUID tenantId, @PathVariable UUID inviteId) {
        assertSameTenantOrPlatformOwner(tenantId);
        tenantUserInviteService.cancelInvite(tenantId, inviteId);
    }

    private void assertSameTenantOrPlatformOwner(UUID tenantId) {
        tenantAccessControlService.assertTenantAccess(requestActorService.currentActor(), tenantId);
    }

    private TenantResponse toTenantResponse(Tenant tenant) {
        return new TenantResponse(
                tenant.getId(),
                tenant.getName(),
                tenant.getSlug(),
                tenant.getStatus(),
                tenant.getPlanCode(),
                tenant.getBillingRef(),
                tenant.getMaxConnectorCount(),
                tenant.getMaxServiceAccountCount(),
                tenant.getMaxDailySbomUploads(),
                tenant.getMaxExportRows(),
                tenant.getMaxDailyExposureRefreshes(),
                tenant.getSbomRateLimitWindowSeconds(),
                tenant.getMaxSbomJobsPerRateLimitWindow(),
                tenant.getMaxActiveSbomJobs(),
                tenant.getDemoExpiresAt(),
                tenant.getExpiredAt(),
                tenant.getPurgeStartedAt(),
                tenant.getPurgedAt(),
                tenant.getPurgeStatus(),
                tenant.getPurgeError(),
                tenant.getDemoCreatedBy(),
                tenant.getDemoSource(),
                tenant.getDemoOwnerEmail(),
                DemoDatasetProvisioningService.isRequested(tenant),
                DemoDatasetProvisioningService.status(tenant),
                DemoDatasetProvisioningService.version(tenant),
                tenant.getCreatedAt(),
                tenant.getUpdatedAt());
    }

    private TenantMemberResponse toMemberResponse(TenantMembership membership) {
        return new TenantMemberResponse(
                membership.getId(),
                membership.getUser().getId(),
                membership.getUser().getExternalSubject(),
                membership.getUser().getEmail(),
                membership.getUser().getDisplayName(),
                membership.getRole(),
                membership.getStatus(),
                membership.getCreatedAt());
    }

    private TenantInviteResponse toInviteResponse(TenantUserInvite invite) {
        return new TenantInviteResponse(
                invite.getId(),
                invite.getTenant().getId(),
                invite.getEmail(),
                invite.getDisplayName(),
                invite.getExternalSubject(),
                invite.getRole(),
                invite.getStatus(),
                invite.getCreatedAt(),
                invite.getExpiresAt(),
                invite.getAcceptedAt(),
                invite.getLastSentAt(),
                invite.getInvitedBy() == null ? null : invite.getInvitedBy().getExternalSubject(),
                invite.getInvitedBy() == null ? null : invite.getInvitedBy().getDisplayName(),
                invite.getDeliveryDetail()
        );
    }

    private String normalizeBulkInviteError(Exception exception) {
        if (exception instanceof ResponseStatusException responseStatusException
                && responseStatusException.getReason() != null
                && !responseStatusException.getReason().isBlank()) {
            return responseStatusException.getReason();
        }
        String message = exception.getMessage();
        if (message == null || message.isBlank()) {
            return "Invite failed";
        }
        return message.trim().replace('_', ' ');
    }

    private String number(Number value) {
        return value == null ? "null" : value.toString();
    }

}
