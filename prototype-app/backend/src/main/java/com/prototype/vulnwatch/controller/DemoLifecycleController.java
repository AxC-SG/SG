package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.DemoInviteResponse;
import com.prototype.vulnwatch.dto.DemoSetupLinkResponse;
import com.prototype.vulnwatch.dto.DemoInviteValidationResponse;
import com.prototype.vulnwatch.dto.InvitationTokenRequest;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import com.prototype.vulnwatch.dto.DemoRequestCreateRequest;
import com.prototype.vulnwatch.dto.DemoRequestApprovalRequest;
import com.prototype.vulnwatch.dto.DemoRequestDecisionRequest;
import com.prototype.vulnwatch.dto.DemoRequestResponse;
import com.prototype.vulnwatch.dto.DemoRequestReceiptResponse;
import com.prototype.vulnwatch.service.DuplicateDemoRequestException;
import com.prototype.vulnwatch.dto.DemoStatusResponse;
import com.prototype.vulnwatch.service.DemoLifecycleService;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TurnstileVerificationService;
import com.prototype.vulnwatch.service.WorkspaceService;
import com.prototype.vulnwatch.security.PasswordSetupCookieService;
import com.prototype.vulnwatch.security.PublicEndpointRateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.util.List;
import java.util.UUID;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api")
public class DemoLifecycleController {

    private final DemoLifecycleService demoLifecycleService;
    private final RequestActorService requestActorService;
    private final TurnstileVerificationService turnstileVerificationService;
    private final WorkspaceService workspaceService;
    private final PasswordSetupCookieService passwordSetupCookieService;
    private final PublicEndpointRateLimiter publicEndpointRateLimiter;

    public DemoLifecycleController(
            DemoLifecycleService demoLifecycleService,
            RequestActorService requestActorService,
            TurnstileVerificationService turnstileVerificationService,
            WorkspaceService workspaceService,
            PasswordSetupCookieService passwordSetupCookieService,
            PublicEndpointRateLimiter publicEndpointRateLimiter
    ) {
        this.demoLifecycleService = demoLifecycleService;
        this.requestActorService = requestActorService;
        this.turnstileVerificationService = turnstileVerificationService;
        this.workspaceService = workspaceService;
        this.passwordSetupCookieService = passwordSetupCookieService;
        this.publicEndpointRateLimiter = publicEndpointRateLimiter;
    }

    @PostMapping("/demo-requests")
    public ResponseEntity<DemoRequestReceiptResponse> createRequest(
            @Valid @RequestBody DemoRequestCreateRequest request,
            HttpServletRequest servletRequest
    ) {
        publicEndpointRateLimiter.checkRegistration(servletRequest, request.email());
        turnstileVerificationService.verifyDemoRequest(request.captchaToken(), publicEndpointRateLimiter.clientIp(servletRequest));
        try {
            TenantContext.runAsPreAuthentication(() -> demoLifecycleService.createRequest(request));
        } catch (DuplicateDemoRequestException ignored) {
            // Deliberately indistinguishable from a new request to prevent email enumeration.
        }
        return ResponseEntity.accepted().body(DemoRequestReceiptResponse.received());
    }

    @GetMapping("/platform/demo-requests")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public List<DemoRequestResponse> listRequests() {
        return demoLifecycleService.listRequests();
    }

    @PostMapping("/platform/demo-requests/{requestId}/approve")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public DemoRequestResponse approve(
            @PathVariable UUID requestId,
            @RequestBody(required = false) DemoRequestApprovalRequest request
    ) {
        return demoLifecycleService.approve(
                requestId,
                requestActorService.currentActor().userId(),
                request != null && request.addDemoData());
    }

    @PostMapping("/platform/demo-requests/{requestId}/reject")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public DemoRequestResponse reject(
            @PathVariable UUID requestId,
            @Valid @RequestBody(required = false) DemoRequestDecisionRequest request
    ) {
        return demoLifecycleService.reject(
                requestId,
                request == null ? null : request.reason(),
                requestActorService.currentActor().userId());
    }

    @PostMapping("/platform/demo-requests/{requestId}/resend-invite")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public DemoInviteResponse resendInvite(@PathVariable UUID requestId) {
        return demoLifecycleService.resendInvite(requestId);
    }

    @PostMapping("/platform/demo-requests/{requestId}/issue-setup-link")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public DemoSetupLinkResponse issueSetupLink(@PathVariable UUID requestId) {
        return demoLifecycleService.issueSetupLink(requestId, requestActorService.currentActor().userId());
    }

    @DeleteMapping("/platform/demo-requests/{requestId}")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public void deleteRequest(@PathVariable UUID requestId) {
        demoLifecycleService.deleteRequest(requestId, requestActorService.currentActor().userId());
    }

    @PostMapping("/demo-invites/validate")
    public DemoInviteValidationResponse validateInvite(@Valid @RequestBody InvitationTokenRequest body, HttpServletRequest request) {
        String token = body.token();
        publicEndpointRateLimiter.checkInvite(request, token);
        return TenantContext.runAsPreAuthentication(() -> demoLifecycleService.validateInvite(token));
    }

    @PostMapping("/demo-invites/accept")
    public DemoInviteValidationResponse acceptInvite(
            @Valid @RequestBody InvitationTokenRequest body,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String token = body.token();
        publicEndpointRateLimiter.checkInvite(request, token);
        DemoInviteValidationResponse result = TenantContext.runAsPreAuthentication(() -> demoLifecycleService.acceptInvite(token));
        passwordSetupCookieService.write(response, result.setupToken());
        return result;
    }

    @GetMapping("/demo-invites/{token}")
    public void legacyValidate() { throw new ResponseStatusException(HttpStatus.GONE, "Request a new invitation link"); }

    @PostMapping("/demo-invites/{token}/accept")
    public void legacyAccept() { throw new ResponseStatusException(HttpStatus.GONE, "Request a new invitation link"); }

    @GetMapping("/demo/status")
    public DemoStatusResponse demoStatus() {
        return demoLifecycleService.statusForTenant(workspaceService.getWorkspace());
    }
}
