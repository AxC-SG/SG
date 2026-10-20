package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.TenantInviteValidationResponse;
import com.prototype.vulnwatch.dto.InvitationTokenRequest;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantUserInviteService;
import com.prototype.vulnwatch.security.PasswordSetupCookieService;
import com.prototype.vulnwatch.security.PublicEndpointRateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/tenant-invites")
public class TenantInviteController {

    private final TenantUserInviteService tenantUserInviteService;
    private final PasswordSetupCookieService passwordSetupCookieService;
    private final PublicEndpointRateLimiter publicEndpointRateLimiter;

    public TenantInviteController(
            TenantUserInviteService tenantUserInviteService,
            PasswordSetupCookieService passwordSetupCookieService,
            PublicEndpointRateLimiter publicEndpointRateLimiter
    ) {
        this.tenantUserInviteService = tenantUserInviteService;
        this.passwordSetupCookieService = passwordSetupCookieService;
        this.publicEndpointRateLimiter = publicEndpointRateLimiter;
    }

    @PostMapping("/validate")
    public TenantInviteValidationResponse validate(@Valid @RequestBody InvitationTokenRequest body, HttpServletRequest request) {
        String token = body.token();
        publicEndpointRateLimiter.checkInvite(request, token);
        return TenantContext.runAsPreAuthentication(() -> tenantUserInviteService.validateInvite(token));
    }

    @PostMapping("/accept")
    public TenantInviteValidationResponse accept(
            @Valid @RequestBody InvitationTokenRequest body,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        String token = body.token();
        publicEndpointRateLimiter.checkInvite(request, token);
        TenantInviteValidationResponse result = TenantContext.runAsPreAuthentication(() -> tenantUserInviteService.acceptInvite(token));
        passwordSetupCookieService.write(response, result.setupToken());
        return result;
    }
    @GetMapping("/{token}")
    public void legacyValidate() { throw new ResponseStatusException(HttpStatus.GONE, "Request a new invitation link"); }

    @PostMapping("/{token}/accept")
    public void legacyAccept() { throw new ResponseStatusException(HttpStatus.GONE, "Request a new invitation link"); }
}
