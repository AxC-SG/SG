package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.AuthLoginRequest;
import com.prototype.vulnwatch.dto.AuthSetupPasswordRequest;
import com.prototype.vulnwatch.dto.AuthSetupSessionRequest;
import com.prototype.vulnwatch.dto.AuthTenantContextRequest;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import com.prototype.vulnwatch.service.LocalCredentialAuthService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.security.PasswordSetupCookieService;
import com.prototype.vulnwatch.security.PublicEndpointRateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.security.Principal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.http.ResponseEntity;

@RestController
@RequestMapping("/api/auth")
public class LocalAuthController {

    private final LocalCredentialAuthService localCredentialAuthService;
    private final PasswordSetupCookieService passwordSetupCookieService;
    private final PublicEndpointRateLimiter publicEndpointRateLimiter;

    public LocalAuthController(
            LocalCredentialAuthService localCredentialAuthService,
            PasswordSetupCookieService passwordSetupCookieService,
            PublicEndpointRateLimiter publicEndpointRateLimiter
    ) {
        this.localCredentialAuthService = localCredentialAuthService;
        this.passwordSetupCookieService = passwordSetupCookieService;
        this.publicEndpointRateLimiter = publicEndpointRateLimiter;
    }

    @PostMapping("/login")
    public AuthTokenResponse login(@Valid @RequestBody AuthLoginRequest request, HttpServletRequest servletRequest) {
        publicEndpointRateLimiter.checkLogin(servletRequest, request.email());
        return localCredentialAuthService.login(request.email(), request.password());
    }

    @GetMapping("/csrf")
    public java.util.Map<String, String> csrf(CsrfToken token, HttpServletResponse response) {
        passwordSetupCookieService.noStore(response);
        return java.util.Map.of("headerName", token.getHeaderName(), "token", token.getToken());
    }

    @PostMapping("/setup-password")
    public AuthTokenResponse setupPassword(
            @CookieValue(name = PasswordSetupCookieService.COOKIE_NAME, required = false) String setupToken,
            @Valid @RequestBody AuthSetupPasswordRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse response
    ) {
        requireSetupHeader(servletRequest);
        publicEndpointRateLimiter.checkPasswordSetup(servletRequest, setupToken);
        AuthTokenResponse result = TenantContext.runAsPreAuthentication(
                () -> localCredentialAuthService.setupPassword(setupToken, request.password()));
        passwordSetupCookieService.clear(response);
        return result;
    }

    @PostMapping("/setup-session")
    public ResponseEntity<Void> startSetupSession(
            @Valid @RequestBody AuthSetupSessionRequest request,
            HttpServletRequest servletRequest,
            HttpServletResponse response
    ) {
        requireSetupHeader(servletRequest);
        publicEndpointRateLimiter.checkSetupSession(servletRequest, request.setupToken());
        String sessionToken = TenantContext.runAsPreAuthentication(
                () -> localCredentialAuthService.exchangePasswordSetupToken(request.setupToken()));
        passwordSetupCookieService.write(response, sessionToken);
        return ResponseEntity.noContent().build();
    }

    private void requireSetupHeader(HttpServletRequest request) {
        if (!"1".equals(request.getHeader("X-Scout-Setup"))) {
            throw new org.springframework.web.server.ResponseStatusException(
                    org.springframework.http.HttpStatus.BAD_REQUEST,
                    "Password setup request is invalid");
        }
    }

    @PostMapping("/tenant-context")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public AuthTokenResponse switchTenantContext(
            Principal principal,
            @Valid @RequestBody AuthTenantContextRequest request
    ) {
        return localCredentialAuthService.switchTenantContext(principal.getName(), request.tenantId());
    }

    @DeleteMapping("/tenant-context")
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    public AuthTokenResponse clearTenantContext(Principal principal) {
        return localCredentialAuthService.clearTenantContext(principal.getName());
    }
}
