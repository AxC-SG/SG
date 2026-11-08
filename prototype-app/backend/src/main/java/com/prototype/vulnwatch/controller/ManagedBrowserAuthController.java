package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.dto.InvitationTokenRequest;
import com.prototype.vulnwatch.security.PublicEndpointRateLimiter;
import com.prototype.vulnwatch.service.ManagedBrowserAuthService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
@ConditionalOnProperty(name = "app.security.managed-auth.enabled", havingValue = "true")
public class ManagedBrowserAuthController {
    public static final String LOGIN_PATH = "/api/auth/managed/login";
    public static final String CALLBACK_PATH = "/api/auth/callback";
    public static final String INVITATION_PATH = "/api/auth/managed/invitation";
    public static final String LOGOUT_PATH = "/api/auth/managed/logout";

    private final ManagedBrowserAuthService auth;
    private final PublicEndpointRateLimiter limiter;
    private final URI frontend;

    public ManagedBrowserAuthController(ManagedBrowserAuthService auth, PublicEndpointRateLimiter limiter,
                                       @Value("${app.cors.allowed-origins:}") String frontendOrigin) {
        if (!frontendOrigin.matches("https://[a-z0-9.-]+")) {
            throw new IllegalStateException("Managed sign-in requires one explicit HTTPS frontend origin.");
        }
        this.auth = auth;
        this.limiter = limiter;
        this.frontend = URI.create(frontendOrigin + "/");
    }

    @GetMapping(LOGIN_PATH)
    public ResponseEntity<Void> login(HttpServletRequest request, HttpServletResponse response) {
        noStore(response);
        limiter.checkManagedSignIn(request);
        var login = auth.begin();
        writeCookie(response, ManagedBrowserAuthService.LOGIN_COOKIE, login.browser(), Duration.ofMinutes(5));
        return ResponseEntity.status(HttpStatus.SEE_OTHER).location(login.authorizationUri()).build();
    }

    @PostMapping(INVITATION_PATH)
    public Map<String, URI> startInvitation(@Valid @RequestBody InvitationTokenRequest invitation,
                                            HttpServletRequest request, HttpServletResponse response) {
        noStore(response);
        limiter.checkManagedSignIn(request);
        limiter.checkInvite(request, invitation.token());
        var login = auth.beginInvitation(invitation.token());
        writeCookie(response, ManagedBrowserAuthService.LOGIN_COOKIE, login.browser(), Duration.ofMinutes(5));
        return Map.of("authorizationUrl", login.authorizationUri());
    }

    @GetMapping(CALLBACK_PATH)
    public ResponseEntity<Void> callback(
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String code,
            @CookieValue(name = ManagedBrowserAuthService.LOGIN_COOKIE, required = false) String browser,
            @CookieValue(name = ManagedBrowserAuthService.SESSION_COOKIE, required = false) String previous,
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        noStore(response);
        limiter.checkManagedSignIn(request);
        var session = auth.complete(state, browser, code, previous);
        writeCookie(response, ManagedBrowserAuthService.LOGIN_COOKIE, "", Duration.ZERO);
        writeCookie(response, ManagedBrowserAuthService.SESSION_COOKIE, session.token(),
                Duration.between(Instant.now(), session.expiry()));
        return ResponseEntity.status(HttpStatus.SEE_OTHER).location(frontend).build();
    }

    @PostMapping(LOGOUT_PATH)
    public ResponseEntity<Void> logout(
            @CookieValue(name = ManagedBrowserAuthService.SESSION_COOKIE, required = false) String token,
            HttpServletResponse response
    ) {
        noStore(response);
        auth.logout(token);
        writeCookie(response, ManagedBrowserAuthService.LOGIN_COOKIE, "", Duration.ZERO);
        writeCookie(response, ManagedBrowserAuthService.SESSION_COOKIE, "", Duration.ZERO);
        return ResponseEntity.noContent().build();
    }

    private static void noStore(HttpServletResponse response) {
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");
        response.setHeader("Referrer-Policy", "no-referrer");
    }

    private static void writeCookie(HttpServletResponse response, String name, String value, Duration lifetime) {
        response.addHeader(HttpHeaders.SET_COOKIE, ResponseCookie.from(name, value)
                .httpOnly(true).secure(true).sameSite("Lax").path("/")
                .maxAge(lifetime.isNegative() ? Duration.ZERO : lifetime).build().toString());
    }
}
