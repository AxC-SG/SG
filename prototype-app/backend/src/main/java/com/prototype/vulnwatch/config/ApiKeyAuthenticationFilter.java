package com.prototype.vulnwatch.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import com.prototype.vulnwatch.service.AuthenticatedTenantActor;
import com.prototype.vulnwatch.service.JwtTenantAuthenticationService;
import com.prototype.vulnwatch.service.ManagedBrowserAuthService;
import com.prototype.vulnwatch.controller.ManagedBrowserAuthController;
import com.prototype.vulnwatch.service.TenantContext;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class ApiKeyAuthenticationFilter extends OncePerRequestFilter {
    public static final String VERIFIED_HEADER_AUTH="scout.verified-header-auth";

    @Value("${app.security.api-key:}")
    private String configuredApiKey;
    @Value("${app.security.creator-key:}")
    private String configuredCreatorKey;
    @Value("${app.security.allow-api-key-auth:true}")
    private boolean allowApiKeyAuth;
    @Value("${app.security.default-user-id:local-analyst}")
    private String configuredDefaultUserId;
    private final ObjectProvider<JwtDecoder> jwtDecoderProvider;
    private final ObjectProvider<JwtTenantAuthenticationService> jwtTenantAuthenticationServiceProvider;
    private ManagedBrowserAuthService managedBrowserAuth;

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    void setManagedBrowserAuth(ManagedBrowserAuthService managedBrowserAuth) {
        this.managedBrowserAuth = managedBrowserAuth;
    }

    public ApiKeyAuthenticationFilter(
            ObjectProvider<JwtDecoder> jwtDecoderProvider,
            ObjectProvider<JwtTenantAuthenticationService> jwtTenantAuthenticationServiceProvider
    ) {
        this.jwtDecoderProvider = jwtDecoderProvider;
        this.jwtTenantAuthenticationServiceProvider = jwtTenantAuthenticationServiceProvider;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        boolean protectedActuatorEndpoint = path.startsWith("/actuator/")
                && !"/actuator/health".equals(path)
                && !path.startsWith("/actuator/health/")
                && !"/actuator/info".equals(path);
        // A BOM ingest key was already authenticated by BomIngestKeyAuthenticationFilter.
        if (request.getAttribute(BomIngestKeyAuthenticationFilter.AUTHENTICATED) != null) {
            return true;
        }
        if (managedBrowserAuth != null && Set.of(ManagedBrowserAuthController.LOGIN_PATH,
                ManagedBrowserAuthController.CALLBACK_PATH, ManagedBrowserAuthController.LOGOUT_PATH,
                ManagedBrowserAuthController.INVITATION_PATH).contains(path)) {
            return true;
        }
        return (!path.startsWith("/api/") && !protectedActuatorEndpoint)
                || "/api/auth/login".equals(path)
                || "/api/auth/setup-password".equals(path)
                || "/api/auth/setup-session".equals(path)
                || "/api/auth/csrf".equals(path)
                || ("/api/demo-requests".equals(path) && "POST".equalsIgnoreCase(request.getMethod()))
                || path.startsWith("/api/demo-invites/")
                || path.startsWith("/api/tenant-invites/");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            filterChain.doFilter(request, response);
            return;
        }

        String authorization = request.getHeader("Authorization");
        // JWT and API-key are two independent authentication paths. A Bearer token
        // intentionally bypasses the API-key check; if JWT validation fails the
        // request is rejected before reaching filterChain.doFilter.
        if (authorization != null && !authorization.isBlank()) {
            if (!authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
                reject(response, "Unsupported authorization scheme");
                return;
            }
            if (!authenticateJwt(authorization.substring(7).trim(), request, response)) {
                return;
            }
            try {
                filterChain.doFilter(request, response);
            } finally {
                TenantContext.clear();
            }
            return;
        }

        if (managedBrowserAuth != null) {
            var session = org.springframework.web.util.WebUtils.getCookie(request, ManagedBrowserAuthService.SESSION_COOKIE);
            if (session != null) {
                AuthenticatedTenantActor actor;
                try {
                    actor = managedBrowserAuth.authenticate(session.getValue(),
                            request.getHeader(ManagedBrowserAuthService.WORKSPACE_HEADER), request.getRequestURI());
                } catch (ResponseStatusException ex) {
                    reject(response, ex.getStatusCode().value(), "Managed session or workspace was rejected");
                    return;
                }
                try {
                    installActor(actor);
                    response.setHeader("Cache-Control", "no-store");
                    filterChain.doFilter(request, response);
                } finally {
                    TenantContext.clear();
                }
                return;
            }
        }

        String providedApiKey = request.getHeader("X-API-Key");
        if (!allowApiKeyAuth) {
            reject(response, "JWT authentication is required");
            return;
        }
        if (configuredApiKey == null || configuredApiKey.isBlank()) {
            reject(response, "API key is not configured");
            return;
        }

        if (!constantTimeEquals(configuredApiKey, providedApiKey)) {
            reject(response, "Unauthorized");
            return;
        }

        // If creator key is not configured, keep operations workspace available in local/dev mode.
        // When a creator key is configured, callers must provide matching X-Creator-Key.
        boolean creator = !hasText(configuredCreatorKey)
                || constantTimeEquals(configuredCreatorKey, request.getHeader("X-Creator-Key"));
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority("ROLE_OPERATOR"));
        authorities.add(new SimpleGrantedAuthority("ROLE_SECURITY_ANALYST"));
        if (creator) {
            authorities.add(new SimpleGrantedAuthority("ROLE_CREATOR"));
            authorities.add(new SimpleGrantedAuthority("ROLE_PLATFORM_OWNER"));
            authorities.add(new SimpleGrantedAuthority("ROLE_TENANT_ADMIN"));
            authorities.add(new SimpleGrantedAuthority("ROLE_INVENTORY_ADMIN"));
        }
        String headerUserId = request.getHeader("X-User-ID");
        String resolvedUserId = hasText(headerUserId) ? headerUserId.trim() : configuredDefaultUserId;
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                resolvedUserId,
                null,
                authorities);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setAttribute(VERIFIED_HEADER_AUTH,Boolean.TRUE);
        MDC.put(RequestCorrelationFilter.ACTOR_ID_MDC_KEY, resolvedUserId);
        MDC.put(RequestCorrelationFilter.ACTOR_ROLES_MDC_KEY, authorities.stream()
                .map(SimpleGrantedAuthority::getAuthority)
                .collect(Collectors.joining(",")));
        try {
            filterChain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }

    private boolean authenticateJwt(String token, HttpServletRequest request, HttpServletResponse response) throws IOException {
        JwtDecoder jwtDecoder = jwtDecoderProvider.getIfAvailable();
        JwtTenantAuthenticationService jwtTenantAuthenticationService = jwtTenantAuthenticationServiceProvider.getIfAvailable();
        if (jwtDecoder == null || jwtTenantAuthenticationService == null) {
            reject(response, "JWT authentication is not configured");
            return false;
        }
        try {
            Jwt jwt = jwtDecoder.decode(token);
            AuthenticatedTenantActor actor = managedBrowserAuth == null
                    ? jwtTenantAuthenticationService.authenticate(jwt, request.getRequestURI())
                    : jwtTenantAuthenticationService.authenticate(jwt, request.getRequestURI(), true);
            installActor(actor);
            request.setAttribute(VERIFIED_HEADER_AUTH, Boolean.TRUE);
            return true;
        } catch (JwtException ex) {
            reject(response, "Invalid JWT");
            return false;
        } catch (ResponseStatusException ex) {
            reject(response, ex.getStatusCode().value(), ex.getReason() == null ? "Unauthorized" : ex.getReason());
            return false;
        }
    }

    private void installActor(AuthenticatedTenantActor actor) {
        List<SimpleGrantedAuthority> authorities = actor.roles().stream()
                .map(role -> role.startsWith("ROLE_") ? role : "ROLE_" + role)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toCollection(ArrayList::new));
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                actor.subject(),
                null,
                authorities);
        authentication.setDetails(new TenantAuthenticationDetails(
                actor.tenantId(),
                actor.tenantName(),
                actor.subject(),
                actor.email(),
                actor.displayName(),
                Set.copyOf(actor.roles()),
                actor.accessMode(),
                actor.accessReferenceId(),
                actor.accessExpiresAt()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        TenantContext.setCurrentTenantId(actor.tenantId());
        TenantContext.setCurrentSchemaName(actor.tenantSchemaName());
        MDC.put(RequestCorrelationFilter.ACTOR_ID_MDC_KEY, actor.subject());
        MDC.put(RequestCorrelationFilter.TENANT_ID_MDC_KEY, actor.tenantId() == null ? "" : actor.tenantId().toString());
        MDC.put(RequestCorrelationFilter.ACTOR_ROLES_MDC_KEY, String.join(",", actor.roles()));
    }

    private boolean constantTimeEquals(String left, String right) {
        if (left == null || right == null) {
            return false;
        }
        return MessageDigest.isEqual(
                left.getBytes(StandardCharsets.UTF_8),
                right.getBytes(StandardCharsets.UTF_8));
    }

    private void reject(HttpServletResponse response, String message) throws IOException {
        reject(response, HttpServletResponse.SC_UNAUTHORIZED, message);
    }

    private void reject(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"error\":\"" + message + "\"}");
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }
}
