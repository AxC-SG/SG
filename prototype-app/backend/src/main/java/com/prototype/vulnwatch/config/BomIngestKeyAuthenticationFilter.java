package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.BomApiIngestService;
import com.prototype.vulnwatch.service.BomIngestApiKeyService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantLifecycleGuardService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Set;
import org.slf4j.MDC;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

/**
 * Authenticates a pipeline's BOM ingest key (an {@code Authorization: Bearer sgk_...} token).
 *
 * <p>It runs ahead of {@link ApiKeyAuthenticationFilter}, which would otherwise try to read the
 * token as a JWT. A key is accepted only on the ingest endpoints; anywhere else it is refused, so a
 * leaked key can push BOMs and cannot read or change anything else. Every other request, including
 * every non-key Bearer token, passes through untouched.
 */
@Component
public class BomIngestKeyAuthenticationFilter extends OncePerRequestFilter {

    /** Request attribute set once this filter has authenticated the request. */
    public static final String AUTHENTICATED = "scout.bom-ingest-key-authenticated";

    private static final String INGEST_PATH = "/api/bom/ingest";

    // Resolved lazily, like ApiKeyAuthenticationFilter's dependencies, so an application slice
    // that has no ingest-key storage still starts; a key then simply cannot authenticate there.
    private final ObjectProvider<BomIngestApiKeyService> keysProvider;
    private final ObjectProvider<TenantRepository> tenantsProvider;
    private final ObjectProvider<TenantLifecycleGuardService> lifecycleProvider;

    public BomIngestKeyAuthenticationFilter(
            ObjectProvider<BomIngestApiKeyService> keysProvider,
            ObjectProvider<TenantRepository> tenantsProvider,
            ObjectProvider<TenantLifecycleGuardService> lifecycleProvider) {
        this.keysProvider = keysProvider;
        this.tenantsProvider = tenantsProvider;
        this.lifecycleProvider = lifecycleProvider;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getRequestURI().startsWith("/api/") || bearerKey(request) == null;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (!isIngestRequest(request)) {
            write(response, HttpServletResponse.SC_FORBIDDEN, "KEY_SCOPE",
                    "An ingest key can only be used on the BOM ingest endpoints.");
            return;
        }
        BomIngestApiKeyService keys = keysProvider.getIfAvailable();
        TenantRepository tenants = tenantsProvider.getIfAvailable();
        TenantLifecycleGuardService lifecycle = lifecycleProvider.getIfAvailable();
        if (keys == null || tenants == null || lifecycle == null) {
            write(response, HttpServletResponse.SC_UNAUTHORIZED, "INVALID_KEY",
                    "Ingest key authentication is not configured.");
            return;
        }
        var principal = keys.authenticate(bearerKey(request));
        if (principal.isEmpty()) {
            write(response, HttpServletResponse.SC_UNAUTHORIZED, "INVALID_KEY",
                    "The ingest key is invalid, expired or revoked.");
            return;
        }
        Tenant tenant = TenantContext.runAsPlatform(() -> tenants.findById(principal.get().tenantId()).orElse(null));
        try {
            lifecycle.assertTenantAccessible(tenant);
        } catch (ResponseStatusException ex) {
            write(response, ex.getStatusCode().value(), "TENANT_UNAVAILABLE", ex.getReason());
            return;
        }

        String userId = "ingest-key:" + principal.get().keyPrefix();
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                userId, null, List.of(new SimpleGrantedAuthority("ROLE_" + BomApiIngestService.KEY_ROLE)));
        // No access mode, like the local API-key actor: SensitiveTenantActionInterceptor treats a
        // mode it does not know as a support session and refuses writes. The key is already
        // confined to the ingest endpoints above, so it needs no wider tenant-access semantics.
        authentication.setDetails(new TenantAuthenticationDetails(
                tenant.getId(), tenant.getName(), userId, null, principal.get().name(),
                Set.of(BomApiIngestService.KEY_ROLE), null, principal.get().keyId(), null));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        request.setAttribute(ApiKeyAuthenticationFilter.VERIFIED_HEADER_AUTH, Boolean.TRUE);
        request.setAttribute(AUTHENTICATED, Boolean.TRUE);
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
        MDC.put(RequestCorrelationFilter.ACTOR_ID_MDC_KEY, userId);
        MDC.put(RequestCorrelationFilter.TENANT_ID_MDC_KEY, tenant.getId().toString());
        MDC.put(RequestCorrelationFilter.ACTOR_ROLES_MDC_KEY, BomApiIngestService.KEY_ROLE);
        try {
            chain.doFilter(request, response);
        } finally {
            TenantContext.clear();
        }
    }

    private static boolean isIngestRequest(HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();
        if (INGEST_PATH.equals(path)) {
            return "POST".equalsIgnoreCase(method);
        }
        return "GET".equalsIgnoreCase(method) && path.startsWith(INGEST_PATH + "/") && path.endsWith("/status");
    }

    /** The token when the Authorization header is a Bearer token shaped like an ingest key, else null. */
    private static String bearerKey(HttpServletRequest request) {
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = authorization.substring(7).trim();
        return token.startsWith(BomIngestApiKeyService.TOKEN_PREFIX) ? token : null;
    }

    private static void write(HttpServletResponse response, int status, String code, String message)
            throws IOException {
        response.setStatus(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"code\":\"" + code + "\",\"error\":\""
                + (message == null ? "" : message.replace("\"", "'")) + "\"}");
    }
}
