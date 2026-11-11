package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.AuthTokenResponse;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
public class AuthTokenService {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private final String hmacSecret;
    private final long tokenTtlMinutes;
    private final String activeTenantIdClaim;
    private final boolean requireProductionSecrets;
    private final boolean sharedLocalhostLoginEnabled;
    private final String corsAllowedOrigins;
    private final AppUserGlobalRoleService globalRoleService;
    @Value("${app.security.jwt.mode:LOCAL}")
    private String jwtMode = "LOCAL";
    @Value("${app.security.jwt.local-issuer:urn:scoutgrid:local}")
    private String localIssuer = "urn:scoutgrid:local";
    @Value("${app.security.jwt.audience:scoutgrid-api}")
    private String audience = "scoutgrid-api";

    @Autowired
    public AuthTokenService(
            @Value("${app.security.jwt.hmac-secret:}") String hmacSecret,
            @Value("${app.security.jwt.token-ttl-minutes:480}") long tokenTtlMinutes,
            @Value("${app.security.jwt.active-tenant-id-claim:active_tenant_id}") String activeTenantIdClaim,
            @Value("${app.security.require-production-secrets:false}") boolean requireProductionSecrets,
            @Value("${app.security.local-auth.shared-localhost-login-enabled:false}") boolean sharedLocalhostLoginEnabled,
            @Value("${app.cors.allowed-origins:}") String corsAllowedOrigins,
            AppUserGlobalRoleService globalRoleService
    ) {
        this.hmacSecret = hmacSecret;
        this.tokenTtlMinutes = tokenTtlMinutes;
        this.activeTenantIdClaim = activeTenantIdClaim;
        this.requireProductionSecrets = requireProductionSecrets;
        this.sharedLocalhostLoginEnabled = sharedLocalhostLoginEnabled;
        this.corsAllowedOrigins = corsAllowedOrigins;
        this.globalRoleService = globalRoleService;
    }

    AuthTokenService(String hmacSecret, long tokenTtlMinutes, String activeTenantIdClaim,
            boolean requireProductionSecrets, boolean sharedLocalhostLoginEnabled, String corsAllowedOrigins) {
        this(hmacSecret, tokenTtlMinutes, activeTenantIdClaim, requireProductionSecrets,
                sharedLocalhostLoginEnabled, corsAllowedOrigins, null);
    }

    AuthTokenService(String hmacSecret, long tokenTtlMinutes, String activeTenantIdClaim) {
        this(
                hmacSecret,
                tokenTtlMinutes,
                activeTenantIdClaim,
                false,
                true,
                "http://localhost:5173,http://127.0.0.1:5173"
        );
    }

    public AuthTokenResponse issueToken(AppUser user, Set<String> roles, Tenant activeTenant) {
        return issueToken(user, roles, activeTenant, null);
    }

    public AuthTokenResponse issueToken(
            AppUser user,
            Set<String> roles,
            Tenant activeTenant,
            TenantAccessResolution access
    ) {
        requireIssuerConfigured();
        Set<String> authorizedRoles = validateRoles(user, roles, activeTenant, access);
        Instant now = Instant.now();
        Instant expiresAt = now.plus(Math.max(1, tokenTtlMinutes), ChronoUnit.MINUTES);
        return new AuthTokenResponse(
                signToken(user, authorizedRoles, activeTenant, access, now, expiresAt),
                "Bearer",
                expiresAt);
    }

    void requireLocalMode() {
        if (!"LOCAL".equalsIgnoreCase(jwtMode)) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "Local credential token issuance is disabled in EXTERNAL JWT mode");
        }
    }

    private void requireIssuerConfigured() {
        requireLocalMode();
        if (resolvedHmacSecret().isBlank()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT, "APP_JWT_HMAC_SECRET is required for local credential login");
        }
    }

    private Set<String> validateRoles(AppUser user, Set<String> roles, Tenant tenant, TenantAccessResolution access) {
        if (user == null || !"ACTIVE".equalsIgnoreCase(user.getStatus()) || roles == null || roles.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Current authorization is required");
        }
        Set<String> normalized = roles.stream().map(TenantRolePolicy::canonicalRole)
                .collect(java.util.stream.Collectors.toSet());
        boolean currentOwner = globalRoleService == null ? user.isPlatformOwner()
                : globalRoleService.rolesForUser(user.getId()).contains("PLATFORM_OWNER");
        if (normalized.contains("PLATFORM_OWNER") && !currentOwner) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Current platform-owner access is required");
        }
        if (tenant == null) {
            if (!normalized.equals(Set.of("PLATFORM_OWNER"))) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Platform tokens require platform-owner access");
            }
        } else {
            if (access == null || access.mode() == null || access.referenceId() == null
                    || access.tenant() == null || !tenant.getId().equals(access.tenant().getId())) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant-bound tokens require resolved authorization");
            }
            if (access.mode().isSupport()) {
                if (!normalized.equals(Set.of("PLATFORM_OWNER")) || !currentOwner) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Support tokens require platform-owner access");
                }
            } else {
                String membershipRole = TenantRolePolicy.forAuthorization(access.role());
                Set<String> expected = normalized.contains("PLATFORM_OWNER")
                        ? Set.of("PLATFORM_OWNER", membershipRole) : Set.of(membershipRole);
                if (!normalized.equals(expected)) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Token roles must match current tenant authorization");
                }
            }
        }
        return normalized;
    }

    private String signToken(
            AppUser user,
            Set<String> roles,
            Tenant activeTenant,
            TenantAccessResolution access,
            Instant issuedAt,
            Instant expiresAt
    ) {
        try {
            String header = json(Map.of("alg", "HS256", "typ", "JWT"));
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("sub", user.getExternalSubject());
            claims.put("iss", localIssuer);
            claims.put("aud", List.of(audience));
            claims.put("token_use", "access");
            if (user.getEmail() != null && !user.getEmail().isBlank()) {
                claims.put("email", user.getEmail());
            }
            if (user.getDisplayName() != null && !user.getDisplayName().isBlank()) {
                claims.put("name", user.getDisplayName());
            }
            claims.put("roles", roles);
            claims.put("iat", issuedAt.getEpochSecond());
            claims.put("exp", expiresAt.getEpochSecond());
            if (activeTenant != null) {
                claims.put(activeTenantIdClaim, activeTenant.getId().toString());
                if (access == null) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Tenant-bound tokens require resolved authorization");
                }
                claims.put("tenant_access_mode", access.mode().name());
                claims.put("tenant_access_ref", access.referenceId().toString());
                if (access.expiresAt() != null) {
                    claims.put("tenant_access_expires_at", access.expiresAt().toString());
                }
            }
            String unsigned = base64Url(header.getBytes(StandardCharsets.UTF_8))
                    + "."
                    + base64Url(json(claims).getBytes(StandardCharsets.UTF_8));
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(resolvedHmacSecret().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            return unsigned + "." + base64Url(mac.doFinal(unsigned.getBytes(StandardCharsets.UTF_8)));
        } catch (ResponseStatusException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to issue login token");
        }
    }

    private String json(Object value) throws Exception {
        return MAPPER.writeValueAsString(value);
    }

    private String base64Url(byte[] value) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(value);
    }

    private String resolvedHmacSecret() {
        if (hmacSecret != null && !hmacSecret.isBlank()) {
            return hmacSecret;
        }
        return "";
    }

    private boolean isSharedLocalhostEnvironment() {
        if (requireProductionSecrets || !sharedLocalhostLoginEnabled) {
            return false;
        }
        if (corsAllowedOrigins == null || corsAllowedOrigins.isBlank()) {
            return false;
        }
        return List.of(corsAllowedOrigins.split(",")).stream()
                .map(String::trim)
                .filter(origin -> !origin.isBlank())
                .allMatch(this::isLoopbackOrigin);
    }

    private boolean isLoopbackOrigin(String origin) {
        try {
            URI uri = URI.create(origin);
            return isLoopbackHost(uri.getHost());
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private boolean isLoopbackHost(String host) {
        if (host == null || host.isBlank()) {
            return false;
        }
        String normalized = host.trim().toLowerCase(Locale.ROOT);
        return "localhost".equals(normalized)
                || "127.0.0.1".equals(normalized)
                || "::1".equals(normalized)
                || "[::1]".equals(normalized);
    }
}
