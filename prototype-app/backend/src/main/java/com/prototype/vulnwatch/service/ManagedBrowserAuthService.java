package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.http.CognitoBrowserIdentityClient;
import jakarta.annotation.PostConstruct;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
@ConditionalOnProperty(name = "app.security.managed-auth.enabled", havingValue = "true")
public class ManagedBrowserAuthService {
    public static final String SESSION_COOKIE = "__Host-sg-session";
    public static final String LOGIN_COOKIE = "__Host-sg-login";
    public static final String WORKSPACE_HEADER = "X-Scout-Workspace";

    private static final Set<String> WORKSPACE_OPTIONAL = Set.of(
            "/api/me", "/api/auth/context", "/api/auth/authorized-workspaces");
    // Platform-owner routes the platform console calls before a workspace is selected. Their
    // services serve platform-scope data when the actor has no tenant (global feeds, EOL catalog,
    // platform-user audit, AI framework registry); tenant-bound routes stay workspace-only.
    private static final Set<String> PLATFORM_SCOPE_ROUTES = Set.of(
            "/api/tenants", "/api/auth/support-grants", "/api/audit-events/platform-users",
            "/api/sync-runs", "/api/sync-runs/sources-summary", "/api/ai-frameworks");
    private static final List<String> PLATFORM_SCOPE_PREFIXES = List.of("/api/eol/", "/api/ingestion/");
    private static final java.util.regex.Pattern ACCEPT_SUPPORT_GRANT = java.util.regex.Pattern.compile(
            "/api/auth/support-grants/[0-9a-fA-F-]{36}/accept");
    private final SecureRandom random = new SecureRandom();
    private final ManagedBrowserSessionStore store;
    private final CognitoBrowserIdentityClient provider;
    private final ManagedTenantInviteService invites;
    private final AppUserGlobalRoleService globalRoles;
    private final TenantAccessResolutionService tenantAccess;

    ManagedBrowserAuthService(ManagedBrowserSessionStore store, CognitoBrowserIdentityClient provider,
                              ManagedTenantInviteService invites, AppUserGlobalRoleService globalRoles,
                              TenantAccessResolutionService tenantAccess) {
        this.store = store;
        this.provider = provider;
        this.invites = invites;
        this.globalRoles = globalRoles;
        this.tenantAccess = tenantAccess;
    }

    @PostConstruct
    void checkSchema() {
        TenantContext.runAsPlatform(store::checkSchema);
    }

    public Login begin() {
        return begin(null);
    }

    public Login beginInvitation(String token) {
        return begin(InvitationTokens.hash(token));
    }

    private Login begin(String inviteHash) {
        String state = randomToken();
        String browser = randomToken();
        String verifier = randomToken();
        String nonce = randomToken();
        TenantContext.runAsPlatform(() -> store.saveAttempt(hash(state), hash(browser), verifier, nonce, inviteHash));
        String challenge = Base64.getUrlEncoder().withoutPadding().encodeToString(digest(verifier));
        return new Login(provider.authorizationUri(state, nonce, challenge), browser);
    }

    public Session complete(String state, String browser, String code, String previousSession) {
        if (!isToken(state) || !isToken(browser)) {
            throw unauthorized();
        }
        var attempt = TenantContext.runAsPlatform(() -> store.consumeAttempt(hash(state), hash(browser)))
                .orElseThrow(ManagedBrowserAuthService::unauthorized);
        if (code == null || code.isBlank() || code.length() > 2048) {
            throw unauthorized();
        }
        var identity = provider.exchange(code, attempt.verifier(), attempt.nonce());
        if (attempt.inviteHash() != null) {
            return invites.accept(attempt.inviteHash(), provider.issuer(), identity, () -> issueSession(identity, previousSession));
        }
        return TenantContext.runAsPlatform(() -> issueSession(identity, previousSession));
    }

    private Session issueSession(CognitoBrowserIdentityClient.Identity identity, String previousSession) {
        String token = randomToken();
        Instant expiry = store.createSession(hash(token), isToken(previousSession) ? hash(previousSession) : null,
                        provider.issuer(), identity.subject(), identity.expiresAt())
                .orElseThrow(ManagedBrowserAuthService::unauthorized);
        return new Session(token, expiry);
    }

    public AuthenticatedTenantActor authenticate(String token, String workspace, String requestUri) {
        if (!isToken(token)) {
            throw unauthorized();
        }
        return TenantContext.runAsPlatform(() -> {
            var user = store.findUser(hash(token), provider.issuer()).orElseThrow(ManagedBrowserAuthService::unauthorized);
            return resolveActor(user, workspace, requestUri);
        });
    }

    private AuthenticatedTenantActor resolveActor(ManagedBrowserSessionStore.SessionUser user, String workspace, String uri) {
        Set<String> roles = new LinkedHashSet<>(globalRoles.rolesForUser(user.id()));
        TenantAccessResolution access = null;
        if (workspace != null) {
            access = tenantAccess.resolve(user.subject(), workspaceId(workspace));
            if (!access.mode().isSupport()) {
                roles.add(TenantRolePolicy.forAuthorization(access.role()));
            }
        } else {
            boolean platformPath = uri.startsWith("/api/platform/") || uri.startsWith("/api/operations/")
                    || PLATFORM_SCOPE_ROUTES.contains(uri) || PLATFORM_SCOPE_PREFIXES.stream().anyMatch(uri::startsWith)
                    || ACCEPT_SUPPORT_GRANT.matcher(uri).matches();
            if (!WORKSPACE_OPTIONAL.contains(uri) && !(platformPath && roles.contains("PLATFORM_OWNER"))) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Select an authorized workspace for this request");
            }
        }
        var tenant = access == null ? null : access.tenant();
        return new AuthenticatedTenantActor(
                user.subject(), user.id(), user.email(), user.displayName(),
                tenant == null ? null : tenant.getId(), tenant == null ? null : tenant.getName(),
                tenant == null ? null : tenant.getSchemaName(), Set.copyOf(roles),
                access == null ? null : access.mode(), access == null ? null : access.referenceId(),
                access == null ? null : access.expiresAt());
    }

    public void logout(String token) {
        if (isToken(token)) {
            TenantContext.runAsPlatform(() -> store.revoke(hash(token)));
        }
    }

    private static UUID workspaceId(String value) {
        try {
            UUID id = UUID.fromString(value);
            if (id.toString().equals(value)) {
                return id;
            }
        } catch (IllegalArgumentException invalid) {
            // Return the same response for all malformed workspace IDs.
        }
        throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Workspace header must be a tenant UUID");
    }

    private String randomToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static boolean isToken(String token) {
        return token != null && token.matches("[A-Za-z0-9_-]{43}");
    }

    private static byte[] digest(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 is unavailable", impossible);
        }
    }

    private static String hash(String value) {
        return HexFormat.of().formatHex(digest(value));
    }

    private static ResponseStatusException unauthorized() {
        return new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Managed sign-in is required");
    }

    public record Login(URI authorizationUri, String browser) { }
    public record Session(String token, Instant expiry) { }
}
