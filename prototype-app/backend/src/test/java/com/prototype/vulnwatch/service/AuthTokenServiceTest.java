package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.AppUser;
import com.prototype.vulnwatch.domain.Tenant;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

class AuthTokenServiceTest {

    @Test
    void localhostLoopbackConfigStillRequiresExplicitSecret() {
        AuthTokenService service = new AuthTokenService(
                "",
                60,
                "active_tenant_id",
                false,
                true,
                "http://localhost:5173,http://127.0.0.1:5173"
        );

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.issueToken(user("owner@example.com"), Set.of("PLATFORM_OWNER"), null)
        );
        assertEquals(HttpStatus.CONFLICT, error.getStatusCode());
    }

    @Test
    void nonLoopbackConfigStillRequiresExplicitSecret() {
        AuthTokenService service = new AuthTokenService(
                "",
                60,
                "active_tenant_id",
                false,
                true,
                "https://app.example.com"
        );

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.issueToken(user("owner@example.com"), Set.of("PLATFORM_OWNER"), null)
        );

        assertEquals(HttpStatus.CONFLICT, error.getStatusCode());
        assertEquals("APP_JWT_HMAC_SECRET is required for local credential login", error.getReason());
    }

    @Test
    void productionModeStillRequiresExplicitSecret() {
        AuthTokenService service = new AuthTokenService(
                "",
                60,
                "active_tenant_id",
                true,
                true,
                "http://localhost:5173"
        );

        ResponseStatusException error = assertThrows(
                ResponseStatusException.class,
                () -> service.issueToken(user("owner@example.com"), Set.of("PLATFORM_OWNER"), null)
        );

        assertEquals(HttpStatus.CONFLICT, error.getStatusCode());
    }

    @Test
    void validTenantRoleIsCanonicalizedAndBoundToResolvedMembership() throws Exception {
        Tenant tenant = tenant();
        UUID membershipId = UUID.randomUUID();
        TenantAccessResolution access = new TenantAccessResolution(
                tenant, TenantAccessMode.TENANT_MEMBERSHIP, membershipId, "role-role-security-analyst", null);

        String token = issuer().issueToken(user("analyst@example.com"), Set.of("security analyst"), tenant, access).token();
        Map<String, Object> claims = claims(token);

        assertEquals(Set.of("SECURITY_ANALYST"), new HashSet<>((List<?>) claims.get("roles")));
        assertEquals(tenant.getId().toString(), claims.get("active_tenant_id"));
        assertEquals("TENANT_MEMBERSHIP", claims.get("tenant_access_mode"));
        assertEquals(membershipId.toString(), claims.get("tenant_access_ref"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"PLATFORM_OWNER", "ROLE_ROLE_PLATFORM_OWNER", "CREATOR", "SERVICE_ACCOUNT", "OPERATOR", "unknown", ""})
    void tenantIssuerRejectsInvalidStoredMembershipRole(String role) {
        AppUser user = user("invalid-membership@example.com");
        user.setPlatformOwner(true);
        Tenant tenant = tenant();
        TenantAccessResolution access = new TenantAccessResolution(
                tenant, TenantAccessMode.TENANT_MEMBERSHIP, UUID.randomUUID(), role, null);

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> issuer().issueToken(user, Set.of("READ_ONLY_AUDITOR"), tenant, access));

        assertEquals(HttpStatus.FORBIDDEN, error.getStatusCode());
    }

    @Test
    void tenantIssuerRejectsRequestedRoleThatExceedsCurrentMembership() {
        Tenant tenant = tenant();
        TenantAccessResolution access = new TenantAccessResolution(
                tenant, TenantAccessMode.TENANT_MEMBERSHIP, UUID.randomUUID(), "READ_ONLY_AUDITOR", null);

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> issuer().issueToken(user("demoted@example.com"), Set.of("TENANT_ADMIN"), tenant, access));

        assertEquals(HttpStatus.FORBIDDEN, error.getStatusCode());
    }

    @Test
    void separatelyAuthorizedCurrentOwnerCanReceiveSelectedTenantToken() throws Exception {
        AppUser owner = user("owner@example.com");
        owner.setPlatformOwner(true);
        Tenant tenant = tenant();
        TenantAccessResolution access = new TenantAccessResolution(
                tenant, TenantAccessMode.TENANT_MEMBERSHIP, UUID.randomUUID(), "TENANT_ADMIN", null);

        String token = issuer().issueToken(owner,
                Set.of("ROLE_ROLE_PLATFORM_OWNER", "tenant-admin"), tenant, access).token();

        assertEquals(Set.of("PLATFORM_OWNER", "TENANT_ADMIN"), new HashSet<>((List<?>) claims(token).get("roles")));
        assertEquals(tenant.getId().toString(), claims(token).get("active_tenant_id"));
    }

    @Test
    void tenantMembershipCannotAuthorizeOwnerToken() {
        Tenant tenant = tenant();
        TenantAccessResolution access = new TenantAccessResolution(
                tenant, TenantAccessMode.TENANT_MEMBERSHIP, UUID.randomUUID(), "TENANT_ADMIN", null);

        ResponseStatusException error = assertThrows(ResponseStatusException.class,
                () -> issuer().issueToken(user("tenant-admin@example.com"),
                        Set.of("PLATFORM_OWNER", "TENANT_ADMIN"), tenant, access));

        assertEquals(HttpStatus.FORBIDDEN, error.getStatusCode());
    }

    @Test
    void tenantBoundTokenRequiresMatchingResolvedAuthorization() {
        Tenant tenant = tenant();
        TenantAccessResolution otherTenantAccess = new TenantAccessResolution(
                tenant(), TenantAccessMode.TENANT_MEMBERSHIP, UUID.randomUUID(), "SECURITY_ANALYST", null);

        assertThrows(ResponseStatusException.class, () -> issuer().issueToken(
                user("analyst@example.com"), Set.of("SECURITY_ANALYST"), tenant));
        assertThrows(ResponseStatusException.class, () -> issuer().issueToken(
                user("analyst@example.com"), Set.of("SECURITY_ANALYST"), tenant, otherTenantAccess));
    }

    private AuthTokenService issuer() {
        return new AuthTokenService("auth-token-regression-secret-32-bytes", 60, "active_tenant_id");
    }

    private Tenant tenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        return tenant;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> claims(String token) throws Exception {
        return new ObjectMapper().readValue(Base64.getUrlDecoder().decode(token.split("\\.")[1]), Map.class);
    }

    private AppUser user(String subject) {
        AppUser user = new AppUser();
        user.setExternalSubject(subject);
        user.setEmail(subject);
        user.setDisplayName("Test User");
        return user;
    }
}
