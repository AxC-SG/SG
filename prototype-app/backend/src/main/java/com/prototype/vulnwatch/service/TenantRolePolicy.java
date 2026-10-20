package com.prototype.vulnwatch.service;

import java.util.Locale;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/** Keeps customer membership roles separate from platform and machine authority. */
public final class TenantRolePolicy {

    private static final Set<String> ROLES = Set.of(
            "TENANT_ADMIN", "INVENTORY_ADMIN", "SECURITY_ANALYST", "READ_ONLY_AUDITOR");

    private TenantRolePolicy() {
    }

    public static String forAssignment(String value) {
        return requireTenantRole(value, HttpStatus.BAD_REQUEST);
    }

    public static String forAuthorization(String value) {
        return requireTenantRole(value, HttpStatus.FORBIDDEN);
    }

    static String canonicalRole(String value) {
        if (value == null) {
            return "";
        }
        String role = value.trim().toUpperCase(Locale.ROOT).replace('-', '_').replace(' ', '_');
        while (role.startsWith("ROLE_")) {
            role = role.substring("ROLE_".length());
        }
        return role;
    }

    private static String requireTenantRole(String value, HttpStatus status) {
        String role = canonicalRole(value);
        if (!ROLES.contains(role)) {
            throw new ResponseStatusException(status, "Unsupported tenant role");
        }
        return role;
    }
}
