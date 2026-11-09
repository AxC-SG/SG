package com.prototype.vulnwatch.service.ownership;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * The ownership authorization matrix (plan §5, design §4) in one place. Controllers call it from
 * {@code @PreAuthorize("@ownershipAuthorization.can('ACTION')")}; an unknown action is always denied.
 * Analyst workflow-scope checks (manual assignment) are additionally enforced by the service, server-side.
 */
@Component("ownershipAuthorization")
public class OwnershipAuthorization {

    public enum Action {
        VIEW_OWNERSHIP, VIEW_DIRECTORY, WRITE_DIRECTORY, IMPORT_DIRECTORY, MANAGE_ENCRYPTION, CONFIGURE_IDENTITY_SOURCE,
        CONFIGURE_OWNERSHIP_PRODUCER, WRITE_TEAMS, MAP_GROUPS, MANUAL_ASSIGN, REVOKE_ASSIGNMENT, RESOLVE_REVIEW, PAUSE_SOURCE,
        INGEST_CLAIMS, MANAGE_AUTHORITY
    }

    private static final Set<String> ADMINS = Set.of("TENANT_ADMIN", "INVENTORY_ADMIN");
    private static final Set<String> INTERACTIVE = Set.of("TENANT_ADMIN", "INVENTORY_ADMIN", "SECURITY_ANALYST", "READ_ONLY_AUDITOR");

    static final Map<Action, Set<String>> MATRIX = Map.ofEntries(
            Map.entry(Action.VIEW_OWNERSHIP, INTERACTIVE),
            Map.entry(Action.VIEW_DIRECTORY, Set.of("TENANT_ADMIN", "INVENTORY_ADMIN", "SECURITY_ANALYST")),
            Map.entry(Action.WRITE_DIRECTORY, Set.of("TENANT_ADMIN")),
            Map.entry(Action.IMPORT_DIRECTORY, Set.of("TENANT_ADMIN")),
            Map.entry(Action.MANAGE_ENCRYPTION, Set.of("TENANT_ADMIN")),
            Map.entry(Action.CONFIGURE_IDENTITY_SOURCE, Set.of("TENANT_ADMIN")),
            Map.entry(Action.CONFIGURE_OWNERSHIP_PRODUCER, ADMINS),
            Map.entry(Action.WRITE_TEAMS, ADMINS),
            Map.entry(Action.MAP_GROUPS, ADMINS),
            Map.entry(Action.MANUAL_ASSIGN, Set.of("TENANT_ADMIN", "INVENTORY_ADMIN", "SECURITY_ANALYST")),
            Map.entry(Action.REVOKE_ASSIGNMENT, ADMINS),
            Map.entry(Action.MANAGE_AUTHORITY, Set.of("TENANT_ADMIN")),
            Map.entry(Action.RESOLVE_REVIEW, ADMINS),
            Map.entry(Action.PAUSE_SOURCE, ADMINS),
            Map.entry(Action.INGEST_CLAIMS, Set.of("SERVICE_ACCOUNT")));

    public boolean can(String action) {
        Action parsed;
        try {
            parsed = Action.valueOf(action);
        } catch (IllegalArgumentException ex) {
            return false;
        }
        return allowed(parsed, currentRoles());
    }

    /** True when the caller holds an admin role rather than only analyst scope. */
    public boolean isAdmin() {
        return currentRoles().stream().anyMatch(ADMINS::contains);
    }

    public static boolean allowed(Action action, Set<String> roles) {
        return roles.stream().anyMatch(MATRIX.getOrDefault(action, Set.of())::contains);
    }

    private static Set<String> currentRoles() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) return Set.of();
        return auth.getAuthorities().stream().map(GrantedAuthority::getAuthority).filter(a -> a.startsWith("ROLE_"))
                .map(a -> a.substring("ROLE_".length())).collect(Collectors.toUnmodifiableSet());
    }
}
