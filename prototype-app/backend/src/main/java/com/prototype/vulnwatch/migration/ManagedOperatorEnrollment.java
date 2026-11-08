package com.prototype.vulnwatch.migration;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.function.Function;

final class ManagedOperatorEnrollment {
    private static final String PREFIX = "APP_MANAGED_INSTALLATION_";

    private ManagedOperatorEnrollment() { }

    static Spec configured(Function<String, String> env, boolean localSetup, boolean reportOnly) {
        String enabled = env.apply(PREFIX + "ENABLED");
        String issuer = env.apply(PREFIX + "ISSUER");
        String ownerEmail = env.apply(PREFIX + "OWNER_EMAIL");
        String ownerSubject = env.apply(PREFIX + "OWNER_SUBJECT");
        String adminEmail = env.apply(PREFIX + "INTERNAL_ADMIN_EMAIL");
        String adminSubject = env.apply(PREFIX + "INTERNAL_ADMIN_SUBJECT");
        if (enabled.isBlank() || "false".equalsIgnoreCase(enabled)) {
            if (List.of(issuer, ownerEmail, ownerSubject, adminEmail, adminSubject).stream().anyMatch(value -> !value.isBlank())) {
                throw new IllegalArgumentException("Managed operator inputs require APP_MANAGED_INSTALLATION_ENABLED=true");
            }
            return null;
        }
        if (!"true".equalsIgnoreCase(enabled) || localSetup || reportOnly) {
            throw new IllegalArgumentException("Managed operator enrollment requires an enrollment run with local setup disabled");
        }
        if (!issuer.matches("https://cognito-idp\\.([a-z0-9-]+)\\.amazonaws\\.com/\\1_[A-Za-z0-9]+")) {
            throw new IllegalArgumentException("Managed operator enrollment requires a Cognito pool issuer");
        }
        Account owner = account(ownerEmail, ownerSubject);
        Account admin = account(adminEmail, adminSubject);
        if (owner.email().equals(admin.email()) || owner.subject().equals(admin.subject())) {
            throw new IllegalArgumentException("Managed operator enrollment requires distinct emails and Cognito subjects");
        }
        return new Spec(issuer, owner, admin);
    }

    private static Account account(String email, String subject) {
        String canonicalEmail = email.trim().toLowerCase(Locale.ROOT);
        if (canonicalEmail.length() > 255 || !canonicalEmail.matches("[^\\s@\\p{Cntrl}]+@[^\\s@\\p{Cntrl}]+\\.[^\\s@\\p{Cntrl}]+")
                || subject.isBlank() || subject.length() > 255 || !subject.equals(subject.trim())
                || subject.codePoints().anyMatch(Character::isISOControl)) {
            throw new IllegalArgumentException("Managed operator enrollment requires valid email aliases and Cognito subjects");
        }
        return new Account(canonicalEmail, subject);
    }

    static boolean exists(Connection connection) throws SQLException {
        try (var statement = connection.prepareStatement("select 1 from platform.managed_operator_enrollment");
             var result = statement.executeQuery()) {
            return result.next();
        }
    }

    /** Called under the production bootstrap lock and inside its identity transaction. */
    static boolean enroll(Connection connection, Spec spec, UUID tenantId) throws SQLException {
        if (exists(connection)) {
            verifyExisting(connection, spec, tenantId);
            return false;
        }

        try (var statement = connection.createStatement()) {
            statement.execute("lock table platform.app_users in share row exclusive mode");
        }
        try (var statement = connection.prepareStatement("""
                select exists(select 1 from platform.app_users)
                    or exists(select 1 from platform.tenants where id <> ?)
                    or not exists(
                        select 1 from platform.tenants where id = ? and classification = 'INTERNAL'
                        and status = 'ACTIVE' and deleted_at is null and purged_at is null
                    )
                """)) {
            statement.setObject(1, tenantId);
            statement.setObject(2, tenantId);
            try (var result = statement.executeQuery()) {
                result.next();
                if (result.getBoolean(1)) {
                    throw new IllegalStateException("First managed operator enrollment requires a fresh SG Internal installation");
                }
            }
        }

        UUID ownerId = ProductionBootstrapCli.reconcileIdentity(connection, spec.owner().email(), spec.owner().email(), true, tenantId);
        UUID adminId = ProductionBootstrapCli.reconcileIdentity(connection, spec.admin().email(), spec.admin().email(), false, tenantId);
        UUID ownerBinding = bind(connection, spec.issuer(), spec.owner().subject(), ownerId);
        UUID adminBinding = bind(connection, spec.issuer(), spec.admin().subject(), adminId);
        try (var statement = connection.prepareStatement("""
                insert into platform.managed_operator_enrollment (request_digest, tenant_id, owner_binding_id, admin_binding_id)
                values (?, ?, ?, ?)
                """)) {
            statement.setString(1, spec.digest());
            statement.setObject(2, tenantId);
            statement.setObject(3, ownerBinding);
            statement.setObject(4, adminBinding);
            statement.executeUpdate();
        }
        verifyExisting(connection, spec, tenantId);
        ProductionBootstrapCli.recordInstallationAudit(connection, tenantId, ownerId, adminId, "COGNITO");
        return true;
    }

    static UUID bind(Connection connection, String issuer, String subject, UUID userId) throws SQLException {
        try (var statement = connection.prepareStatement("""
                insert into platform.managed_identities (issuer, subject, user_id)
                values (?, ?, ?) returning id
                """)) {
            statement.setString(1, issuer);
            statement.setString(2, subject);
            statement.setObject(3, userId);
            try (var result = statement.executeQuery()) {
                result.next();
                return result.getObject(1, UUID.class);
            }
        }
    }

    private static void verifyExisting(Connection connection, Spec spec, UUID tenantId) throws SQLException {
        try (var statement = connection.prepareStatement("""
                select 1
                from platform.managed_operator_enrollment e
                join platform.tenants tenant on tenant.id = e.tenant_id
                join platform.managed_identities owner_link on owner_link.id = e.owner_binding_id
                join platform.managed_identities admin_link on admin_link.id = e.admin_binding_id
                join platform.app_users owner on owner.id = owner_link.user_id
                join platform.app_users admin on admin.id = admin_link.user_id
                where e.request_digest = ? and e.tenant_id = ?
                  and tenant.classification = 'INTERNAL' and tenant.status = 'ACTIVE'
                  and tenant.deleted_at is null and tenant.purged_at is null
                  and owner_link.issuer = ? and owner_link.subject = ? and admin_link.issuer = ? and admin_link.subject = ?
                  and owner.external_subject = ? and lower(owner.email) = owner.external_subject
                  and admin.external_subject = ? and lower(admin.email) = admin.external_subject
                  and owner.id <> admin.id and owner.status = 'ACTIVE' and admin.status = 'ACTIVE'
                  and owner.platform_owner and not admin.platform_owner
                  and not exists (
                      select 1 from platform.app_users u where u.id in (owner.id, admin.id)
                      and (u.password_hash is not null or u.password_set_at is not null
                           or u.password_setup_token_hash is not null or u.password_setup_token_expires_at is not null)
                  )
                  and exists (
                      select 1 from platform.app_user_global_roles
                      where app_user_id = owner.id and role = 'PLATFORM_OWNER'
                  )
                  and not exists (
                      select 1 from platform.app_user_global_roles
                      where app_user_id = admin.id or (app_user_id = owner.id and role <> 'PLATFORM_OWNER')
                  )
                  and exists (
                      select 1 from platform.tenant_memberships where user_id = admin.id
                      and tenant_id = e.tenant_id and role = 'TENANT_ADMIN' and status = 'ACTIVE'
                      and provenance = 'INSTALLATION_BOOTSTRAP'
                  )
                  and not exists (
                      select 1 from platform.tenant_memberships
                      where user_id = owner.id or (user_id = admin.id and tenant_id <> e.tenant_id)
                  )
                """)) {
            statement.setString(1, spec.digest());
            statement.setObject(2, tenantId);
            statement.setString(3, spec.issuer());
            statement.setString(4, spec.owner().subject());
            statement.setString(5, spec.issuer());
            statement.setString(6, spec.admin().subject());
            statement.setString(7, spec.owner().email());
            statement.setString(8, spec.admin().email());
            try (var result = statement.executeQuery()) {
                if (!result.next()) {
                    throw new IllegalStateException("Managed operator enrollment differs from the recorded installation");
                }
            }
        }
    }

    record Account(String email, String subject) { }

    record Spec(String issuer, Account owner, Account admin) {
        String digest() {
            String identity = String.join("\0", issuer, owner.email(), owner.subject(), admin.email(), admin.subject());
            try {
                return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                        .digest(identity.getBytes(StandardCharsets.UTF_8)));
            } catch (NoSuchAlgorithmException impossible) {
                throw new IllegalStateException("SHA-256 is unavailable", impossible);
            }
        }
    }
}
