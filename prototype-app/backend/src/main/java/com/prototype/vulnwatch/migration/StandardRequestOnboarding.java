package com.prototype.vulnwatch.migration;

import java.sql.Connection;
import java.sql.SQLException;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;

/** Exit-once handoff for a platform owner's approved request in the SG Internal queue. */
final class StandardRequestOnboarding {
    private static final String APPROVED = "STANDARD_APPROVED";
    private static final String PROVISIONING_FAILED = "STANDARD_PROVISIONING_FAILED";
    private static final String WORKSPACE_ACTIVE = "STANDARD_WORKSPACE_ACTIVE";
    private static final String ADMIN_LINKED = "STANDARD_ADMIN_LINKED";
    private static final String EMAIL_FAILED = "STANDARD_SETUP_FAILED";
    private static final String EMAIL_SUBMITTED = "STANDARD_SETUP_SUBMITTED";

    private StandardRequestOnboarding() { }

    enum Action { PROVISION, LINK_ADMIN, RECORD_EMAIL, RECORD_EMAIL_FAILURE }

    record Command(Action action, UUID requestId, UUID subject, UUID providerRequestId) {
        static Command parse(String[] args) {
            if (args.length == 0) return null;
            Action action = switch (args[0]) {
                case "--provision-standard-request" -> Action.PROVISION;
                case "--link-standard-admin" -> Action.LINK_ADMIN;
                case "--record-standard-setup-email" -> Action.RECORD_EMAIL;
                case "--record-standard-setup-failure" -> Action.RECORD_EMAIL_FAILURE;
                default -> null;
            };
            if (action == null) return null;
            int count = switch (action) {
                case PROVISION -> 2;
                case LINK_ADMIN, RECORD_EMAIL_FAILURE -> 3;
                case RECORD_EMAIL -> 4;
            };
            if (args.length != count) throw new IllegalArgumentException("Invalid Standard onboarding command arguments");
            return new Command(action, uuid(args[1]), count >= 3 ? uuid(args[2]) : null, count == 4 ? uuid(args[3]) : null);
        }

        private static UUID uuid(String value) {
            if (!value.matches("[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")) {
                throw new IllegalArgumentException("Standard onboarding identifiers must be UUIDs");
            }
            return UUID.fromString(value);
        }
    }

    record ApprovedRequest(UUID id, String company, String email, String stage, UUID tenantId) {
        StandardTenantEnrollment.Request workspace() {
            String prefix = company.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9]+", "-").replaceAll("(^-|-$)", "");
            if (prefix.length() > 80) prefix = prefix.substring(0, 80).replaceFirst("-$", "");
            return StandardTenantEnrollment.Request.parse(new String[]{"--provision-standard", id.toString(),
                    (prefix.isEmpty() ? "workspace" : prefix) + "-" + id, company});
        }
    }

    static ApprovedRequest load(Connection connection, UUID id) throws SQLException {
        try (var statement = connection.prepareStatement("""
                select company, email, bootstrap_status, tenant_id
                from tenant_default.demo_requests
                where id = ? and decided_at is not null and decided_by is not null
                  and status in ('QUEUED', 'SENT')
                for update
                """)) {
            statement.setObject(1, id);
            try (var row = statement.executeQuery()) {
                if (row.next()) {
                    String stage = row.getString("bootstrap_status");
                    UUID tenantId = row.getObject("tenant_id", UUID.class);
                    if (stage != null && (Set.of(APPROVED, PROVISIONING_FAILED).contains(stage) && tenantId == null
                            || Set.of(WORKSPACE_ACTIVE, ADMIN_LINKED, EMAIL_FAILED, EMAIL_SUBMITTED).contains(stage) && id.equals(tenantId))) {
                        return new ApprovedRequest(id, row.getString("company"), row.getString("email"), stage, tenantId);
                    }
                }
            }
        }
        throw new IllegalStateException("Standard onboarding requires an approved request and its original workspace");
    }

    static void recordProvisioning(Connection connection, ApprovedRequest request, boolean active) throws SQLException {
        if (request.tenantId() != null) return;
        try (var statement = connection.prepareStatement("""
                update tenant_default.demo_requests set tenant_id = ?, bootstrap_status = ?
                where id = ? and status = 'QUEUED' and tenant_id is null
                  and bootstrap_status in ('STANDARD_APPROVED', 'STANDARD_PROVISIONING_FAILED')
                """)) {
            statement.setObject(1, active ? request.id() : null);
            statement.setString(2, active ? WORKSPACE_ACTIVE : PROVISIONING_FAILED);
            statement.setObject(3, request.id());
            if (statement.executeUpdate() != 1) throw new SQLException("Standard approval changed during provisioning");
        }
    }

    static void finish(Connection connection, Command command, String issuer, int tenantVersion) throws SQLException {
        connection.setAutoCommit(false);
        try {
            var request = load(connection, command.requestId());
            verifyActiveWorkspace(connection, request, tenantVersion);
            if (command.action() == Action.LINK_ADMIN && WORKSPACE_ACTIVE.equals(request.stage())) {
                createAdmin(connection, request, issuer, command.subject());
                advance(connection, request, ADMIN_LINKED, "QUEUED", "STANDARD_ADMIN_LINKED", null);
            } else {
                if (!Set.of(ADMIN_LINKED, EMAIL_FAILED, EMAIL_SUBMITTED).contains(request.stage())) {
                    throw new IllegalStateException("Link the approved administrator before recording setup email");
                }
                verifyAdmin(connection, request, issuer, command.subject());
                if (command.action() == Action.RECORD_EMAIL && !EMAIL_SUBMITTED.equals(request.stage())) {
                    advance(connection, request, EMAIL_SUBMITTED, "SENT", "STANDARD_SETUP_SUBMITTED", command.providerRequestId());
                } else if (command.action() == Action.RECORD_EMAIL_FAILURE && ADMIN_LINKED.equals(request.stage())) {
                    advance(connection, request, EMAIL_FAILED, "QUEUED", "STANDARD_SETUP_FAILED", null);
                }
            }
            connection.commit();
        } catch (SQLException failure) {
            connection.rollback();
            throw new IllegalStateException("Standard administrator handoff failed in the database", failure);
        } catch (RuntimeException failure) {
            connection.rollback();
            throw failure;
        } finally {
            connection.setAutoCommit(true);
        }
    }

    private static void verifyActiveWorkspace(Connection connection, ApprovedRequest request, int version) throws SQLException {
        try (var statement = connection.prepareStatement("""
                select 1 from platform.tenants t
                join platform.tenant_schema_versions v on v.tenant_id = t.id
                where t.id = ? and t.schema_name = ? and t.classification = 'CUSTOMER'
                  and t.status = 'ACTIVE' and t.deleted_at is null and t.purged_at is null
                  and v.status = 'CURRENT' and v.current_version = ? and v.target_version = ?
                for share of t, v
                """)) {
            statement.setObject(1, request.tenantId());
            statement.setString(2, request.workspace().schema());
            statement.setInt(3, version);
            statement.setInt(4, version);
            try (var row = statement.executeQuery()) {
                if (!row.next()) throw new IllegalStateException("Standard workspace must be active and current before enrollment");
            }
        }
    }

    private static void createAdmin(Connection connection, ApprovedRequest request, String issuer, UUID subject) throws SQLException {
        try (var lock = connection.createStatement()) {
            lock.execute("lock table platform.app_users in share row exclusive mode");
        }
        try (var statement = connection.prepareStatement("""
                select 1 from platform.app_users where lower(email) = ? or external_subject = ?
                """)) {
            statement.setString(1, request.email());
            statement.setString(2, request.email());
            try (var row = statement.executeQuery()) {
                if (row.next()) throw new IllegalStateException("Approved email already belongs to a ScoutGrid identity");
            }
        }
        UUID userId = ProductionBootstrapCli.reconcileIdentity(connection, request.email(), request.email(), false, request.tenantId());
        ManagedOperatorEnrollment.bind(connection, issuer, subject.toString(), userId);
        verifyAdmin(connection, request, issuer, subject);
    }

    private static void verifyAdmin(Connection connection, ApprovedRequest request, String issuer, UUID subject) throws SQLException {
        try (var statement = connection.prepareStatement("""
                select 1 from platform.managed_identities i
                join platform.app_users u on u.id = i.user_id
                join platform.tenant_memberships m on m.user_id = u.id
                where i.issuer = ? and i.subject = ? and u.external_subject = ? and lower(u.email) = ?
                  and not u.platform_owner and u.status = 'ACTIVE'
                  and u.password_hash is null and u.password_setup_token_hash is null
                  and m.tenant_id = ? and m.role = 'TENANT_ADMIN' and m.status = 'ACTIVE'
                  and m.provenance = 'INSTALLATION_BOOTSTRAP'
                  and not exists (select 1 from platform.app_user_global_roles r where r.app_user_id = u.id)
                for share of i, u, m
                """)) {
            statement.setString(1, issuer);
            statement.setString(2, subject.toString());
            statement.setString(3, request.email());
            statement.setString(4, request.email());
            statement.setObject(5, request.tenantId());
            try (var row = statement.executeQuery()) {
                if (!row.next()) throw new IllegalStateException("Existing Standard administrator does not match the approved identity");
            }
        }
    }

    private static void advance(Connection connection, ApprovedRequest request, String stage, String status,
                                String action, UUID providerRequestId) throws SQLException {
        try (var update = connection.prepareStatement("""
                update tenant_default.demo_requests set bootstrap_status = ?, status = ? where id = ?
                """);
             var audit = connection.prepareStatement("""
                insert into platform.intelligence_audit_events(id, action, actor, detail)
                values (?, ?, 'system:standard-onboarding', jsonb_build_object(
                    'requestId', ?::text, 'tenantId', ?::text, 'providerRequestId', ?::text))
                """)) {
            update.setString(1, stage);
            update.setString(2, status);
            update.setObject(3, request.id());
            update.executeUpdate();
            audit.setObject(1, UUID.randomUUID());
            audit.setString(2, action);
            audit.setObject(3, request.id());
            audit.setObject(4, request.tenantId());
            audit.setObject(5, providerRequestId);
            audit.executeUpdate();
        }
    }
}
