package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase.DatabaseConfig;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class ManagedOperatorEnrollmentPostgresIntegrationTest {
    private static final String RUNTIME_ROLE = "scout_runtime_managed_operator_it";
    private static final String RUNTIME_PASSWORD = "managed-operator-fixture-" + UUID.randomUUID();

    @Test
    void initialInstallAndRetryPreserveRoleSeparationAndDoNotRestoreRevocation() throws Exception {
        var database = LocalPostgresTestDatabase.provision("managed_operator_enrollment");
        var input = ManagedOperatorEnrollmentTest.inputs();
        bootstrap(database, input);
        bootstrap(database, input);

        try (Connection owner = connect(database)) {
            assertEquals(1, query(owner, "select count(*) from platform.managed_operator_enrollment"));
            assertEquals(2, query(owner, """
                    select count(*) from platform.managed_identities i
                    join platform.app_users u on u.id = i.user_id
                    where i.issuer = ? and u.password_hash is null and u.password_setup_token_hash is null
                    """, input.get("APP_MANAGED_INSTALLATION_ISSUER")));
            assertEquals(1, query(owner, """
                    select count(*) from platform.managed_identities i
                    join platform.app_user_global_roles r on r.app_user_id = i.user_id
                    where i.subject = 'owner-subject' and r.role = 'PLATFORM_OWNER'
                    """));
            assertEquals(1, query(owner, """
                    select count(*) from platform.managed_identities i
                    join platform.tenant_memberships m on m.user_id = i.user_id
                    join platform.tenants t on t.id = m.tenant_id
                    where i.subject = 'admin-subject' and t.classification = 'INTERNAL'
                      and m.role = 'TENANT_ADMIN' and m.status = 'ACTIVE'
                    """));
            assertEquals(1, query(owner, """
                    select count(*) from platform.intelligence_audit_events
                    where action = 'INSTALLATION_VERIFIED' and detail->>'mode' = 'COGNITO'
                    """));
            assertEquals(0, query(owner, "select count(*) from platform.invitation_email_outbox"));
        }
        try (Connection runtime = DriverManager.getConnection(database.url(), RUNTIME_ROLE, RUNTIME_PASSWORD);
             var statement = runtime.createStatement()) {
            assertEquals(2, query(runtime, "select count(*) from platform.managed_identities"));
            assertEquals(0, query(runtime, "select count(*) from platform.managed_operator_enrollment"));
            assertEquals(0, statement.executeUpdate("delete from platform.managed_operator_enrollment"));
        }

        var changed = new HashMap<>(input);
        changed.put("APP_MANAGED_INSTALLATION_OWNER_SUBJECT", "different-owner-subject");
        assertThrows(RuntimeException.class, () -> bootstrap(database, changed));
        try (Connection owner = connect(database); var statement = owner.createStatement()) {
            statement.executeUpdate("delete from platform.managed_identities where subject = 'owner-subject'");
            statement.executeUpdate("update platform.tenant_memberships set status = 'REVOKED'");
        }
        assertThrows(RuntimeException.class, () -> bootstrap(database, input));

        assertThrows(RuntimeException.class, () -> bootstrap(database, Map.of(
                "APP_PLATFORM_OWNER_BOOTSTRAP_ENABLED", "true",
                "APP_SECURITY_BOOTSTRAP_PLATFORM_OWNERS_USERS_0_EMAIL", "owner@example.test",
                "SG_INTERNAL_ADMIN_EMAIL", "admin@example.test",
                "APP_CREDENTIAL_ENCRYPTION_KEY", java.util.Base64.getEncoder().encodeToString(new byte[32]))));
        bootstrap(database, Map.of());
        try (Connection owner = connect(database)) {
            assertEquals(1, query(owner, "select count(*) from platform.managed_identities"));
            assertEquals(1, query(owner, "select count(*) from platform.managed_operator_enrollment"));
            assertEquals(1, query(owner, "select count(*) from platform.tenant_memberships where status = 'REVOKED'"));
            assertEquals(0, query(owner, "select count(*) from platform.invitation_email_outbox"));
        }
    }

    @Test
    void failedSecondBindingRollsBackBothOperatorsAndRefusesAnExistingAccount() throws Exception {
        var database = LocalPostgresTestDatabase.provision("managed_operator_enrollment_failure");
        var input = ManagedOperatorEnrollmentTest.inputs();
        bootstrap(database, Map.of());
        try (Connection owner = connect(database); var statement = owner.createStatement()) {
            statement.execute("""
                    create function platform.fail_admin_binding() returns trigger language plpgsql as $$
                    begin
                        if new.subject = 'admin-subject' then
                            raise exception 'private-enrollment-fixture';
                        end if;
                        return new;
                    end $$;
                    create trigger fail_admin_binding before insert on platform.managed_identities
                        for each row execute function platform.fail_admin_binding();
                    """);
        }
        var failure = assertThrows(RuntimeException.class, () -> bootstrap(database, input));
        assertTrue(failure.getMessage().contains("Managed operator enrollment"));
        assertFalse(failure.getMessage().contains("private-enrollment-fixture"));
        try (Connection owner = connect(database); var statement = owner.createStatement()) {
            assertEquals(0, query(owner, "select count(*) from platform.app_users"));
            assertEquals(0, query(owner, "select count(*) from platform.managed_identities"));
            assertEquals(0, query(owner, "select count(*) from platform.managed_operator_enrollment"));
            statement.execute("drop trigger fail_admin_binding on platform.managed_identities");
            statement.execute("""
                    insert into platform.app_users (id, external_subject, email, status, platform_owner, created_at, updated_at)
                    values (gen_random_uuid(), 'owner@example.test', 'owner@example.test', 'ACTIVE', false, now(), now())
                    """);
        }
        assertThrows(RuntimeException.class, () -> bootstrap(database, input));
        try (Connection owner = connect(database)) {
            assertEquals(1, query(owner, "select count(*) from platform.app_users where not platform_owner"));
            assertEquals(0, query(owner, "select count(*) from platform.managed_identities"));
        }
    }

    @Test
    void approvedRequestProvisionsOnceAndLinksOnlyItsFirstAdminBeforeSetupSubmission() throws Exception {
        var database = LocalPostgresTestDatabase.provision("managed_standard_request");
        var input = new HashMap<>(ManagedOperatorEnrollmentTest.inputs());
        input.put("APP_STANDARD_CUSTOMER_LIMIT", "3");
        bootstrap(database, input);
        var runtime = Map.of("APP_STANDARD_CUSTOMER_LIMIT", "3",
                "APP_JWT_ISSUER_URI", input.get("APP_MANAGED_INSTALLATION_ISSUER"));
        UUID request = UUID.randomUUID();
        UUID subject = UUID.randomUUID();
        UUID providerRequest = UUID.randomUUID();
        var provision = new String[]{"--provision-standard-request", request.toString()};
        var link = new String[]{"--link-standard-admin", request.toString(), subject.toString()};
        var email = new String[]{"--record-standard-setup-email", request.toString(), subject.toString(), providerRequest.toString()};
        try (Connection owner = connect(database)) {
            try (var insert = owner.prepareStatement("""
                    insert into tenant_default.demo_requests(id, company, email, full_name, status, requested_at)
                    values (?, 'Orchard Systems', 'first-admin@example.test', 'First Admin', 'PENDING', now())
                    """)) {
                insert.setObject(1, request);
                insert.executeUpdate();
            }
            assertThrows(RuntimeException.class, () -> bootstrap(database, runtime, provision));
            assertEquals(0, query(owner, "select count(*) from platform.tenants where classification = 'CUSTOMER'"));
            try (var approve = owner.prepareStatement("""
                    update tenant_default.demo_requests set status = 'QUEUED', bootstrap_status = 'STANDARD_APPROVED',
                        decided_by = 'owner@example.test', decided_at = now() where id = ?
                    """)) {
                approve.setObject(1, request);
                approve.executeUpdate();
            }
            assertThrows(RuntimeException.class, () -> bootstrap(database, runtime, link));
            bootstrap(database, runtime, provision);
            bootstrap(database, runtime, provision);
            assertEquals(1, query(owner, """
                    select count(*) from tenant_default.demo_requests
                    where id = ? and tenant_id = id and bootstrap_status = 'STANDARD_WORKSPACE_ACTIVE'
                    """, request));
            assertThrows(RuntimeException.class, () -> bootstrap(database, runtime, email));
            bootstrap(database, runtime, link);
            bootstrap(database, runtime, link);
            assertThrows(RuntimeException.class, () -> bootstrap(database, runtime,
                    "--link-standard-admin", request.toString(), UUID.randomUUID().toString()));
            bootstrap(database, runtime, "--record-standard-setup-failure", request.toString(), subject.toString());
            assertEquals(1, query(owner, """
                    select count(*) from tenant_default.demo_requests
                    where id = ? and status = 'QUEUED' and bootstrap_status = 'STANDARD_SETUP_FAILED'
                    """, request));
            bootstrap(database, runtime, email);
            bootstrap(database, runtime, email);
            assertEquals(1, query(owner, """
                    select count(*) from platform.managed_identities i
                    join platform.app_users u on u.id = i.user_id
                    join platform.tenant_memberships m on m.user_id = u.id
                    where i.subject = ? and u.email = 'first-admin@example.test'
                      and u.password_hash is null and not u.platform_owner
                      and m.tenant_id = ? and m.role = 'TENANT_ADMIN' and m.status = 'ACTIVE'
                    """, subject.toString(), request));
            assertEquals(1, query(owner, """
                    select count(*) from tenant_default.demo_requests
                    where id = ? and status = 'SENT' and bootstrap_status = 'STANDARD_SETUP_SUBMITTED'
                    """, request));
            assertEquals(1, query(owner, """
                    select count(*) from platform.intelligence_audit_events
                    where action = 'STANDARD_SETUP_SUBMITTED' and detail->>'providerRequestId' = ?
                    """, providerRequest.toString()));
            assertEquals(0, query(owner, "select count(*) from tenant_default.demo_invites"));
        }
    }

    private void bootstrap(DatabaseConfig database, Map<String, String> inputs, String... args) throws Exception {
        var settings = new HashMap<>(Map.of(
                "DB_URL", database.url(), "DB_USERNAME", database.username(), "DB_PASSWORD", database.password(),
                "RUNTIME_DB_USERNAME", RUNTIME_ROLE, "RUNTIME_DB_PASSWORD", RUNTIME_PASSWORD));
        settings.putAll(inputs);
        var original = new HashMap<String, String>();
        settings.forEach((name, value) -> original.put(name, System.setProperty(name, value)));
        try {
            ProductionBootstrapCli.main(args);
        } finally {
            original.forEach((name, value) -> {
                if (value == null) System.clearProperty(name);
                else System.setProperty(name, value);
            });
        }
    }

    private Connection connect(DatabaseConfig database) throws Exception {
        return DriverManager.getConnection(database.url(), database.username(), database.password());
    }

    private int query(Connection connection, String sql, Object... parameters) throws Exception {
        try (var statement = connection.prepareStatement(sql)) {
            for (int i = 0; i < parameters.length; i++) {
                statement.setObject(i + 1, parameters[i]);
            }
            try (var result = statement.executeQuery()) {
                result.next();
                return result.getInt(1);
            }
        }
    }
}
