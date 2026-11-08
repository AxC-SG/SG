package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;

@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class StandardTenantEnrollmentPostgresIntegrationTest {

    private static final String RUNTIME_ROLE = "scout_standard_enrollment_it";
    private static final String RUNTIME_PASSWORD = "standard-fixture-" + UUID.randomUUID();

    @Test
    void reservesOnceRecoversFromFailedActivationAndEnforcesThePilotLimit() throws Exception {
        var database = LocalPostgresTestDatabase.provision("standard_enrollment");
        var settings = Map.of(
                "DB_URL", database.url(), "DB_USERNAME", database.username(), "DB_PASSWORD", database.password(),
                "RUNTIME_DB_USERNAME", RUNTIME_ROLE, "RUNTIME_DB_PASSWORD", RUNTIME_PASSWORD,
                "APP_STANDARD_RUNTIME_DB_CONNECTION_LIMIT", "2",
                "APP_STANDARD_CUSTOMER_LIMIT", "3");
        var previous = new HashMap<String, String>();
        settings.forEach((key, value) -> previous.put(key, System.setProperty(key, value)));
        try (Connection owner = DriverManager.getConnection(database.url(), database.username(), database.password())) {
            ProductionBootstrapCli.main(new String[0]);
            try (Connection first = DriverManager.getConnection(database.url(), RUNTIME_ROLE, RUNTIME_PASSWORD);
                 Connection second = DriverManager.getConnection(database.url(), RUNTIME_ROLE, RUNTIME_PASSWORD)) {
                assertEquals("53300", assertThrows(SQLException.class, () ->
                        DriverManager.getConnection(database.url(), RUNTIME_ROLE, RUNTIME_PASSWORD)).getSQLState());
                assertEquals(2, count(owner, "select rolconnlimit from pg_roles where rolname = '" + RUNTIME_ROLE + "'"));
            }
            assertEquals(1, count(owner, "select count(*) from platform.tenants where classification = 'INTERNAL'"));

            var first = request("first");
            var orphan = request("orphan");
            execute(owner, "create schema " + orphan.schema());
            assertThrows(RuntimeException.class, () -> provision(orphan));
            assertEquals(1, count(owner, "select count(*) from pg_namespace where nspname = '" + orphan.schema() + "'"));
            assertEquals(0, count(owner, "select count(*) from platform.tenants where classification = 'CUSTOMER'"));

            execute(owner, """
                    create function platform.reject_fixture_activation() returns trigger language plpgsql as $$
                    begin
                        if NEW.status = 'ACTIVE' and OLD.status = 'PROVISIONING' then
                            raise exception 'fixture activation interrupted';
                        end if;
                        return NEW;
                    end;
                    $$;
                    create trigger reject_fixture_activation before update on platform.tenants
                        for each row execute function platform.reject_fixture_activation();
                    """);
            var failure = assertThrows(RuntimeException.class, () -> provision(first));
            assertTrue(failure.getMessage().contains("fixture activation interrupted"));
            assertEquals(1, count(owner, """
                    select count(*) from platform.tenants t
                    join platform.tenant_schema_versions v on v.tenant_id = t.id
                    where t.status = 'PROVISIONING_FAILED' and v.status = 'PROVISIONING_FAILED'
                        and v.current_version = 0
                    """));
            assertEquals(1, count(owner, "select count(*) from " + first.schema()
                    + ".tenant_schema_history where version = '20' and success"));

            try (Connection runtime = DriverManager.getConnection(database.url(), RUNTIME_ROLE, RUNTIME_PASSWORD)) {
                assertEquals(0, execute(runtime, "update platform.standard_enrollment_policy set customer_limit = 10"));
                assertEquals("42501", assertThrows(SQLException.class, () -> execute(runtime,
                        "update platform.tenants set status = 'ACTIVE' where slug = 'first'")).getSQLState());
                assertEquals("42501", assertThrows(SQLException.class, () -> execute(runtime,
                        "delete from platform.tenants where slug = 'first'")).getSQLState());
                assertEquals("42501", assertThrows(SQLException.class, () -> execute(runtime, """
                        insert into platform.tenants
                            (id, name, slug, schema_name, status, plan_code, created_at, updated_at,
                             max_connector_count, max_service_account_count, max_daily_sbom_uploads,
                             max_export_rows, max_daily_exposure_refreshes)
                        values (gen_random_uuid(), 'Unreserved', 'unreserved', 'tenant_unreserved',
                            'PROVISIONING', 'PRO', now(), now(), 10, 25, 100, 50000, 25)
                        """)).getSQLState());
            }

            execute(owner, "drop trigger reject_fixture_activation on platform.tenants");
            assertEquals(2, concurrentEnrollments(List.of(request("second"), request("third"), request("fourth"))));
            assertEquals(2, count(owner, "select count(*) from platform.tenants where classification = 'CUSTOMER' and status = 'ACTIVE'"));
            provision(first);
            provision(first);
            assertEquals(3, count(owner, "select count(*) from platform.tenants where classification = 'CUSTOMER' and status = 'ACTIVE'"));
            assertEquals(1, count(owner, "select count(*) from " + first.schema()
                    + ".tenant_schema_history where version = '20' and success"));
            var conflicting = new StandardTenantEnrollment.Request(first.id(), first.slug(), "Conflicting retry");
            assertThrows(RuntimeException.class, () -> provision(conflicting));
            System.setProperty("APP_STANDARD_CUSTOMER_LIMIT", "10");
            assertThrows(RuntimeException.class, () -> ProductionBootstrapCli.main(new String[0]));
            assertThrows(RuntimeException.class, () -> provision(request("stale-limit")));
            assertEquals(3, count(owner, "select customer_limit from platform.standard_enrollment_policy"));
            assertEquals(4, count(owner, "select count(*) from platform.tenants"));
        } finally {
            previous.forEach((key, value) -> {
                if (value == null) {
                    System.clearProperty(key);
                } else {
                    System.setProperty(key, value);
                }
            });
        }
    }

    private int concurrentEnrollments(List<StandardTenantEnrollment.Request> requests) throws Exception {
        var start = new CountDownLatch(1);
        var executor = Executors.newFixedThreadPool(requests.size());
        try {
            var results = requests.stream().map(request -> executor.submit(() -> {
                start.await();
                try {
                    provision(request);
                    return 1;
                } catch (RuntimeException ex) {
                    assertTrue(ex.getMessage().contains("enrollment limit reached"), ex.getMessage());
                    return 0;
                }
            })).toList();
            start.countDown();
            int enrolled = 0;
            for (var result : results) {
                enrolled += result.get(90, TimeUnit.SECONDS);
            }
            return enrolled;
        } finally {
            executor.shutdownNow();
        }
    }

    private static StandardTenantEnrollment.Request request(String slug) {
        return new StandardTenantEnrollment.Request(UUID.randomUUID(), slug, slug + " customer");
    }

    private static void provision(StandardTenantEnrollment.Request request) throws Exception {
        ProductionBootstrapCli.main(new String[]{"--provision-standard", request.id().toString(), request.slug(), request.name()});
    }

    private static int count(Connection connection, String sql) throws SQLException {
        try (var statement = connection.createStatement(); var row = statement.executeQuery(sql)) {
            row.next();
            return row.getInt(1);
        }
    }

    private static int execute(Connection connection, String sql) throws SQLException {
        try (var statement = connection.createStatement()) {
            return statement.executeUpdate(sql);
        }
    }
}
