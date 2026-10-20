package com.prototype.vulnwatch.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.AbstractDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Real Hikari physical reuse/eviction, including faults below the pool proxy. */
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class TenantConnectionCleanupPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("phase_two_connection_cleanup");
    private final AtomicReference<String> fault = new AtomicReference<>();
    private HikariDataSource pool;
    private TenantAwareDataSource scoped;
    private JdbcTemplate raw;
    private JdbcTemplate jdbc;
    private Tenant alpha;
    private Tenant beta;

    @BeforeEach
    void setUp() {
        HikariConfig config = new HikariConfig();
        config.setDataSource(new AbstractDataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                return physicalConnection();
            }

            @Override
            public Connection getConnection(String username, String password) throws SQLException {
                return physicalConnection();
            }
        });
        config.setMaximumPoolSize(1);
        config.setMinimumIdle(0);
        config.setConnectionTimeout(3000);
        pool = new HikariDataSource(config);
        scoped = new TenantAwareDataSource(pool, true, "tenant_alpha", null);
        raw = new JdbcTemplate(pool);
        jdbc = new JdbcTemplate(scoped);
        for (String schema : new String[]{"platform", "tenant_alpha", "tenant_beta"}) {
            raw.execute("CREATE SCHEMA IF NOT EXISTS " + schema);
            raw.execute("CREATE TABLE IF NOT EXISTS " + schema + ".scope_marker (value text)");
            raw.execute("TRUNCATE " + schema + ".scope_marker");
            raw.update("INSERT INTO " + schema + ".scope_marker VALUES (?)", schema);
        }
        alpha = tenant("tenant_alpha");
        beta = tenant("tenant_beta");
    }

    @AfterEach
    void tearDown() {
        TenantContext.clear();
        if (pool != null) {
            pool.close();
        }
    }

    @Test
    void alternatingTenantsAndPlatformRawPoolNeverInheritSessionState() {
        for (Tenant tenant : new Tenant[]{alpha, beta, alpha, beta}) {
            select(tenant);
            assertEquals(tenant.getSchemaName(), jdbc.queryForObject("SELECT value FROM scope_marker", String.class));
            assertEquals(tenant.getId().toString(), jdbc.queryForObject(
                    "SELECT current_setting('app.current_tenant_id')", String.class));
            assertRawClean();
        }
        TenantContext.runAsPlatform(() ->
                assertEquals("platform", jdbc.queryForObject("SELECT value FROM scope_marker", String.class)));
        assertRawClean();
    }

    @Test
    void failedResetPhysicallyEvictsInsteadOfReturningContaminatedSession() throws Exception {
        select(alpha);
        int before = raw.queryForObject("SELECT pg_backend_pid()", Integer.class);
        Connection connection = scoped.getConnection();
        fault.set("reset");

        assertThrows(SQLException.class, connection::close);

        assertNotEquals(before, raw.queryForObject("SELECT pg_backend_pid()", Integer.class));
        assertRawClean();
        select(beta);
        assertEquals("tenant_beta", jdbc.queryForObject("SELECT value FROM scope_marker", String.class));
    }

    @Test
    void partiallyAppliedContextPhysicallyEvictsInsteadOfLeakingItsTenant() {
        int before = raw.queryForObject("SELECT pg_backend_pid()", Integer.class);
        select(alpha);
        fault.set("context");

        assertThrows(SQLException.class, scoped::getConnection);

        assertNotEquals(before, raw.queryForObject("SELECT pg_backend_pid()", Integer.class));
        assertRawClean();
    }

    @Test
    void abortedTransactionIsDiscardedAndReplacementHasNoTenantState() throws Exception {
        int before = raw.queryForObject("SELECT pg_backend_pid()", Integer.class);
        select(alpha);
        Connection connection = scoped.getConnection();
        connection.setAutoCommit(false);
        try (Statement statement = connection.createStatement()) {
            assertThrows(SQLException.class, () -> statement.execute("SELECT 1 / 0"));
        }
        connection.close();

        assertNotEquals(before, raw.queryForObject("SELECT pg_backend_pid()", Integer.class));
        assertRawClean();
    }

    @Test
    void strictNestingKeepsBoundConnectionAndRestoresContextAfterFailure() {
        TenantSchemaService schemas = mock(TenantSchemaService.class);
        when(schemas.schemaNameForTenant(alpha)).thenReturn(alpha.getSchemaName());
        when(schemas.schemaNameForTenant(beta)).thenReturn(beta.getSchemaName());
        TenantSchemaExecutionService execution = new TenantSchemaExecutionService(mock(TenantService.class), schemas, "FAIL");
        TransactionTemplate transaction = new TransactionTemplate(new DataSourceTransactionManager(scoped));
        select(alpha);
        transaction.execute(status -> {
            assertEquals("tenant_alpha", jdbc.queryForObject("SELECT value FROM scope_marker", String.class));
            assertEquals("tenant_alpha", execution.run(alpha,
                    () -> jdbc.queryForObject("SELECT value FROM scope_marker", String.class)));
            assertThrows(IllegalStateException.class, () -> execution.run(beta, () -> "wrong tenant"));
            assertEquals("tenant_alpha", jdbc.queryForObject("SELECT value FROM scope_marker", String.class));
            return null;
        });
        TenantContext.runAsPlatform(() -> {
            assertThrows(IllegalStateException.class, () -> execution.run(beta, () -> transaction.execute(status -> {
                assertEquals("tenant_beta", jdbc.queryForObject("SELECT value FROM scope_marker", String.class));
                throw new IllegalStateException("work failed");
            })));
            assertTrue(TenantContext.isPlatformContext());
        });
        assertRawClean();
    }

    private void assertRawClean() {
        String tenant = raw.queryForObject("SELECT current_setting('app.current_tenant_id', true)", String.class);
        assertTrue(tenant == null || tenant.isEmpty());
        String path = raw.queryForObject("SHOW search_path", String.class);
        assertFalse(path.contains("tenant_alpha") || path.contains("tenant_beta") || path.equals("platform,public"));
    }

    private Tenant tenant(String schema) {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        tenant.setSchemaName(schema);
        return tenant;
    }

    private void select(Tenant tenant) {
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
    }

    private Connection physicalConnection() throws SQLException {
        Connection target = DriverManager.getConnection(DATABASE.url(), DATABASE.username(), DATABASE.password());
        return (Connection) Proxy.newProxyInstance(Connection.class.getClassLoader(), new Class[]{Connection.class},
                (proxy, method, args) -> {
                    Object result = invoke(target, method, args);
                    if ("createStatement".equals(method.getName())) {
                        Statement statement = (Statement) result;
                        return Proxy.newProxyInstance(Statement.class.getClassLoader(), new Class[]{Statement.class},
                                (p, m, a) -> {
                                    if ("execute".equals(m.getName()) && a != null
                                            && "RESET search_path".equals(a[0]) && fault.compareAndSet("reset", null)) {
                                        throw new SQLException("injected reset failure");
                                    }
                                    return invoke(statement, m, a);
                                });
                    }
                    if ("prepareStatement".equals(method.getName()) && args[0].toString().contains("'search_path'")) {
                        PreparedStatement statement = (PreparedStatement) result;
                        return Proxy.newProxyInstance(PreparedStatement.class.getClassLoader(), new Class[]{PreparedStatement.class},
                                (p, m, a) -> {
                                    if ("execute".equals(m.getName()) && fault.compareAndSet("context", null)) {
                                        throw new SQLException("injected context failure");
                                    }
                                    return invoke(statement, m, a);
                                });
                    }
                    return result;
                });
    }

    private static Object invoke(Object target, Method method, Object[] args) throws Throwable {
        try {
            return method.invoke(target, args);
        } catch (InvocationTargetException ex) {
            throw ex.getCause();
        }
    }
}
