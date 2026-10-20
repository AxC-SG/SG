package com.prototype.vulnwatch.config;

import com.prototype.vulnwatch.service.TenantContext;
import com.zaxxer.hikari.HikariDataSource;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Proxy;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.BooleanSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.jdbc.datasource.DelegatingDataSource;

/**
 * BLG-007: DataSource decorator that sets the PostgreSQL session variable
 * app.current_tenant_id on every connection acquired from the underlying pool,
 * and resets it when the connection is returned (on close()).
 *
 * This allows PostgreSQL Row-Level Security policies to enforce tenant isolation
 * at the database layer, complementing application-layer tenant filtering.
 *
 * set_config(name, value, FALSE) sets a session-level variable that persists for
 * the life of the connection. The reset on close() restores it to an empty string,
 * which the RLS policies treat as "no tenant constraint" in local/dev mode.
 * In production mode, missing tenant context is converted to a sentinel UUID
 * so tenant-scoped RLS policies match no tenant rows.
 */
public class TenantAwareDataSource extends DelegatingDataSource {

    private static final Logger LOG = LoggerFactory.getLogger(TenantAwareDataSource.class);
    private static final String NO_TENANT_SENTINEL = "00000000-0000-0000-0000-000000000000";

    private final boolean requireTenantContext;
    private final String defaultTenantSchema;
    private final MeterRegistry meterRegistry;
    private final BooleanSupplier applicationReadySupplier;

    public TenantAwareDataSource(
            javax.sql.DataSource targetDataSource,
            boolean requireTenantContext,
            String defaultTenantSchema,
            MeterRegistry meterRegistry
    ) {
        this(targetDataSource, requireTenantContext, defaultTenantSchema, meterRegistry, () -> true);
    }

    public TenantAwareDataSource(
            javax.sql.DataSource targetDataSource,
            boolean requireTenantContext,
            String defaultTenantSchema,
            MeterRegistry meterRegistry,
            BooleanSupplier applicationReadySupplier
    ) {
        super(targetDataSource);
        this.requireTenantContext = requireTenantContext;
        this.defaultTenantSchema = defaultTenantSchema;
        this.meterRegistry = meterRegistry;
        this.applicationReadySupplier = applicationReadySupplier == null ? () -> true : applicationReadySupplier;
    }

    @Override
    public Connection getConnection() throws SQLException {
        Connection conn = super.getConnection();
        try {
            applyTenantContext(conn);
            return wrapWithReset(conn);
        } catch (SQLException | RuntimeException ex) {
            closeAfterContextFailure(conn, ex);
            throw ex;
        }
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        Connection conn = super.getConnection(username, password);
        try {
            applyTenantContext(conn);
            return wrapWithReset(conn);
        } catch (SQLException | RuntimeException ex) {
            closeAfterContextFailure(conn, ex);
            throw ex;
        }
    }

    private void applyTenantContext(Connection conn) throws SQLException {
        UUID tenantId = TenantContext.getCurrentTenantId();
        boolean platformContext = TenantContext.isPlatformContext();
        boolean preAuthenticationContext = TenantContext.isPreAuthenticationContext();
        String schemaName = platformContext ? "platform" : normalizeSchemaName(TenantContext.getCurrentSchemaName());
        recordTenantContextState(tenantId);
        String value = tenantId != null
                ? tenantId.toString()
                : requireTenantContext && !platformContext && !preAuthenticationContext ? NO_TENANT_SENTINEL : "";
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT set_config('app.current_tenant_id', ?, FALSE)")) {
            ps.setString(1, value);
            ps.execute();
        }
        String searchPath = platformContext ? "platform,public" : schemaName + ",platform";
        try (PreparedStatement ps = conn.prepareStatement(
                "SELECT set_config('search_path', ?, FALSE)")) {
            ps.setString(1, searchPath);
            ps.execute();
        }
    }

    /**
     * Wraps the connection in a JDK proxy that resets app.current_tenant_id before
     * close(), ensuring the pool connection is clean for the next request.
     * ConnectionWrapper was removed in Spring 6; Proxy is the portable alternative.
     */
    private Connection wrapWithReset(Connection target) {
        AtomicBoolean closed = new AtomicBoolean();
        return (Connection) Proxy.newProxyInstance(
                target.getClass().getClassLoader(),
                new Class[]{Connection.class},
                (proxy, method, args) -> {
                    if ("close".equals(method.getName())) {
                        if (!closed.compareAndSet(false, true)) {
                            return null;
                        }
                        // A caller returning an unfinished/aborted transaction cannot
                        // make session RESET durable. Discard its physical connection.
                        boolean autoCommit;
                        try {
                            autoCommit = target.getAutoCommit();
                        } catch (SQLException | RuntimeException stateFailure) {
                            discardConnection(target, stateFailure);
                            throw stateFailure;
                        }
                        if (!autoCommit) {
                            discardConnection(target, null);
                            return null;
                        }
                        try (Statement stmt = target.createStatement()) {
                            stmt.execute("RESET app.current_tenant_id");
                            stmt.execute("RESET search_path");
                        } catch (SQLException | RuntimeException resetFailure) {
                            discardConnection(target, resetFailure);
                            throw resetFailure;
                        }
                    }
                    try {
                        return method.invoke(target, args);
                    } catch (InvocationTargetException ex) {
                        throw ex.getCause();
                    }
                });
    }

    private String normalizeSchemaName(String schemaName) {
        if (schemaName == null || schemaName.isBlank()) {
            return defaultTenantSchema;
        }
        String normalized = schemaName.trim();
        int separator = normalized.indexOf(',');
        if (separator >= 0) {
            normalized = normalized.substring(0, separator).trim();
        }
        normalized = normalized.toLowerCase();
        normalized = normalized.replaceAll("[^a-z0-9_]+", "_");
        normalized = normalized.replaceAll("^[^a-z]+", "tenant_");
        return normalized.isBlank() ? defaultTenantSchema : normalized;
    }

    private void recordTenantContextState(UUID tenantId) {
        String classification;
        if (tenantId != null) {
            classification = "tenant";
        } else if (TenantContext.isPlatformContext()) {
            classification = "platform";
        } else if (TenantContext.isPreAuthenticationContext()) {
            classification = "pre_authentication";
        } else if (!applicationReadySupplier.getAsBoolean()) {
            classification = "bootstrap_default_tenant";
        } else {
            classification = "missing_unclassified";
            LOG.warn("Tenant-aware connection acquired without tenant or platform context");
        }
        if (meterRegistry != null) {
            meterRegistry.counter("tenant.context.missing", "classification", classification).increment();
        }
    }

    private void closeAfterContextFailure(Connection conn, Exception original) throws SQLException {
        discardConnection(conn, original);
    }

    private void discardConnection(Connection conn, Exception original) throws SQLException {
        SQLException failure = original instanceof SQLException sqlException ? sqlException : null;
        boolean discarded = false;
        boolean poolEvicted = false;
        try {
            // This is the actual pool installed by TenantIsolationConfig. Closing
            // its proxy alone would return a potentially contaminated session.
            if (getTargetDataSource() instanceof HikariDataSource pool) {
                pool.evictConnection(conn);
                poolEvicted = true;
            } else {
                conn.abort(Runnable::run);
            }
            discarded = true;
        } catch (SQLException | RuntimeException discardFailure) {
            if (original != null) {
                original.addSuppressed(discardFailure);
            } else {
                failure = new SQLException("Could not discard tenant connection", discardFailure);
            }
            try {
                conn.abort(Runnable::run);
                discarded = true;
            } catch (SQLException | RuntimeException abortFailure) {
                if (original != null) {
                    original.addSuppressed(abortFailure);
                } else {
                    failure.addSuppressed(abortFailure);
                }
            }
        }
        // Do not return an uncertain pooled connection when both eviction and
        // physical abort failed. Surface the failure and leave it out of reuse.
        if (!discarded) {
            if (original == null) {
                throw failure;
            }
            return;
        }
        if (poolEvicted) {
            // Hikari owns physical close and pool bookkeeping after eviction.
            // Closing the detached proxy again can touch its cleared PoolEntry.
            return;
        }
        try {
            conn.close();
        } catch (SQLException closeFailure) {
            if (original != null) {
                original.addSuppressed(closeFailure);
            } else if (failure == null) {
                failure = closeFailure;
            } else {
                failure.addSuppressed(closeFailure);
            }
        }
        if (original == null && failure != null) {
            throw failure;
        }
    }
}
