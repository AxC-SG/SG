package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase.DatabaseConfig;
import java.lang.management.ManagementFactory;
import java.math.BigDecimal;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.jdbc.core.JdbcTemplate;

final class FirstCustomerQualificationMetrics implements AutoCloseable {
    private final ScheduledExecutorService monitor = Executors.newSingleThreadScheduledExecutor();
    private final AtomicLong heap = new AtomicLong();
    private final AtomicLong connections = new AtomicLong();
    private final AtomicLong correlationTransaction = new AtomicLong();
    private final DatabaseConfig database;
    private final String phase;
    private final JdbcTemplate jdbc;
    private final long start = System.nanoTime();
    private final long databaseBytes;
    private final BigDecimal wal;
    private final BigDecimal statementWal;

    FirstCustomerQualificationMetrics(DatabaseConfig database, JdbcTemplate jdbc, String phase) {
        this.database = database;
        this.jdbc = jdbc;
        this.phase = phase;
        databaseBytes = databaseBytes();
        wal = walPosition();
        statementWal = statementWalBytes();
        monitor.scheduleWithFixedDelay(this::sample, 0, 200, TimeUnit.MILLISECONDS);
    }

    static DatabaseConfig provision(String key) {
        return database(key, false);
    }

    static DatabaseConfig database(String key, boolean resume) {
        String admin = System.getProperty("postgres.test.admin-url", "");
        if (!admin.matches("jdbc:postgresql://127\\.0\\.0\\.1:[0-9]+/postgres") || admin.contains(":5432/")) {
            throw new IllegalStateException("Use an explicit disposable PostgreSQL 16 loopback port");
        }
        if (resume) {
            return new DatabaseConfig(admin.replaceFirst("/postgres$", "/vulnwatch_it_" + key),
                    System.getProperty("postgres.test.username", System.getProperty("user.name")),
                    System.getProperty("postgres.test.password", ""));
        }
        return LocalPostgresTestDatabase.provision(key);
    }

    private void sample() {
        heap.accumulateAndGet(ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed(), Math::max);
        try (var connection = DriverManager.getConnection(database.url(), database.username(), database.password());
                var statement = connection.createStatement();
                var row = statement.executeQuery("""
                        select count(*), coalesce(max(extract(epoch from clock_timestamp()-xact_start)*1000)
                            filter (where state<>'idle' and (query like '%finding_delta_queue%'
                                or query like '%component_vulnerability_states%')),0)::bigint
                        from pg_stat_activity
                        where datname=current_database() and backend_type='client backend' and pid<>pg_backend_pid()
                        """)) {
            row.next();
            connections.accumulateAndGet(row.getLong(1), Math::max);
            correlationTransaction.accumulateAndGet(row.getLong(2), Math::max);
        } catch (SQLException failure) {
            throw new IllegalStateException("Qualification resource sampling failed", failure);
        }
    }

    void mark(String stage, String fields) {
        System.out.printf("QUALIFICATION phase=%s stage=%s elapsed_ms=%d heap_peak_bytes=%d "
                        + "client_connections_peak=%d database_bytes=%d database_growth_bytes=%d "
                        + "cluster_wal_bytes=%s database_statement_wal_bytes=%s "
                        + "sampled_correlation_transaction_ms=%d %s%n",
                phase, stage, elapsedMillis(start), heap.get(), connections.get(), databaseBytes(),
                databaseBytes() - databaseBytes, walPosition().subtract(wal).toPlainString(),
                statementWalBytes().subtract(statementWal).toPlainString(), correlationTransaction.get(), fields);
    }

    @Override
    public void close() {
        monitor.shutdownNow();
        mark("end", "");
    }

    static long elapsedMillis(long since) {
        return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - since);
    }

    private long databaseBytes() {
        return jdbc.queryForObject("select pg_database_size(current_database())", Long.class);
    }

    private BigDecimal walPosition() {
        return jdbc.queryForObject("select pg_wal_lsn_diff(pg_current_wal_insert_lsn(),'0/0')", BigDecimal.class);
    }

    private BigDecimal statementWalBytes() {
        return jdbc.queryForObject("""
                select coalesce(sum(wal_bytes),0) from public.pg_stat_statements
                where dbid=(select oid from pg_database where datname=current_database())
                """, BigDecimal.class);
    }
}
