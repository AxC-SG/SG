package com.prototype.vulnwatch.service;

import jakarta.annotation.PreDestroy;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.ConfigurableTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionExecution;
import org.springframework.transaction.TransactionExecutionListener;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Ownership of attempts in the existing ingestion_jobs queue, including each batch document commit. */
@Service
public class IngestionAttemptService implements SmartInitializingSingleton {
    private static final org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(IngestionAttemptService.class);
    private static final ThreadLocal<Attempt> CURRENT = new ThreadLocal<>();
    private final JdbcTemplate jdbc;
    private final TenantSchemaExecutionService tenants;
    private final ObjectProvider<PlatformTransactionManager> transactionManagers;
    private final TransactionTemplate heartbeatTransaction = new TransactionTemplate();
    private final long leaseSeconds;
    private final ScheduledExecutorService heartbeats = Executors.newScheduledThreadPool(2, task -> {
        Thread thread = new Thread(task, "ingestion-lease-heartbeat");
        thread.setDaemon(true);
        return thread;
    });

    public IngestionAttemptService(JdbcTemplate jdbc, TenantSchemaExecutionService tenants,
            ObjectProvider<PlatformTransactionManager> transactionManagers,
            @Value("${app.ingestion.jobs.lease-seconds:120}") long leaseSeconds) {
        if (leaseSeconds < 3) throw new IllegalArgumentException("Ingestion lease must be at least three seconds");
        this.jdbc = jdbc;
        this.tenants = tenants;
        this.leaseSeconds = leaseSeconds;
        this.transactionManagers = transactionManagers;
        this.heartbeatTransaction.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @Override
    public void afterSingletonsInstantiated() {
        // JPA bootstrap can instantiate this service before the transaction manager exists.
        PlatformTransactionManager transactionManager = transactionManagers.getObject();
        if (!(transactionManager instanceof ConfigurableTransactionManager configurable)) {
            throw new IllegalStateException("Ingestion commits require a configurable transaction manager");
        }
        heartbeatTransaction.setTransactionManager(transactionManager);
        // Every existing Spring transaction on the executing thread is fenced. This includes
        // independently committed documents in a GitHub batch and provider observation writes.
        configurable.addListener(new TransactionExecutionListener() {
            @Override public void beforeCommit(TransactionExecution transaction) {
                Attempt attempt = CURRENT.get();
                if (attempt != null && !transaction.isReadOnly()) fence(attempt);
            }
        });
    }

    public long leaseSeconds() { return leaseSeconds; }

    /** Capacity is always locked before a source/configuration row and a job row. */
    public void lockCapacity(UUID tenantId) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Capacity admission must join a transaction");
        }
        long key = tenantId.getMostSignificantBits() ^ tenantId.getLeastSignificantBits() ^ 0x4341504143495459L;
        jdbc.execute((org.springframework.jdbc.core.PreparedStatementCreator) connection -> {
            var statement = connection.prepareStatement("select pg_advisory_xact_lock(?)");
            statement.setLong(1, key);
            return statement;
        }, java.sql.PreparedStatement::execute);
    }

    public void lockIdentity(UUID tenantId, String dedupeKey) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            throw new IllegalStateException("Job identity admission must join a transaction");
        }
        long key = tenantId.getMostSignificantBits() ^ tenantId.getLeastSignificantBits()
                ^ ((long) dedupeKey.hashCode() << 32) ^ 0x4944454e54495459L;
        jdbc.execute((org.springframework.jdbc.core.PreparedStatementCreator) connection -> {
            var statement = connection.prepareStatement("select pg_advisory_xact_lock(?)");
            statement.setLong(1, key);
            return statement;
        }, java.sql.PreparedStatement::execute);
    }

    public AttemptScope open(UUID tenantId, UUID jobId, UUID token) {
        if (token == null) throw new StaleAttemptException();
        if (CURRENT.get() != null) throw new IllegalStateException("Nested ingestion attempt");
        boolean owned = tenants.run(tenantId, () -> Boolean.TRUE.equals(jdbc.queryForObject("""
                select exists(select 1 from ingestion_jobs where id=? and claim_token=?
                  and status='RUNNING' and lease_expires_at>clock_timestamp())
                """, Boolean.class, jobId, token)));
        if (!owned) throw new StaleAttemptException();
        Attempt attempt = new Attempt(tenantId, jobId, token);
        CURRENT.set(attempt);
        var heartbeat = heartbeats.scheduleWithFixedDelay(() -> renew(attempt),
                Math.max(1, leaseSeconds / 3), Math.max(1, leaseSeconds / 3), TimeUnit.SECONDS);
        return () -> {
            heartbeat.cancel(false);
            CURRENT.remove();
        };
    }

    public UUID currentToken(UUID tenantId, UUID jobId) {
        Attempt attempt = CURRENT.get();
        if (attempt == null || !attempt.tenantId().equals(tenantId) || !attempt.jobId().equals(jobId)) {
            throw new StaleAttemptException();
        }
        return attempt.token();
    }

    public void lockOwnedJob(UUID tenantId, UUID jobId) {
        currentToken(tenantId, jobId);
        fence(CURRENT.get());
    }

    public void lockSourceForRecovery(String type,com.fasterxml.jackson.databind.JsonNode payload) {
        String table=null,key=null;
        if (java.util.Set.of("GITHUB_REPOSITORY","GITHUB_GHCR").contains(type)) {table="github_sbom_sources";key="sourceId";}
        else if ("AWS_DISCOVERY".equals(type)) {table="aws_discovery_configs";key="configId";}
        else if ("SERVICENOW_CMDB".equals(type)) {table="servicenow_cmdb_configs";key="configId";}
        else if ("SCCM_CMDB".equals(type)) {table="sccm_cmdb_configs";key="configId";}
        else if ("GCP_DISCOVERY".equals(type)) {table="gcp_discovery_configs";key="configId";}
        else if ("PATCH_SYNC".equals(type)) {table="patch_connector_configs";key="configId";}
        if (table!=null && payload.hasNonNull(key)) jdbc.query("select id from "+table+" where id=? for update",(rs,row) -> rs.getObject(1,UUID.class),UUID.fromString(payload.path(key).asText()));
    }
    public boolean lockExpiredJob(UUID jobId) {
        return !jdbc.query("select id from ingestion_jobs where id=? and status='RUNNING' and lease_expires_at<=clock_timestamp() for update",(rs,row) -> rs.getObject(1,UUID.class),jobId).isEmpty();
    }
    public void terminalizeExhausted(UUID tenantId,String type,com.fasterxml.jackson.databind.JsonNode payload) {
        String run=payload.path("syncRunId").asText(null);
        if (run==null) run=payload.path("runId").asText(null);
        if (run!=null) jdbc.update("update platform.sync_runs set status='failed',completed_at=clock_timestamp(),error_message='Worker attempt limit exhausted' where id=? and tenant_id=? and lower(status) in ('queued','running')",UUID.fromString(run),tenantId);
        if (java.util.Set.of("GITHUB_REPOSITORY","GITHUB_GHCR").contains(type) && payload.hasNonNull("sourceId"))
            jdbc.update("update github_sbom_sources set last_run_status='FAILURE',last_error='Worker attempt limit exhausted' where id=? and tenant_id=? and upper(last_run_status) in ('QUEUED','RUNNING')",UUID.fromString(payload.path("sourceId").asText()),tenantId);
    }

    private void fence(Attempt attempt) {
        if (!attempt.tenantId().equals(TenantContext.getCurrentTenantId())) throw new StaleAttemptException();
        // The lock and check belong to the domain commit transaction. A concurrent reclaim
        // cannot change the token between this check and that commit.
        var owned = jdbc.query("""
                select id from ingestion_jobs where id=? and claim_token=?
                  and status in ('RUNNING','SUCCEEDED','FAILED','QUEUED')
                  and lease_expires_at>clock_timestamp() for update
                """, (rs, row) -> rs.getObject(1, UUID.class), attempt.jobId(), attempt.token());
        if (owned.isEmpty()) throw new StaleAttemptException();
    }

    private void renew(Attempt attempt) {
        try {
            tenants.run(attempt.tenantId(), () -> heartbeatTransaction.execute(status -> jdbc.update("""
                    update ingestion_jobs set heartbeat_at=clock_timestamp(), lease_expires_at=clock_timestamp()+make_interval(secs=>?)
                     where id=? and claim_token=? and status='RUNNING'
                       and lease_expires_at>clock_timestamp()
                    """, leaseSeconds, attempt.jobId(), attempt.token())));
        } catch (RuntimeException failure) {
            // An unrenewed attempt loses its lease and its next domain commit is refused.
            LOG.warn("Ingestion heartbeat failed for job {}", attempt.jobId());
        }
    }

    @PreDestroy
    public void stopHeartbeats() { heartbeats.shutdownNow(); }

    private record Attempt(UUID tenantId, UUID jobId, UUID token) { }
    public interface AttemptScope extends AutoCloseable { @Override void close(); }
    public static class StaleAttemptException extends IllegalStateException {
        public StaleAttemptException() { super("Ingestion attempt is no longer owned"); }
    }
}
