package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;

import com.prototype.vulnwatch.VulnWatchApplication;
import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import com.prototype.vulnwatch.support.*;
import java.nio.file.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/** Sends a real TERM to a child JVM with the production Spring context and executor beans. */
@PostgresIntegrationTest
class ExecutorSigtermPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DB = LocalPostgresTestDatabase.provision("phase3_sigterm");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) { PostgresITSupport.registerDatabaseProperties(registry, DB); }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService scoped;
    @Autowired IngestionJobService jobs;
    @Autowired JdbcTemplate jdbc;
    @Autowired PlatformTransactionManager manager;
    @TempDir Path signals;

    @ParameterizedTest @ValueSource(strings = {"CLAIM", "QUEUED", "EXECUTION", "COMMIT"})
    void termPreservesAcceptedWorkAtEachBoundary(String boundary) throws Exception {
        String slug = "term-" + UUID.randomUUID().toString().substring(0, 8);
        Tenant created = tenants.createTenant(slug, slug, "ENTERPRISE", null);
        migrations.provisionNewTenant(created);
        Tenant tenant = tenants.resolveTenantUuid(created.getId());
        scoped.run(tenant, () -> jdbc.execute("create table shutdown_effect (job_id uuid primary key)"));
        UUID id = jobs.enqueueEndpointJob(tenant, new SbomEndpointIngestionRequest(
                AssetType.APPLICATION, "offline", slug, "https://example.test/offline", "test", null), "test").jobId();
        var claim = jobs.claimPendingJobs(tenant, 1, 1).get(0);
        String classpath = System.getProperty("surefire.test.class.path", System.getProperty("java.class.path"));
        ProcessBuilder builder = new ProcessBuilder(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", classpath, Child.class.getName(), DB.url(), DB.username(), DB.password(),
                tenant.getId().toString(), id.toString(), claim.claimToken().toString(), boundary, signals.toString());
        builder.environment().clear();
        builder.environment().putAll(Map.of("APP_ENVIRONMENT", "test", "APP_RUNTIME_ROLE", "worker", "DB_URL", DB.url(),
                "DB_USERNAME", DB.username(), "DB_PASSWORD", DB.password(), "OPENAI_ENABLED", "false"));
        builder.redirectErrorStream(true).redirectOutput(signals.resolve("child.log").toFile());
        Process child = builder.start();
        try {
            Instant deadline = Instant.now().plusSeconds(45);
            while (!Files.exists(signals.resolve("ready")) && child.isAlive() && Instant.now().isBefore(deadline)) Thread.sleep(20);
            assertTrue(Files.exists(signals.resolve("ready")), () -> readLog(signals));
            child.destroy(); // Unix Process.destroy sends SIGTERM; no simulated ContextClosedEvent.
            assertTrue(child.waitFor(35, TimeUnit.SECONDS), () -> readLog(signals));
            assertFalse(Files.exists(signals.resolve("task-failed")), () -> readLog(signals));
            if ("CLAIM".equals(boundary)) {
                assertEquals("RUNNING", jobs.loadJob(tenant.getId(), id).getStatus());
                scoped.run(tenant, () -> jdbc.update("update ingestion_jobs set lease_expires_at=now()-interval '1 second' where id=?", id));
                assertTrue(jobs.recoverInterruptedRunningJobs() >= 1);
                assertEquals("QUEUED", jobs.loadJob(tenant.getId(), id).getStatus());
                var replay = jobs.claimPendingJobs(tenant, 1, 1).get(0);
                try (var ignored = jobs.openAttempt(tenant.getId(), id, replay.claimToken())) {
                    scoped.run(tenant, () -> new TransactionTemplate(manager).executeWithoutResult(status -> {
                        jdbc.update("insert into shutdown_effect values (?)", id);
                        jobs.markSucceeded(tenant.getId(), id, null, "{}");
                    }));
                }
            }
            assertEquals("SUCCEEDED", jobs.loadJob(tenant.getId(), id).getStatus(), () -> readLog(signals));
            scoped.run(tenant, () -> assertEquals(1, jdbc.queryForObject("select count(*) from shutdown_effect", Integer.class)));
        } finally { if (child.isAlive()) { child.destroyForcibly(); child.waitFor(10, TimeUnit.SECONDS); } TenantContext.clear(); }
    }

    private static String readLog(Path path) {
        try { return Files.readString(path.resolve("child.log")); } catch (Exception error) { return error.toString(); }
    }

    public static class Child {
        public static void main(String[] args) throws Exception {
            Path signals = Path.of(args[7]);
            var context = new SpringApplicationBuilder(VulnWatchApplication.class).profiles("postgres").run(
                    "--server.port=0", "--spring.flyway.enabled=false", "--app.scheduling.enabled=false",
                    "--app.schema-migration.enabled=false", "--app.schema-migration.legacy-test-runner-enabled=false",
                    "--app.runtime.role=worker", "--app.environment=test", "--logging.level.root=WARN",
                    "--app.correlation.backfill-targets-on-startup=false",
                    "--app.security.credential-encryption-key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
            CountDownLatch closing = new CountDownLatch(1);
            context.addApplicationListener(event -> { if (event instanceof ContextClosedEvent) closing.countDown(); });
            UUID tenant = UUID.fromString(args[3]), job = UUID.fromString(args[4]), token = UUID.fromString(args[5]);
            String boundary = args[6];
            var policy = context.getBean(BackgroundTaskExecutionPolicy.class);
            var executor = context.getBean("integrationQueueExecutor", ThreadPoolTaskExecutor.class);
            if ("CLAIM".equals(boundary)) {
                Files.writeString(signals.resolve("ready"), boundary);
            } else {
                if ("QUEUED".equals(boundary)) executor.execute(() -> await(closing));
                executor.execute(() -> {
                    try {
                        var jobs = context.getBean(IngestionJobService.class);
                        var scoped = context.getBean(TenantSchemaExecutionService.class);
                        var jdbc = context.getBean(JdbcTemplate.class);
                        var tx = new TransactionTemplate(context.getBean(PlatformTransactionManager.class));
                        try (var ignored = jobs.openAttempt(tenant, job, token)) {
                            scoped.run(tenant, () -> tx.execute(status -> {
                                jdbc.update("insert into shutdown_effect values (?)", job);
                                if ("EXECUTION".equals(boundary)) {
                                    ready(signals, boundary); await(closing);
                                    if (policy.allowsBackgroundTask("post-term-admission")) throw new IllegalStateException("Admission stayed open");
                                }
                                jobs.markSucceeded(tenant, job, null, "{}");
                                return null;
                            }));
                            if ("COMMIT".equals(boundary)) { ready(signals, boundary); await(closing); }
                        }
                    } catch (Throwable error) {
                        try { Files.writeString(signals.resolve("task-failed"), error.toString()); } catch (Exception ignored) { }
                        error.printStackTrace();
                    }
                });
                if ("QUEUED".equals(boundary)) ready(signals, boundary);
            }
            closing.await();
        }
        private static void ready(Path signals, String boundary) {
            try { Files.writeString(signals.resolve("ready"), boundary); } catch (Exception error) { throw new IllegalStateException(error); }
        }
        private static void await(CountDownLatch latch) {
            try { if (!latch.await(30, TimeUnit.SECONDS)) throw new IllegalStateException("No shutdown signal"); }
            catch (InterruptedException error) { Thread.currentThread().interrupt(); throw new IllegalStateException(error); }
        }
    }
}
