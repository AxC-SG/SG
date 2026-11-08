package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.time.Clock;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.ToDoubleFunction;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/**
 * Registers queue and projection gauges that capture the freshness signals most likely to affect
 * analyst-perceived performance.
 */
@Service
public class PerformanceTelemetryService {
    private final MeterRegistry meterRegistry;
    private final TenantService tenantService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final FindingProjectionStatusService findingProjectionStatusService;
    private final JdbcTemplate jdbcTemplate;
    private final long staleProjectionThresholdSeconds;
    private final long maximumSnapshotAgeSeconds;
    private final boolean ownsRefresh;
    private final Clock clock;
    private final AtomicReference<Snapshot> snapshot = new AtomicReference<>(Snapshot.empty());

    @Autowired
    public PerformanceTelemetryService(
            ObjectProvider<MeterRegistry> meterRegistryProvider,
            TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            FindingProjectionStatusService findingProjectionStatusService,
            JdbcTemplate jdbcTemplate,
            @Value("${app.slo.projection-stale-threshold-minutes:15}") long projectionStaleThresholdMinutes,
            @Value("${app.performance.telemetry-refresh-ms:30000}") long refreshIntervalMs,
            BackgroundTaskExecutionPolicy executionPolicy
    ) {
        this(meterRegistryProvider, tenantService, tenantSchemaExecutionService, findingProjectionStatusService,
                jdbcTemplate, projectionStaleThresholdMinutes, refreshIntervalMs, executionPolicy, Clock.systemUTC());
    }

    PerformanceTelemetryService(ObjectProvider<MeterRegistry> meterRegistryProvider, TenantService tenantService,
            TenantSchemaExecutionService tenantSchemaExecutionService, FindingProjectionStatusService findingProjectionStatusService,
            JdbcTemplate jdbcTemplate, long projectionStaleThresholdMinutes, long refreshIntervalMs,
            BackgroundTaskExecutionPolicy executionPolicy, Clock clock) {
        this.meterRegistry = meterRegistryProvider.getIfAvailable();
        this.tenantService = tenantService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.findingProjectionStatusService = findingProjectionStatusService;
        this.jdbcTemplate = jdbcTemplate;
        this.staleProjectionThresholdSeconds = Math.max(1L, projectionStaleThresholdMinutes) * 60L;
        this.maximumSnapshotAgeSeconds = Math.max(3L, Duration.ofMillis(Math.max(1000L, refreshIntervalMs)).toSeconds() * 3L);
        this.clock = clock;
        String role = executionPolicy.runtimeRole();
        this.ownsRefresh = role.equals("worker") || role.equals("all");
        if (meterRegistry != null) {
            register(role, "scoutgrid.finding_delta_queue.pending", "Observed pending entries; partial results require refresh_valid=0.",
                    service -> service.observedValue(Snapshot::pendingCount));
            register(role, "scoutgrid.finding_delta_queue.oldest_age_seconds", "Oldest visible pending age among observed active tenants.",
                    service -> service.observedValue(Snapshot::oldestPendingAgeSeconds));
            register(role, "ingestion.jobs.queue.depth", "Queued endpoint and GitHub jobs in active tenants.",
                    service -> service.validValue(current -> current.ingestion().queued()));
            register(role, "ingestion.jobs.active", "Queued and running endpoint and GitHub jobs in active tenants.",
                    service -> service.validValue(current -> current.ingestion().active()));
            register(role, "scoutgrid.ingestion.queue.oldest_visible_age_seconds", "Oldest eligible queued job across ingestion job types.",
                    service -> service.validValue(current -> current.ingestion().oldestAgeSeconds()));
            register(role, "scoutgrid.finding_projection.stale_tenants", "Observed active tenants with a missing or stale projection.",
                    service -> service.observedValue(Snapshot::staleProjectionTenants));
            register(role, "scoutgrid.finding_projection.max_lag_seconds", "Maximum known projection lag; unknown when any observed projection is missing.",
                    service -> service.snapshot.get().projectionLagKnown() ? service.observedValue(Snapshot::maxProjectionLagSeconds) : Double.NaN);
            register(role, "scoutgrid.performance.refresh_owner", "Whether this process owns worker refresh.", service -> service.ownsRefresh ? 1 : 0);
            register(role, "scoutgrid.performance.refresh_valid", "One only for a fresh, complete active-tenant observation.", service -> service.isValid() ? 1 : 0);
            register(role, "scoutgrid.performance.refresh_error", "One when tenant discovery or any eligible tenant failed in the latest attempt.",
                    service -> service.snapshot.get().discoveryFailed() || service.snapshot.get().failedTenants() > 0 ? 1 : 0);
            register(role, "scoutgrid.performance.last_attempt_timestamp_seconds", "Latest refresh attempt, unknown before startup refresh.",
                    service -> epoch(service.snapshot.get().lastAttemptAt()));
            register(role, "scoutgrid.performance.last_refresh_timestamp_seconds", "Latest completed observation, including partial observations.",
                    service -> epoch(service.snapshot.get().lastRefreshAt()));
            register(role, "scoutgrid.performance.last_success_timestamp_seconds", "Latest complete successful observation.",
                    service -> epoch(service.snapshot.get().lastSuccessfulAt()));
            register(role, "scoutgrid.performance.snapshot_age_seconds", "Age of the latest completed observation; unknown before refresh.",
                    service -> service.snapshotAgeSeconds());
            register(role, "scoutgrid.performance.eligible_tenants", "ACTIVE tenants selected in the latest observation.", service -> service.observedValue(Snapshot::eligibleTenants));
            register(role, "scoutgrid.performance.observed_tenants", "Eligible tenants read successfully in the latest observation.", service -> service.observedValue(Snapshot::observedTenants));
            register(role, "scoutgrid.performance.failed_tenants", "Eligible tenants that could not be read in the latest observation.", service -> service.observedValue(Snapshot::failedTenants));
            register(role, "scoutgrid.performance.skipped_tenants", "Non-active tenants deliberately excluded from the latest observation.", service -> service.observedValue(Snapshot::skippedTenants));
        }
    }

    private void register(String role, String name, String description,
            ToDoubleFunction<PerformanceTelemetryService> value) {
        Gauge.builder(name, this, value).description(description)
                .tag("role", role).tag("scope", "active-tenants-worker-observation").register(meterRegistry);
    }

    public synchronized void refreshFreshnessSnapshot() {
        if (!ownsRefresh) {
            return;
        }
        Instant now = clock.instant();
        Snapshot previous = snapshot.get();
        try {
            TenantContext.runAsPlatform(() -> {
                List<Tenant> tenants = tenantService.listTenants();
                int eligible = 0, observed = 0, failed = 0, skipped = 0;
                long pending = 0, oldest = 0, stale = 0, lag = 0;
                IngestionSnapshot ingestion = new IngestionSnapshot(0, 0, 0);
                boolean lagKnown = true;
                for (Tenant tenant : tenants) {
                    if (tenant == null || tenant.getId() == null || !"ACTIVE".equalsIgnoreCase(tenant.getStatus())) {
                        skipped++;
                        continue;
                    }
                    eligible++;
                    try {
                        TenantSnapshot result = tenantSchemaExecutionService.run(tenant, () -> readTenantSnapshot(tenant, now));
                        pending += result.pendingCount();
                        oldest = Math.max(oldest, result.oldestPendingAgeSeconds());
                        ingestion = ingestion.combine(result.ingestion());
                        stale += result.staleProjection() ? 1 : 0;
                        lag = Math.max(lag, result.projectionLagSeconds());
                        lagKnown &= result.projectionLagKnown();
                        observed++;
                    } catch (RuntimeException ex) {
                        // Publish only aggregate failures, with no tenant labels or exception payloads.
                        failed++;
                    }
                }
                snapshot.set(new Snapshot(now, now, failed == 0 ? now : previous.lastSuccessfulAt(),
                        eligible, observed, failed, skipped, false, pending, oldest, ingestion, stale, lag, lagKnown));
            });
        } catch (RuntimeException ex) {
            snapshot.set(new Snapshot(now, previous.lastRefreshAt(), previous.lastSuccessfulAt(),
                    previous.eligibleTenants(), previous.observedTenants(), previous.failedTenants(), previous.skippedTenants(),
                    true, previous.pendingCount(), previous.oldestPendingAgeSeconds(), previous.ingestion(),
                    previous.staleProjectionTenants(),
                    previous.maxProjectionLagSeconds(), previous.projectionLagKnown()));
        }
    }

    private boolean isValid() {
        return isValid(snapshot.get());
    }

    private boolean isValid(Snapshot current) {
        return ownsRefresh && current.lastRefreshAt() != null && !current.discoveryFailed()
                && current.failedTenants() == 0
                && Duration.between(current.lastRefreshAt(), clock.instant()).getSeconds() <= maximumSnapshotAgeSeconds;
    }

    private double validValue(ToDoubleFunction<Snapshot> value) {
        Snapshot current = snapshot.get();
        return isValid(current) ? value.applyAsDouble(current) : Double.NaN;
    }

    private double observedValue(ToDoubleFunction<Snapshot> value) {
        Snapshot current = snapshot.get();
        return !ownsRefresh || current.lastRefreshAt() == null || snapshotAgeSeconds() > maximumSnapshotAgeSeconds
                ? Double.NaN : value.applyAsDouble(current);
    }

    private double snapshotAgeSeconds() {
        Instant refreshed = snapshot.get().lastRefreshAt();
        return refreshed == null ? Double.NaN : Math.max(0L, Duration.between(refreshed, clock.instant()).getSeconds());
    }

    private static double epoch(Instant instant) {
        return instant == null ? Double.NaN : instant.getEpochSecond();
    }

    private TenantSnapshot readTenantSnapshot(Tenant tenant, Instant now) {
        Long pendingCount = jdbcTemplate.queryForObject(
                "select count(*) from finding_delta_queue where upper(status) = 'PENDING'",
                Long.class
        );
        Timestamp oldestVisible = jdbcTemplate.query(
                """
                select min(visible_after)
                from finding_delta_queue
                where upper(status) = 'PENDING'
                  and visible_after <= now()
                """,
                rs -> rs.next() ? rs.getTimestamp(1) : null
        );
        long oldestAgeSeconds = 0L;
        if (oldestVisible != null) {
            oldestAgeSeconds = Math.max(0L, Duration.between(oldestVisible.toInstant(), now).getSeconds());
        }

        FindingListProjectionService.ProjectionStatus projectionStatus =
                findingProjectionStatusService.inspectProjectionStatus(tenant);
        long projectionLagSeconds = 0L;
        boolean lagKnown = projectionStatus != null && projectionStatus.lastComputedAt() != null;
        boolean staleProjection = true;
        if (projectionStatus != null && projectionStatus.lastComputedAt() != null) {
            projectionLagSeconds = Math.max(0L, Duration.between(projectionStatus.lastComputedAt(), now).getSeconds());
            staleProjection = projectionStatus.stale() || projectionLagSeconds > staleProjectionThresholdSeconds;
        }

        return new TenantSnapshot(
                pendingCount == null ? 0L : pendingCount,
                oldestAgeSeconds,
                readIngestionSnapshot(now),
                staleProjection,
                projectionLagSeconds,
                lagKnown
        );
    }

    private IngestionSnapshot readIngestionSnapshot(Instant now) {
        return jdbcTemplate.queryForObject("""
                select count(*) filter (where status = 'QUEUED' and legacy_type) as queued,
                       count(*) filter (where legacy_type) as active,
                       min(visible_at) filter (where status = 'QUEUED' and visible_at <= ?) as oldest
                from (
                    select status, visible_at, job_type in ('REMOTE_ENDPOINT', 'GITHUB_REPOSITORY', 'GITHUB_GHCR') as legacy_type
                    from ingestion_jobs
                    where status in ('QUEUED', 'RUNNING')
                ) jobs
                """, (row, index) -> {
            Timestamp oldest = row.getTimestamp("oldest");
            long age = oldest == null ? 0 : Math.max(0, Duration.between(oldest.toInstant(), now).getSeconds());
            return new IngestionSnapshot(row.getLong("queued"), row.getLong("active"), age);
        }, Timestamp.from(now));
    }

    private record IngestionSnapshot(long queued, long active, long oldestAgeSeconds) {
        IngestionSnapshot combine(IngestionSnapshot next) {
            return new IngestionSnapshot(queued + next.queued(), active + next.active(),
                    Math.max(oldestAgeSeconds, next.oldestAgeSeconds()));
        }
    }

    private record TenantSnapshot(
            long pendingCount,
            long oldestPendingAgeSeconds,
            IngestionSnapshot ingestion,
            boolean staleProjection,
            long projectionLagSeconds,
            boolean projectionLagKnown
    ) {
    }

    private record Snapshot(Instant lastAttemptAt, Instant lastRefreshAt, Instant lastSuccessfulAt,
            int eligibleTenants, int observedTenants, int failedTenants, int skippedTenants, boolean discoveryFailed,
            long pendingCount, long oldestPendingAgeSeconds, IngestionSnapshot ingestion,
            long staleProjectionTenants, long maxProjectionLagSeconds,
            boolean projectionLagKnown) {
        static Snapshot empty() {
            return new Snapshot(null, null, null, 0, 0, 0, 0, false, 0, 0, new IngestionSnapshot(0, 0, 0), 0, 0, false);
        }
    }
}
