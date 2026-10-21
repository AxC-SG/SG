package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.jdbc.core.JdbcTemplate;

class PerformanceTelemetryValidityTest {
    @Test void startupFailureRecoveryAndAgeAreDistinguishableFromHealthyZero() {
        var registry=new SimpleMeterRegistry();
        try {
            var tenants=mock(TenantService.class);
            var time=new AtomicReference<>(Instant.parse("2026-10-20T00:00:00Z"));
            Clock clock=new Clock() {
                public ZoneId getZone() {return ZoneOffset.UTC;}
                public Clock withZone(ZoneId zone) {return this;}
                public Instant instant() {return time.get();}
            };
            ObjectProvider<io.micrometer.core.instrument.MeterRegistry> meters=mock(ObjectProvider.class);
            when(meters.getIfAvailable()).thenReturn(registry);
            var service=new PerformanceTelemetryService(meters,tenants,mock(TenantSchemaExecutionService.class),mock(FindingProjectionStatusService.class),mock(JdbcTemplate.class),15,1000,BackgroundTaskExecutionPolicy.forRole("worker"),clock);
            assertEquals(0,gauge(registry,"refresh_valid"));
            assertTrue(Double.isNaN(registry.get("scoutgrid.finding_delta_queue.pending").gauge().value()));
            when(tenants.listTenants()).thenThrow(new IllegalStateException("database unavailable"));
            service.refreshFreshnessSnapshot();assertEquals(1,gauge(registry,"refresh_error"));assertEquals(0,gauge(registry,"refresh_valid"));
            doReturn(List.of()).when(tenants).listTenants();
            service.refreshFreshnessSnapshot();assertEquals(0,gauge(registry,"refresh_error"));assertEquals(1,gauge(registry,"refresh_valid"));
            assertEquals(0,registry.get("scoutgrid.finding_delta_queue.pending").gauge().value());
            time.set(time.get().plusSeconds(4));assertEquals(0,gauge(registry,"refresh_valid"));
            assertEquals("worker",registry.get("scoutgrid.performance.refresh_valid").gauge().getId().getTag("role"));
        } finally {registry.close();}
    }
    @Test void failedTenantDoesNotPreventAnotherTenantBeingObserved() {
        var registry=new SimpleMeterRegistry();
        try {
            ObjectProvider<io.micrometer.core.instrument.MeterRegistry> meters=mock(ObjectProvider.class);when(meters.getIfAvailable()).thenReturn(registry);
            var tenants=mock(TenantService.class);var execution=mock(TenantSchemaExecutionService.class);
            var failed=new com.prototype.vulnwatch.domain.Tenant();failed.setId(UUID.randomUUID());failed.setStatus("ACTIVE");
            var healthy=new com.prototype.vulnwatch.domain.Tenant();healthy.setId(UUID.randomUUID());healthy.setStatus("ACTIVE");
            when(tenants.listTenants()).thenReturn(List.of(failed,healthy));
            when(execution.run(org.mockito.ArgumentMatchers.eq(failed),org.mockito.ArgumentMatchers.<Supplier<?>>any())).thenThrow(new IllegalStateException("unavailable tenant"));
            when(execution.run(org.mockito.ArgumentMatchers.eq(healthy),org.mockito.ArgumentMatchers.<Supplier<?>>any())).thenAnswer(call -> ((Supplier<?>)call.getArgument(1)).get());
            var service=new PerformanceTelemetryService(meters,tenants,execution,mock(FindingProjectionStatusService.class),mock(JdbcTemplate.class),15,1000,BackgroundTaskExecutionPolicy.forRole("worker"),Clock.systemUTC());
            service.refreshFreshnessSnapshot();
            assertEquals(1,gauge(registry,"observed_tenants"));assertEquals(1,gauge(registry,"failed_tenants"));assertEquals(0,gauge(registry,"refresh_valid"));
        } finally {registry.close();}
    }
    @Test void workerPublishesKnownPendingAgeAndProjectionLagWhileApiRemainsUnknown() {
        var registry = new SimpleMeterRegistry(); var apiRegistry = new SimpleMeterRegistry();
        try {
            ObjectProvider<io.micrometer.core.instrument.MeterRegistry> meters = mock(ObjectProvider.class);
            when(meters.getIfAvailable()).thenReturn(registry);
            var tenants = mock(TenantService.class); var execution = mock(TenantSchemaExecutionService.class);
            var projections = mock(FindingProjectionStatusService.class); var jdbc = mock(JdbcTemplate.class);
            Instant now = Instant.parse("2026-10-21T00:00:00Z");
            var tenant = new com.prototype.vulnwatch.domain.Tenant(); tenant.setId(UUID.randomUUID()); tenant.setStatus("ACTIVE");
            when(tenants.listTenants()).thenReturn(List.of(tenant));
            when(execution.run(eq(tenant), org.mockito.ArgumentMatchers.<Supplier<?>>any()))
                    .thenAnswer(call -> ((Supplier<?>) call.getArgument(1)).get());
            when(jdbc.queryForObject(anyString(), eq(Long.class))).thenReturn(7L);
            when(jdbc.query(anyString(), org.mockito.ArgumentMatchers.<org.springframework.jdbc.core.ResultSetExtractor<java.sql.Timestamp>>any()))
                    .thenReturn(java.sql.Timestamp.from(now.minusSeconds(125)));
            when(projections.inspectProjectionStatus(tenant)).thenReturn(
                    new FindingListProjectionService.ProjectionStatus(now.minusSeconds(960), 1, 1, 10L, true, 0));
            var worker = new PerformanceTelemetryService(meters, tenants, execution, projections, jdbc, 15, 1000,
                    BackgroundTaskExecutionPolicy.forRole("worker"), Clock.fixed(now, ZoneOffset.UTC));
            worker.refreshFreshnessSnapshot();
            assertEquals(7, registry.get("scoutgrid.finding_delta_queue.pending").gauge().value());
            assertEquals(125, registry.get("scoutgrid.finding_delta_queue.oldest_age_seconds").gauge().value());
            assertEquals(960, registry.get("scoutgrid.finding_projection.max_lag_seconds").gauge().value());
            assertEquals(1, registry.get("scoutgrid.finding_projection.stale_tenants").gauge().value());
            assertEquals(1, gauge(registry, "refresh_valid")); // A valid observation may report unhealthy lag.
            ObjectProvider<io.micrometer.core.instrument.MeterRegistry> apiMeters = mock(ObjectProvider.class);
            when(apiMeters.getIfAvailable()).thenReturn(apiRegistry);
            var api = new PerformanceTelemetryService(apiMeters, tenants, execution, projections, jdbc, 15, 1000,
                    BackgroundTaskExecutionPolicy.forRole("api"), Clock.fixed(now, ZoneOffset.UTC));
            clearInvocations(tenants, execution, projections, jdbc);
            api.refreshFreshnessSnapshot();
            verifyNoInteractions(tenants, execution, projections, jdbc);
            assertEquals(0, gauge(apiRegistry, "refresh_owner"));
            assertEquals(0, gauge(apiRegistry, "refresh_valid"));
            assertTrue(Double.isNaN(apiRegistry.get("scoutgrid.finding_delta_queue.pending").gauge().value()));
        } finally { registry.close(); apiRegistry.close(); }
    }
    private double gauge(SimpleMeterRegistry registry,String suffix) {return registry.get("scoutgrid.performance."+suffix).gauge().value();}
}
