package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.CbomRuleConfiguration;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.CbomRuleConfigurationRepository;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

@ExtendWith(MockitoExtension.class)
class CbomRuleRolloutReconcilerTest {
    private static final Instant NOW = Instant.parse("2026-11-03T00:00:00Z");

    @Mock CbomRuleConfigurationRepository configs;
    @Mock CbomRuleLifecycleStore lifecycle;
    @Mock CbomRuleRolloutLeaseStore leases;
    @Mock CbomAssessmentBackfillService backfill;
    @Mock BomIngestionRecordRepository boms;
    @Mock TenantService tenants;
    @Mock TenantSchemaExecutionService schemas;
    @Mock TransactionTemplate transactions;
    @Mock AuditEventService audit;

    private final Map<UUID, CbomRuleConfiguration> stored = new HashMap<>();
    private CbomRulePackageRegistry registry;
    private CbomRuleRolloutReconciler reconciler;

    @BeforeEach
    void setUp() {
        registry = new CbomRulePackageRegistry(new ObjectMapper(), new DefaultResourceLoader(), "classpath:cbom-rules-test/index.json", "");
        CbomRulePackageService packages = new CbomRulePackageService(configs, registry);
        reconciler = new CbomRuleRolloutReconciler(registry, packages, configs, lifecycle, leases, backfill, boms, tenants,
                schemas, transactions, audit, new ObjectMapper());
        reconciler.setClock(Clock.fixed(NOW, ZoneOffset.UTC));
        lenient().when(configs.findById(any())).thenAnswer(inv -> Optional.ofNullable(stored.get(inv.<UUID>getArgument(0))));
        lenient().when(configs.save(any())).thenAnswer(inv -> { CbomRuleConfiguration c = inv.getArgument(0); stored.put(c.getTenantId(), c); return c; });
        lenient().when(schemas.run(any(Tenant.class), any(Supplier.class))).thenAnswer(inv -> inv.<Supplier<?>>getArgument(1).get());
        lenient().when(transactions.execute(any())).thenAnswer(inv -> inv.<TransactionCallback<?>>getArgument(0).doInTransaction(null));
        lenient().when(boms.findByTenant_IdAndStatus(any(), any())).thenReturn(List.of());
    }

    @Test
    void canaryMovesOnlyTheDeterministicBucketAndPinnedTenantsKeepBehaviour() {
        var canary = registry.find("test-pack", "1.3.0").orElseThrow();
        reconciler.setCanaryPercent(5);
        UUID inside = tenantInBucket(canary.key(), true);
        UUID outside = tenantInBucket(canary.key(), false);
        UUID pinnedId = UUID.randomUUID();
        stored.put(pinnedId, config(pinnedId, "PINNED", "1.2.0"));

        var movedOutcome = reconciler.applyRollout(tenant(inside), canary, NOW);
        var skippedOutcome = reconciler.applyRollout(tenant(outside), canary, NOW);
        var pinnedOutcome = reconciler.applyRollout(tenant(pinnedId), canary, NOW);

        assertThat(movedOutcome.upgraded()).isTrue();
        assertThat(stored.get(inside).getEffectiveVersion()).isEqualTo("1.3.0");
        assertThat(skippedOutcome.upgraded()).isFalse();
        assertThat(stored.get(outside)).isNull();
        assertThat(pinnedOutcome.upgraded()).isFalse();
        assertThat(stored.get(pinnedId).getPinnedVersion()).isEqualTo("1.2.0");
        assertThat(stored.get(pinnedId).getPinState()).isEqualTo("UPGRADE_AVAILABLE");
        verify(lifecycle).recordHistory(eq(inside), eq("test-pack"), eq("ROLLOUT_UPGRADE"), eq("1.0.0"), eq("1.3.0"),
                eq("FOLLOW_LATEST"), anyString(), anyString(), anyString(), anyString());
        verify(lifecycle).recordAvailability(outside, canary, "AVAILABLE");
        verify(lifecycle).recordAvailability(pinnedId, canary, "DEFERRED_PINNED");
    }

    @Test
    void observeStageRecordsAvailabilityWithoutChangingAnyTenant() {
        var observe = registry("test-pack@1.3.0=OBSERVE").find("test-pack", "1.3.0").orElseThrow();
        UUID id = UUID.randomUUID();
        var outcome = reconciler.applyRollout(tenant(id), observe, NOW);
        assertThat(outcome.upgraded()).isFalse();
        assertThat(stored).doesNotContainKey(id);
        verify(lifecycle).recordAvailability(id, observe, "AVAILABLE");
    }

    @Test
    void bootstrapOnTheBaselineRecordsAvailabilityWithoutReassessingTheFleet() {
        var baseline = registry.find("test-pack", "1.0.0").orElseThrow();
        UUID id = UUID.randomUUID();
        var outcome = reconciler.applyRollout(tenant(id), baseline, NOW);
        assertThat(outcome.upgraded()).isFalse();
        assertThat(outcome.reassess()).isFalse();
        verify(lifecycle).recordAvailability(id, baseline, "EFFECTIVE");
    }

    @Test
    void rolloutObeysTheTenantCeilingAndCommitsACursorPerTenant() {
        reconciler.setTenantsPerMinute(2);
        reconciler.setCanaryPercent(100);
        List<Tenant> fleet = IntStream.range(0, 5).mapToObj(i -> tenant(UUID.randomUUID())).toList();
        when(tenants.listActiveTenants()).thenReturn(fleet);
        when(leases.acquire(eq("test-pack@1.3.0"), anyString(), eq("CANARY"), anyLong()))
                .thenReturn(Optional.of(new CbomRuleRolloutLeaseStore.Lease("test-pack@1.3.0", "CANARY", null, null)));
        when(leases.commitCursor(anyString(), anyString(), any(), anyInt(), anyLong())).thenReturn(true);
        when(backfill.start(any(), anyString(), any())).thenReturn(new CbomAssessmentBackfillService.BackfillStart(0, null));

        var summary = reconciler.rollout();

        assertThat(summary.tenantsVisited()).isEqualTo(2);
        assertThat(summary.tenantsUpgraded()).isEqualTo(2);
        verify(leases, never()).completePass(anyString(), anyString());
        verify(leases).release(eq("test-pack@1.3.0"), anyString());
        List<UUID> sorted = new ArrayList<>(fleet.stream().map(Tenant::getId).sorted().toList());
        verify(leases).commitCursor(eq("test-pack@1.3.0"), anyString(), eq(sorted.get(1)), eq(0), anyLong());
    }

    @Test
    void jobCeilingStopsTheRunBeforeTheCursorPassesAPartiallyReassessedTenant() {
        reconciler.setJobsPerMinute(3);
        reconciler.setCanaryPercent(100);
        Tenant only = tenant(UUID.randomUUID());
        when(tenants.listActiveTenants()).thenReturn(List.of(only));
        when(leases.acquire(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(Optional.of(new CbomRuleRolloutLeaseStore.Lease("test-pack@1.3.0", "CANARY", null, null)));
        when(backfill.start(only, "cbom-rule-rollout", 3)).thenReturn(new CbomAssessmentBackfillService.BackfillStart(3, null));

        var summary = reconciler.rollout();

        assertThat(summary.jobsEnqueued()).isEqualTo(3);
        verify(leases, never()).commitCursor(anyString(), anyString(), any(), anyInt(), anyLong());
        verify(leases, never()).completePass(anyString(), anyString());
    }

    @Test
    void lostLeaseStopsTheRunAndAHeldLeaseIsSkipped() {
        reconciler.setCanaryPercent(100);
        when(tenants.listActiveTenants()).thenReturn(List.of(tenant(UUID.randomUUID()), tenant(UUID.randomUUID())));
        when(leases.acquire(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(Optional.of(new CbomRuleRolloutLeaseStore.Lease("test-pack@1.3.0", "CANARY", null, null)));
        when(leases.commitCursor(anyString(), anyString(), any(), anyInt(), anyLong())).thenReturn(false);
        when(backfill.start(any(), anyString(), any())).thenReturn(new CbomAssessmentBackfillService.BackfillStart(0, null));

        assertThat(reconciler.rollout().tenantsVisited()).isEqualTo(1);
        verify(leases, never()).completePass(anyString(), anyString());

        when(leases.acquire(anyString(), anyString(), anyString(), anyLong())).thenReturn(Optional.empty());
        assertThat(reconciler.rollout().skippedPackages()).containsExactly("test-pack@1.3.0:leased-elsewhere");
    }

    @Test
    void completedStageIsNotRevisitedUntilTheStageAdvances() {
        when(tenants.listActiveTenants()).thenReturn(List.of(tenant(UUID.randomUUID())));
        when(leases.acquire(anyString(), anyString(), anyString(), anyLong()))
                .thenReturn(Optional.of(new CbomRuleRolloutLeaseStore.Lease("test-pack@1.3.0", "CANARY", null, "CANARY")));
        assertThat(reconciler.rollout().tenantsVisited()).isZero();
    }

    @Test
    void pinnedLifecycleNotifiesRequiresUpgradeThenForcesCompatibleUpgrade() {
        UUID id = UUID.randomUUID();
        CbomRuleConfiguration pinned = config(id, "PINNED", "1.0.0");
        pinned.setParametersJson("{\"x\":4}");
        stored.put(id, pinned);
        reconciler.setForcedUpgradeGraceDays(30);

        // 1.0.0 deprecated 2026-01-01 and retired 2026-04-15: the first sweep gives the final notice.
        assertThat(reconciler.applyLifecycle(tenant(id), NOW)).isEqualTo("UPGRADE_REQUIRED");
        assertThat(pinned.getPinState()).isEqualTo("UPGRADE_REQUIRED");
        assertThat(reconciler.applyLifecycle(tenant(id), NOW.plusSeconds(86_400))).isEqualTo("NONE");

        assertThat(reconciler.applyLifecycle(tenant(id), NOW.plusSeconds(31L * 86_400))).isEqualTo("FORCED_UPGRADE");
        assertThat(pinned.getPinnedVersion()).isEqualTo("1.2.0");
        assertThat(pinned.getPinState()).isEqualTo("CURRENT");
        assertThat(pinned.getParametersJson()).isEqualTo("{\"x\":4}");
        verify(lifecycle).recordHistory(eq(id), eq("test-pack"), eq("FORCED_UPGRADE"), eq("1.0.0"), eq("1.2.0"), eq("PINNED"),
                eq(CbomRuleRolloutReconciler.SYSTEM_ACTOR), anyString(), anyString(), anyString());
        verify(audit).record(eq("cbom.rules.forced_upgrade"), eq("tenant"), eq(id.toString()), anyString());
    }

    @Test
    void forcedUpgradeFailsClosedWithoutResettingParametersWhenNothingIsCompatible() {
        UUID id = UUID.randomUUID();
        CbomRuleConfiguration pinned = config(id, "PINNED", "1.0.0");
        pinned.setParametersJson("{\"x\":11}");
        pinned.setPinState("UPGRADE_REQUIRED");
        pinned.setUpgradeRequiredAt(NOW.minusSeconds(60L * 86_400));
        stored.put(id, pinned);

        assertThat(reconciler.applyLifecycle(tenant(id), NOW)).isEqualTo("UNSUPPORTED");
        assertThat(pinned.getPinState()).isEqualTo("UNSUPPORTED");
        assertThat(pinned.getPinnedVersion()).isEqualTo("1.0.0");
        assertThat(pinned.getParametersJson()).isEqualTo("{\"x\":11}");
        CbomRulePackageService packages = new CbomRulePackageService(configs, registry);
        org.assertj.core.api.Assertions.assertThatThrownBy(() -> packages.resolve(pinned, NOW))
                .isInstanceOf(CbomRulePackageService.UnsupportedRulePackageException.class);
        assertThat(reconciler.applyLifecycle(tenant(id), NOW)).isEqualTo("NONE");
    }

    @Test
    void deprecatedButNotRetiredPinGetsOneNotice() {
        var deprecating = registry("").find("test-pack", "1.0.0").orElseThrow();
        UUID id = UUID.randomUUID();
        stored.put(id, config(id, "PINNED", deprecating.version()));
        Instant beforeRetirement = Instant.parse("2026-02-01T00:00:00Z");
        assertThat(reconciler.applyLifecycle(tenant(id), beforeRetirement)).isEqualTo("DEPRECATION_NOTICE");
        assertThat(stored.get(id).getPinState()).isEqualTo("DEPRECATED");
        assertThat(reconciler.applyLifecycle(tenant(id), beforeRetirement.plusSeconds(3600))).isEqualTo("NONE");
        verify(lifecycle).recordHistory(eq(id), eq("test-pack"), eq("DEPRECATION_NOTICE"), eq("1.0.0"), isNull(), eq("PINNED"),
                anyString(), anyString(), isNull(), isNull());
    }

    @Test
    void bucketsAreStableAndPackageSpecific() {
        UUID id = UUID.randomUUID();
        assertThat(CbomRuleRolloutReconciler.bucket(id, "p@1.0.0")).isEqualTo(CbomRuleRolloutReconciler.bucket(id, "p@1.0.0"));
        assertThat(CbomRuleRolloutReconciler.bucket(id, "p@1.0.0")).isBetween(0, 99);
    }

    private CbomRulePackageRegistry registry(String overrides) {
        return new CbomRulePackageRegistry(new ObjectMapper(), new DefaultResourceLoader(), "classpath:cbom-rules-test/index.json", overrides);
    }

    private UUID tenantInBucket(String key, boolean inside) {
        while (true) {
            UUID candidate = UUID.randomUUID();
            if ((CbomRuleRolloutReconciler.bucket(candidate, key) < 5) == inside) return candidate;
        }
    }

    private static CbomRuleConfiguration config(UUID id, String policy, String pinned) {
        CbomRuleConfiguration config = new CbomRuleConfiguration();
        config.setTenantId(id);
        config.setPackageId("test-pack");
        config.setVersionPolicy(policy);
        config.setPinnedVersion(pinned);
        return config;
    }

    private static Tenant tenant(UUID id) {
        Tenant tenant = new Tenant();
        tenant.setId(id);
        return tenant;
    }
}
