package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantEntitlementService.ShadowMismatch;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * Verifies the three-state entitlement resolver against the real seeded platform tables:
 * the six existing ai.* keys are enabled for the PRO plan, ai.security is disabled for every plan,
 * and rollout mode plus the canary allowlist gate enforcement. Requires the {@code postgres-it}
 * profile / a local PostgreSQL (see backend/src/test/.../support/README.md).
 */
@PostgresIntegrationTest
class EntitlementResolutionPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("entitlement_resolution");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private NamedParameterJdbcTemplate jdbcTemplate;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private TenantService tenantService;

    private TenantEntitlementService service(String mode, String allowlist, MeterRegistry registry) {
        return new TenantEntitlementService(jdbcTemplate, objectMapper, registry, mode, allowlist);
    }

    private Tenant proTenant(String label) {
        String slug = label + "-" + UUID.randomUUID();
        return TenantContext.runAsPlatform(() -> tenantService.createTenant("Ent " + slug, slug, "pro", null));
    }

    @Test
    void legacyModeResolvesEverythingEnabled() {
        Tenant tenant = proTenant("legacy");
        TenantEntitlementService svc = service("LEGACY", "", new SimpleMeterRegistry());
        TenantContext.runAsPlatform(() -> {
            assertTrue(svc.isEnabled(tenant, TenantEntitlementService.AI_SECURITY));
            assertTrue(svc.isEnabled(tenant, TenantEntitlementService.AI_INVESTIGATION_SUMMARY));
            return null;
        });
    }

    @Test
    void shadowKeepsLegacyEnabledButRecordsMismatchForDisabledPlanKey() {
        Tenant tenant = proTenant("shadow");
        MeterRegistry registry = new SimpleMeterRegistry();
        TenantEntitlementService svc = service("SHADOW", "", registry);
        TenantContext.runAsPlatform(() -> {
            // ai.security is disabled at the plan level, but SHADOW still enforces legacy(true).
            assertTrue(svc.isEnabled(tenant, TenantEntitlementService.AI_SECURITY));
            return null;
        });
        assertTrue(registry.find("entitlement.resolution.mismatch")
                .tag("key", TenantEntitlementService.AI_SECURITY)
                .counter()
                .count() >= 1.0);
    }

    @Test
    void enforceDisablesAiSecurityButKeepsExistingAiForAllowlistedTenant() {
        Tenant tenant = proTenant("enforce");
        TenantEntitlementService svc = service("ENFORCE", tenant.getId().toString(), new SimpleMeterRegistry());
        TenantContext.runAsPlatform(() -> {
            assertFalse(svc.isEnabled(tenant, TenantEntitlementService.AI_SECURITY));
            assertTrue(svc.isEnabled(tenant, TenantEntitlementService.AI_INVESTIGATION_SUMMARY));
            return null;
        });
    }

    @Test
    void enforceLeavesNonAllowlistedTenantOnLegacy() {
        Tenant tenant = proTenant("noncanary");
        TenantEntitlementService svc = service("ENFORCE", UUID.randomUUID().toString(), new SimpleMeterRegistry());
        TenantContext.runAsPlatform(() -> {
            // Not in the allowlist: behaves as SHADOW, so legacy(true) still wins.
            assertTrue(svc.isEnabled(tenant, TenantEntitlementService.AI_SECURITY));
            return null;
        });
    }

    @Test
    void enforceWildcardIsRejectedInsteadOfEnablingAnUnnamedCohort() {
        org.junit.jupiter.api.Assertions.assertThrows(IllegalStateException.class,() -> service("ENFORCE","*",new SimpleMeterRegistry()));
    }

    @Test
    void explicitFalseOverrideDisablesEnabledPlanKeyUnderEnforce() {
        Tenant tenant = proTenant("override");
        TenantEntitlementService svc = service("ENFORCE", tenant.getId().toString(), new SimpleMeterRegistry());
        TenantContext.runAsPlatform(() -> {
            svc.upsertOverride(tenant.getId(), TenantEntitlementService.AI_INVESTIGATION_SUMMARY,
                    false, Map.of(), "test", null, null);
            assertFalse(svc.isEnabled(tenant, TenantEntitlementService.AI_INVESTIGATION_SUMMARY));
            return null;
        });
    }

    @Test
    void expiredOverridesFallBackToPlanInBothDirections() {
        Tenant tenant = proTenant("expired");
        TenantEntitlementService svc = service("ENFORCE", tenant.getId().toString(), new SimpleMeterRegistry());
        Instant past = Instant.now().minusSeconds(3600);
        TenantContext.runAsPlatform(() -> {
            // Expired override disabling an existing AI key -> falls back to the enabled plan state.
            svc.upsertOverride(tenant.getId(), TenantEntitlementService.AI_INVESTIGATION_SUMMARY,
                    false, Map.of(), "expired", past, null);
            assertTrue(svc.isEnabled(tenant, TenantEntitlementService.AI_INVESTIGATION_SUMMARY));
            // Expired override enabling ai.security -> falls back to the disabled plan state.
            svc.upsertOverride(tenant.getId(), TenantEntitlementService.AI_SECURITY,
                    true, Map.of(), "expired", past, null);
            assertFalse(svc.isEnabled(tenant, TenantEntitlementService.AI_SECURITY));
            return null;
        });
    }

    @Test
    void platformNullContextHasEmptySnapshotAndFailsClosedUnderEnforce() {
        TenantEntitlementService svc = service("ENFORCE", "slug:scoutgrid-internal-pilot", new SimpleMeterRegistry());
        assertTrue(svc.snapshot(null).isEmpty());
        assertFalse(svc.isEnabled(null, TenantEntitlementService.AI_INVESTIGATION_SUMMARY));
    }

    @Test
    void detectShadowMismatchesReturnsDisabledKeysOnly() {
        Tenant tenant = proTenant("sweep");
        TenantEntitlementService svc = service("SHADOW", "", new SimpleMeterRegistry());
        List<ShadowMismatch> mismatches = TenantContext.runAsPlatform(() -> svc.detectShadowMismatches(tenant));
        assertTrue(mismatches.stream().anyMatch(m -> m.key().equals(TenantEntitlementService.AI_SECURITY)));
        assertFalse(mismatches.stream()
                .anyMatch(m -> m.key().equals(TenantEntitlementService.AI_INVESTIGATION_SUMMARY)));
    }

    @Test
    void unknownKeyResolvesDisabledUnderEnforce() {
        Tenant tenant = proTenant("unknown");
        TenantEntitlementService svc = service("ENFORCE", tenant.getId().toString(), new SimpleMeterRegistry());
        TenantContext.runAsPlatform(() -> {
            assertFalse(svc.isEnabled(tenant, "ai.nonexistent_capability"));
            return null;
        });
    }

    @Test
    void invalidModeFailsFast() {
        assertThrows(IllegalStateException.class,
                () -> new TenantEntitlementService(jdbcTemplate, objectMapper, new SimpleMeterRegistry(), "BOGUS", ""));
    }
}
