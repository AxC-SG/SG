package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.lenient;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.CbomTenantSettingsRepository;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CryptoSuppressionPolicyGuardTest {
    private static final Instant NOW = Instant.parse("2026-11-02T00:00:00Z");
    private static final UUID TENANT_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
    @Mock CbomTenantSettingsRepository settings;
    @Mock RequestActorService actors;
    private CryptoSuppressionPolicyGuard guard;
    private Finding finding;

    @BeforeEach
    void setUp() {
        guard = new CryptoSuppressionPolicyGuard(settings, actors, Clock.fixed(NOW, ZoneOffset.UTC));
        Tenant tenant = new Tenant();
        tenant.setId(TENANT_ID);
        finding = new Finding();
        finding.setTenant(tenant);
        finding.setFindingKind("CRYPTO");
        finding.setSeverityOverride("HIGH");
        lenient().when(settings.findById(TENANT_ID)).thenReturn(Optional.empty());
    }

    @Test
    void rejectsNullExpiry() {
        CryptoSuppressionPolicyException error = assertThrows(CryptoSuppressionPolicyException.class,
                () -> guard.check(finding, null, SuppressionMutationSource.APPROVED_REQUEST));
        assertEquals("FINITE_EXPIRY_REQUIRED", error.getReasonCode());
    }

    @Test
    void criticalAlwaysRequiresApprovedRequest() {
        finding.setSeverityOverride("CRITICAL");
        CryptoSuppressionPolicyException error = assertThrows(CryptoSuppressionPolicyException.class,
                () -> guard.check(finding, NOW.plusSeconds(86400), SuppressionMutationSource.DIRECT_TENANT_ADMIN));
        assertEquals("CRITICAL_REQUIRES_APPROVAL", error.getReasonCode());
    }

    @Test
    void supportSessionCannotUseDirectAdminPath() {
        when(actors.currentActor()).thenReturn(new RequestActor("support", false, TENANT_ID, "tenant",
                Set.of("TENANT_ADMIN"), TenantAccessMode.SUPPORT_WRITE_ENABLED, UUID.randomUUID(), NOW.plusSeconds(3600)));
        CryptoSuppressionPolicyException error = assertThrows(CryptoSuppressionPolicyException.class,
                () -> guard.check(finding, NOW.plusSeconds(86400), SuppressionMutationSource.DIRECT_TENANT_ADMIN));
        assertEquals("DIRECT_TENANT_ADMIN_REQUIRED", error.getReasonCode());
    }

    @Test
    void directTenantAdminCanSuppressNonCriticalWithinMaximum() {
        when(actors.currentActor()).thenReturn(new RequestActor("admin", false, TENANT_ID, "tenant",
                Set.of("TENANT_ADMIN"), TenantAccessMode.TENANT_MEMBERSHIP, null, null));
        assertDoesNotThrow(() -> guard.check(finding, NOW.plusSeconds(86400),
                SuppressionMutationSource.DIRECT_TENANT_ADMIN));
    }

    @Test
    void criticalHighCriticalCannotBeResuppressedWithoutAnotherApproval() {
        finding.setSeverityOverride("CRITICAL");
        assertDoesNotThrow(() -> guard.check(finding, NOW.plusSeconds(86400),
                SuppressionMutationSource.APPROVED_REQUEST));
        finding.setSeverityOverride("HIGH");
        finding.setSeverityOverride("CRITICAL");
        assertThrows(CryptoSuppressionPolicyException.class,
                () -> guard.check(finding, NOW.plusSeconds(86400), SuppressionMutationSource.AUTOMATED_RULE));
    }

    @Test
    void nonCryptoSuppressionBehaviourRemainsCompatible() {
        finding.setFindingKind("VULNERABILITY");
        assertDoesNotThrow(() -> guard.check(finding, null, SuppressionMutationSource.AUTOMATED_RULE));
    }
}
