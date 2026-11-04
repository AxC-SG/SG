package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class LegacyCryptoSuppressionCutoverServiceTest {
    @Mock FindingRepository findings;
    @Mock CryptoSuppressionPolicyGuard guard;
    @Mock CanonicalSuppressionMutationService mutations;
    @Mock TenantWorkRunner tenants;
    @Mock AuditEventService audit;

    @Test
    void reopensCriticalAndBoundsNonCriticalLegacySuppressionsIdempotently() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        Finding critical = legacy(tenant, "CRITICAL");
        Finding high = legacy(tenant, "HIGH");
        when(findings.findTop500ByFindingKindAndStatusAndSuppressedUntilIsNullOrderById(
                "CRYPTO", com.prototype.vulnwatch.domain.FindingStatus.SUPPRESSED))
                .thenReturn(List.of(critical, high));
        when(guard.canonicalSeverity(critical)).thenReturn("CRITICAL");
        when(guard.canonicalSeverity(high)).thenReturn("HIGH");
        when(guard.maximumDays(high)).thenReturn(90);
        when(findings.countLegacyCryptoSuppressions()).thenReturn(0L);
        LegacyCryptoSuppressionCutoverService service = new LegacyCryptoSuppressionCutoverService(
                findings, guard, mutations, tenants, audit, true);
        Instant cutover = Instant.parse("2026-11-02T00:00:00Z");

        var result = service.cutoverCurrentTenant(cutover);

        assertEquals(2, result.examined());
        assertEquals(1, result.reopened());
        assertEquals(1, result.bounded());
        assertEquals(0, result.remainingNullExpiry());
        verify(mutations).reopen(eq(critical), eq("v11-cutover"), any(), any());
        verify(mutations).suppress(eq(high), eq("legacy"), eq(Instant.parse("2027-01-31T00:00:00Z")),
                eq(null), eq(null), eq(SuppressionMutationSource.LEGACY_V11_CUTOVER), eq("v11-cutover"));
    }

    private Finding legacy(Tenant tenant, String severity) {
        Finding finding = new Finding();
        ReflectionTestUtils.setField(finding, "id", UUID.randomUUID());
        finding.setTenant(tenant);
        finding.setFindingKind("CRYPTO");
        finding.setSeverityOverride(severity);
        finding.setSuppressionReason("legacy");
        return finding;
    }
}
