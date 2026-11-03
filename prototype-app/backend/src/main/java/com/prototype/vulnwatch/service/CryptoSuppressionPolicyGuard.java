package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.CbomTenantSettings;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.repo.CbomTenantSettingsRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class CryptoSuppressionPolicyGuard {
    private final CbomTenantSettingsRepository settingsRepository;
    private final RequestActorService requestActorService;
    private final Clock clock;

    @Autowired
    public CryptoSuppressionPolicyGuard(
            CbomTenantSettingsRepository settingsRepository,
            RequestActorService requestActorService
    ) {
        this(settingsRepository, requestActorService, Clock.systemUTC());
    }

    CryptoSuppressionPolicyGuard(
            CbomTenantSettingsRepository settingsRepository,
            RequestActorService requestActorService,
            Clock clock
    ) {
        this.settingsRepository = settingsRepository;
        this.requestActorService = requestActorService;
        this.clock = clock;
    }

    public void check(Finding finding, Instant suppressedUntil, SuppressionMutationSource source) {
        if (!isCrypto(finding) || source == SuppressionMutationSource.LEGACY_V11_CUTOVER) {
            return;
        }
        if (suppressedUntil == null || !suppressedUntil.isAfter(clock.instant())) {
            deny("FINITE_EXPIRY_REQUIRED", "CRYPTO suppressions require a future expiry");
        }
        String severity = canonicalSeverity(finding);
        CbomTenantSettings settings = settingsRepository.findById(finding.getTenant().getId()).orElse(null);
        int maximumDays = maximumDays(severity, settings);
        if (suppressedUntil.isAfter(clock.instant().plus(Duration.ofDays(maximumDays)))) {
            deny("EXPIRY_EXCEEDS_MAXIMUM", "Suppression exceeds the " + severity + " maximum of " + maximumDays + " days");
        }
        if (("CRITICAL".equals(severity) || "UNKNOWN".equals(severity))
                && source != SuppressionMutationSource.APPROVED_REQUEST) {
            deny("CRITICAL_REQUIRES_APPROVAL",
                    "Critical or unknown-severity CRYPTO findings require an approved suppression request");
        }
        if (settings != null && settings.isRequireDistinctSuppressionApprover()
                && source != SuppressionMutationSource.APPROVED_REQUEST) {
            deny("DISTINCT_APPROVER_REQUIRED", "Tenant policy requires an approved suppression request");
        }
        if (source == SuppressionMutationSource.DIRECT_TENANT_ADMIN) {
            RequestActor actor = requestActorService.currentActor();
            if (actor == null || !actor.hasRole("TENANT_ADMIN") || !actor.hasDirectTenantMembership()
                    || !finding.getTenant().getId().equals(actor.tenantId())) {
                deny("DIRECT_TENANT_ADMIN_REQUIRED", "A directly assigned tenant administrator is required");
            }
        }
    }

    public int maximumDays(Finding finding) {
        CbomTenantSettings settings = settingsRepository.findById(finding.getTenant().getId()).orElse(null);
        return maximumDays(canonicalSeverity(finding), settings);
    }

    public String canonicalSeverity(Finding finding) {
        String value = finding.getSeverityOverride();
        if ((value == null || value.isBlank()) && finding.getVulnerability() != null) {
            value = finding.getVulnerability().getSeverity();
        }
        return value == null || value.isBlank() ? "UNKNOWN" : value.trim().toUpperCase();
    }

    public boolean isCrypto(Finding finding) {
        return finding != null && "CRYPTO".equalsIgnoreCase(finding.getFindingKind());
    }

    private int maximumDays(String severity, CbomTenantSettings settings) {
        return switch (severity) {
            case "LOW" -> settings == null ? 365 : settings.getLowSuppressionMaxDays();
            case "MEDIUM" -> settings == null ? 180 : settings.getMediumSuppressionMaxDays();
            case "HIGH" -> settings == null ? 90 : settings.getHighSuppressionMaxDays();
            case "CRITICAL" -> settings == null ? 30 : settings.getCriticalSuppressionMaxDays();
            default -> 30;
        };
    }

    private void deny(String code, String message) {
        throw new CryptoSuppressionPolicyException(code, message);
    }
}
