package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.repo.FindingRepository;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Idempotent V11 data cutover. It runs only after the deployment containing the hardened routes
 * and mirror is live, then converges the null-expiry metric to zero.
 */
@Service
public class LegacyCryptoSuppressionCutoverService {
    private static final Logger LOG = LoggerFactory.getLogger(LegacyCryptoSuppressionCutoverService.class);
    private final FindingRepository findingRepository;
    private final CryptoSuppressionPolicyGuard policyGuard;
    private final CanonicalSuppressionMutationService mutationService;
    private final TenantWorkRunner tenantWorkRunner;
    private final AuditEventService auditEventService;
    private final boolean enabled;
    private final AtomicLong remainingNullExpiry = new AtomicLong();

    public LegacyCryptoSuppressionCutoverService(
            FindingRepository findingRepository,
            CryptoSuppressionPolicyGuard policyGuard,
            CanonicalSuppressionMutationService mutationService,
            TenantWorkRunner tenantWorkRunner,
            AuditEventService auditEventService,
            @Value("${app.cbom.legacy-suppression-cutover.enabled:true}") boolean enabled
    ) {
        this.findingRepository = findingRepository;
        this.policyGuard = policyGuard;
        this.mutationService = mutationService;
        this.tenantWorkRunner = tenantWorkRunner;
        this.auditEventService = auditEventService;
        this.enabled = enabled;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void registerMetrics(ObjectProvider<MeterRegistry> registryProvider) {
        MeterRegistry registry = registryProvider.getIfAvailable();
        if (registry != null) {
            Gauge.builder("cbom.suppression.legacy_null_expiry.remaining", remainingNullExpiry, AtomicLong::get)
                    .description("Legacy CRYPTO suppressions that still have no expiry after the V11 cutover")
                    .register(registry);
        }
    }

    @Scheduled(zone = "UTC", cron = "${app.cbom.legacy-suppression-cutover.cron:0 */10 * * * *}")
    public void run() {
        if (!enabled) return;
        remainingNullExpiry.set(0);
        tenantWorkRunner.forEachActiveTenant(tenant -> {
            CutoverResult result = cutoverCurrentTenant(Instant.now());
            remainingNullExpiry.addAndGet(result.remainingNullExpiry());
            if (result.examined() > 0 || result.remainingNullExpiry() > 0) {
                LOG.info("V11 CRYPTO suppression cutover tenant={} examined={} reopened={} bounded={} remaining={}",
                        tenant.getId(), result.examined(), result.reopened(), result.bounded(), result.remainingNullExpiry());
            }
        });
    }

    @Transactional
    public CutoverResult cutoverCurrentTenant(Instant cutoverAt) {
        List<Finding> legacy = findingRepository.findTop500ByFindingKindAndStatusAndSuppressedUntilIsNullOrderById(
                "CRYPTO", com.prototype.vulnwatch.domain.FindingStatus.SUPPRESSED);
        int reopened = 0;
        int bounded = 0;
        for (Finding finding : legacy) {
            String severity = policyGuard.canonicalSeverity(finding);
            if ("CRITICAL".equals(severity) || "UNKNOWN".equals(severity)) {
                mutationService.reopen(finding, "v11-cutover", "LEGACY_CRYPTO_SUPPRESSION_REOPENED",
                        "Legacy CRYPTO suppression reopened by V11 cutover");
                reopened++;
            } else {
                Instant expiry = cutoverAt.plus(policyGuard.maximumDays(finding), ChronoUnit.DAYS);
                mutationService.suppress(finding, finding.getSuppressionReason(), expiry,
                        finding.getSuppressedByRuleId(), finding.getSuppressedByRuleName(),
                        SuppressionMutationSource.LEGACY_V11_CUTOVER, "v11-cutover");
                bounded++;
            }
            auditEventService.record("finding.suppression.v11_cutover", "finding", finding.getId().toString(),
                    "{\"severity\":\"" + severity + "\",\"migration\":\"V11\"}");
        }
        return new CutoverResult(legacy.size(), reopened, bounded, findingRepository.countLegacyCryptoSuppressions());
    }

    public record CutoverResult(int examined, int reopened, int bounded, long remainingNullExpiry) {}
}
