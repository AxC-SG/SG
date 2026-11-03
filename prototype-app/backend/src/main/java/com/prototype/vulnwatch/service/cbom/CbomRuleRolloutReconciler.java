package com.prototype.vulnwatch.service.cbom;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.BomStatus;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.CbomRuleConfiguration;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.CbomRuleConfigurationRepository;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.BackgroundTaskExecutionPolicy;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantService;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Advances packaged CBOM rule packages across the fleet (plan section 5.3) and runs the pinned
 * package deprecation/forced-upgrade lifecycle.
 *
 * <p><b>Rollout.</b> For each package's newest version the release-configured stage decides which
 * {@code FOLLOW_LATEST} tenants move: OBSERVE none, CANARY a deterministic hash bucket below
 * {@code canary-percent}, BATCHED below {@code batched-percent}, GENERAL all. Every tenant records
 * availability; pinned tenants are told an upgrade exists but their behaviour is unchanged. Work is
 * bounded per run by global tenant and job ceilings, and guarded by a durable platform lease whose
 * committed cursor lets another instance resume after the owner dies. Moved tenants get bounded
 * reassessment through the durable backfill; a tenant whose backfill did not finish within the job
 * budget is revisited before the cursor passes it.
 *
 * <p><b>Lifecycle.</b> A pinned version past {@code deprecatedAt} gets a recorded notice. Past
 * {@code retiresAt} the pin becomes UPGRADE_REQUIRED (final notice); after the grace period an
 * audited system action moves it to the lowest compatible supported version, or marks it
 * UNSUPPORTED (fail closed, parameters untouched) when none exists.
 */
@Service
public class CbomRuleRolloutReconciler {
    private static final Logger LOG = LoggerFactory.getLogger(CbomRuleRolloutReconciler.class);
    static final String SYSTEM_ACTOR = "system:cbom-rule-lifecycle";

    private final CbomRulePackageRegistry registry;
    private final CbomRulePackageService packages;
    private final CbomRuleConfigurationRepository configs;
    private final CbomRuleLifecycleStore lifecycle;
    private final CbomRuleRolloutLeaseStore leases;
    private final CbomAssessmentBackfillService backfill;
    private final BomIngestionRecordRepository boms;
    private final TenantService tenants;
    private final TenantSchemaExecutionService schemas;
    private final TransactionTemplate transactions;
    private final AuditEventService audit;
    private final ObjectMapper mapper;
    private BackgroundTaskExecutionPolicy policy = BackgroundTaskExecutionPolicy.allowAll();
    private Clock clock = Clock.systemUTC();
    private final String owner = "cbom-rollout-" + UUID.randomUUID();

    private boolean enabled = true;
    private int tenantsPerMinute = 20;
    private int jobsPerMinute = 200;
    private int canaryPercent = 5;
    private int batchedPercent = 50;
    private long leaseTtlSeconds = 300;
    private long forcedUpgradeGraceDays = 30;

    public CbomRuleRolloutReconciler(CbomRulePackageRegistry registry, CbomRulePackageService packages,
            CbomRuleConfigurationRepository configs, CbomRuleLifecycleStore lifecycle, CbomRuleRolloutLeaseStore leases,
            CbomAssessmentBackfillService backfill, BomIngestionRecordRepository boms, TenantService tenants,
            TenantSchemaExecutionService schemas, TransactionTemplate transactions, AuditEventService audit, ObjectMapper mapper) {
        this.registry = registry; this.packages = packages; this.configs = configs; this.lifecycle = lifecycle;
        this.leases = leases; this.backfill = backfill; this.boms = boms; this.tenants = tenants; this.schemas = schemas;
        this.transactions = transactions; this.audit = audit; this.mapper = mapper;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy value) {
        policy = value == null ? BackgroundTaskExecutionPolicy.allowAll() : value;
    }
    void setClock(Clock value) { clock = value; packages.setClock(value); }
    @Value("${app.cbom.rules.rollout.enabled:true}") public void setEnabled(boolean value) { enabled = value; }
    @Value("${app.cbom.rules.rollout.tenants-per-minute:20}") public void setTenantsPerMinute(int value) { tenantsPerMinute = Math.max(1, value); }
    @Value("${app.cbom.rules.rollout.jobs-per-minute:200}") public void setJobsPerMinute(int value) { jobsPerMinute = Math.max(1, value); }
    @Value("${app.cbom.rules.rollout.canary-percent:5}") public void setCanaryPercent(int value) { canaryPercent = clampPercent(value); }
    @Value("${app.cbom.rules.rollout.batched-percent:50}") public void setBatchedPercent(int value) { batchedPercent = clampPercent(value); }
    @Value("${app.cbom.rules.rollout.lease-ttl-seconds:300}") public void setLeaseTtlSeconds(long value) { leaseTtlSeconds = Math.max(30, value); }
    @Value("${app.cbom.rules.forced-upgrade-grace-days:30}") public void setForcedUpgradeGraceDays(long value) { forcedUpgradeGraceDays = Math.max(0, value); }

    public record RunSummary(int tenantsVisited, int tenantsUpgraded, int jobsEnqueued, List<String> skippedPackages) { }

    /** Runs once a minute, so the per-run ceilings are the per-minute fleet ceilings. */
    @Scheduled(fixedDelayString = "${app.cbom.rules.rollout.interval-ms:60000}",
            initialDelayString = "${app.cbom.rules.rollout.initial-delay-ms:60000}")
    public void scheduledRollout() {
        if (!enabled || !policy.allowsBackgroundTask("cbom-rules.rollout")) return;
        try { rollout(); } catch (RuntimeException failure) { LOG.warn("CBOM rule rollout failed: {}", failure.getMessage(), failure); }
    }

    @Scheduled(fixedDelayString = "${app.cbom.rules.lifecycle.interval-ms:3600000}",
            initialDelayString = "${app.cbom.rules.lifecycle.initial-delay-ms:120000}")
    public void scheduledLifecycle() {
        if (!enabled || !policy.allowsBackgroundTask("cbom-rules.lifecycle")) return;
        try { lifecycleSweep(); } catch (RuntimeException failure) { LOG.warn("CBOM rule lifecycle sweep failed: {}", failure.getMessage(), failure); }
    }

    public RunSummary rollout() {
        Budget budget = new Budget(tenantsPerMinute, jobsPerMinute);
        List<String> skipped = new ArrayList<>();
        int[] totals = new int[2];
        List<Tenant> active = TenantContext.runAsPlatform(() -> tenants.listActiveTenants()).stream()
                .sorted(Comparator.comparing(Tenant::getId)).toList();
        Set<String> packageIds = new LinkedHashSet<>();
        registry.all().forEach(p -> packageIds.add(p.packageId()));
        Instant now = Instant.now(clock);
        for (String packageId : packageIds) {
            var target = registry.newest(packageId).orElse(null);
            if (target == null || target.retired(now)) continue;
            var lease = leases.acquire(target.key(), owner, target.stage().name(), leaseTtlSeconds).orElse(null);
            if (lease == null) { skipped.add(target.key() + ":leased-elsewhere"); continue; }
            try {
                if (target.stage().name().equals(lease.completedStage())) continue;
                boolean finished = true;
                for (Tenant tenant : active) {
                    if (lease.cursorTenantId() != null && tenant.getId().compareTo(lease.cursorTenantId()) <= 0) continue;
                    if (budget.tenants <= 0) { finished = false; break; }
                    budget.tenants--;
                    totals[0]++;
                    TenantOutcome outcome = schemas.run(tenant, () -> transactions.execute(tx -> applyRollout(tenant, target, now)));
                    if (outcome.upgraded()) totals[1]++;
                    int enqueued = 0;
                    if (outcome.reassess()) {
                        if (budget.jobs <= 0) { finished = false; break; }
                        int limit = budget.jobs;
                        enqueued = backfill.start(tenant, "cbom-rule-rollout", limit).enqueued();
                        budget.jobs -= enqueued;
                        if (enqueued >= limit) { finished = false; break; }
                    }
                    if (!leases.commitCursor(target.key(), owner, tenant.getId(), enqueued, leaseTtlSeconds)) {
                        LOG.warn("CBOM rule rollout lease for {} was lost; stopping", target.key());
                        finished = false;
                        break;
                    }
                }
                if (finished) leases.completePass(target.key(), owner);
            } finally {
                leases.release(target.key(), owner);
            }
        }
        return new RunSummary(totals[0], totals[1], jobsPerMinute - budget.jobs, skipped);
    }

    record TenantOutcome(boolean upgraded, boolean reassess) { }

    /** Idempotent per-tenant step; runs inside the tenant's schema and transaction. */
    TenantOutcome applyRollout(Tenant tenant, CbomRulePackageRegistry.RulePackage target, Instant now) {
        CbomRuleConfiguration config = configs.findById(tenant.getId()).orElse(null);
        boolean pinned = config != null && "PINNED".equals(config.getVersionPolicy());
        CbomRulePackageRegistry.RulePackage current;
        if (pinned) {
            try { current = packages.resolve(config, now); } catch (CbomRulePackageService.UnsupportedRulePackageException e) { current = null; }
        } else {
            // Compare against what the rollout last recorded, not the GENERAL default: once the target
            // reaches GENERAL the default already equals it, which would skip reassessment. A tenant
            // never recorded is on the original baseline package.
            String recorded = config == null ? null : config.getEffectiveVersion();
            current = (recorded == null ? null : registry.find(target.packageId(), recorded).orElse(null));
            if (current == null) current = registry.oldest(target.packageId()).orElse(null);
        }
        int order = current == null ? 1 : CbomRulePackageRegistry.compareVersions(target.version(), current.version());
        if (pinned) {
            lifecycle.recordAvailability(tenant.getId(), target, order > 0 ? "DEFERRED_PINNED" : "EFFECTIVE");
            if (order > 0 && "CURRENT".equals(config.getPinState())) {
                config.setPinState("UPGRADE_AVAILABLE");
                config.touch();
                configs.save(config);
                lifecycle.recordHistory(tenant.getId(), target.packageId(), "UPGRADE_AVAILABLE", config.getPinnedVersion(),
                        target.version(), "PINNED", SYSTEM_ACTOR, "A newer rule package is available; the pinned version stays effective", null, null);
            }
            return new TenantOutcome(false, false);
        }
        boolean eligible = eligible(tenant.getId(), target);
        if (eligible && order > 0) {
            if (config == null) { config = new CbomRuleConfiguration(); config.setTenantId(tenant.getId()); config.setPackageId(target.packageId()); }
            String from = current == null ? null : current.version();
            config.setEffectiveVersion(target.version());
            config.setPinState("CURRENT");
            config.touch();
            configs.save(config);
            lifecycle.recordAvailability(tenant.getId(), target, "EFFECTIVE");
            lifecycle.recordHistory(tenant.getId(), target.packageId(), "ROLLOUT_UPGRADE", from, target.version(), "FOLLOW_LATEST",
                    SYSTEM_ACTOR, "Rollout stage " + target.stage() + " moved this FOLLOW_LATEST tenant", config.getParametersJson(),
                    impact(current, target, tenant));
            audit.record("cbom.rules.rollout_upgrade", "tenant", tenant.getId().toString(),
                    "{\"from\":" + quote(from) + ",\"to\":" + quote(target.version()) + ",\"stage\":\"" + target.stage() + "\"}");
            return new TenantOutcome(true, true);
        }
        lifecycle.recordAvailability(tenant.getId(), target, order > 0 ? "AVAILABLE" : "EFFECTIVE");
        // A tenant moved by an earlier pass whose reassessment did not finish is revisited.
        boolean movedByRollout = order == 0 && lifecycle.hasHistory(tenant.getId(), "ROLLOUT_UPGRADE", target.version());
        return new TenantOutcome(false, movedByRollout);
    }

    /** Deterministic per-package bucket so the canary set is stable but differs between packages. */
    boolean eligible(UUID tenantId, CbomRulePackageRegistry.RulePackage pkg) {
        return switch (pkg.stage()) {
            case OBSERVE -> false;
            case CANARY -> bucket(tenantId, pkg.key()) < canaryPercent;
            case BATCHED -> bucket(tenantId, pkg.key()) < batchedPercent;
            case GENERAL -> true;
        };
    }

    static int bucket(UUID tenantId, String packageKey) {
        try {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest((tenantId + ":" + packageKey).getBytes(StandardCharsets.UTF_8));
            int value = ((hash[0] & 0xff) << 24) | ((hash[1] & 0xff) << 16) | ((hash[2] & 0xff) << 8) | (hash[3] & 0xff);
            return Math.floorMod(value, 100);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public record LifecycleSummary(int noticed, int upgradeRequired, int forcedUpgrades, int unsupported) { }

    public LifecycleSummary lifecycleSweep() {
        int[] counts = new int[4];
        Instant now = Instant.now(clock);
        for (Tenant tenant : TenantContext.runAsPlatform(() -> tenants.listActiveTenants())) {
            try {
                String action = schemas.run(tenant, () -> transactions.execute(tx -> applyLifecycle(tenant, now)));
                switch (action) {
                    case "DEPRECATION_NOTICE" -> counts[0]++;
                    case "UPGRADE_REQUIRED" -> counts[1]++;
                    case "FORCED_UPGRADE" -> {
                        counts[2]++;
                        backfill.start(tenant, "cbom-rule-forced-upgrade", jobsPerMinute);
                    }
                    case "UNSUPPORTED" -> counts[3]++;
                    default -> { }
                }
            } catch (RuntimeException failure) {
                LOG.warn("CBOM rule lifecycle failed for tenant {}: {}", tenant.getId(), failure.getMessage());
            }
        }
        return new LifecycleSummary(counts[0], counts[1], counts[2], counts[3]);
    }

    /** Returns the lifecycle action taken for one pinned tenant, or NONE. */
    String applyLifecycle(Tenant tenant, Instant now) {
        CbomRuleConfiguration config = configs.findById(tenant.getId()).orElse(null);
        if (config == null || !"PINNED".equals(config.getVersionPolicy()) || "UNSUPPORTED".equals(config.getPinState())) return "NONE";
        var pinned = registry.find(config.getPackageId(), config.getPinnedVersion()).orElse(null);
        if (pinned == null) return markUnsupported(tenant, config, "The pinned rule package is no longer packaged");
        if (pinned.retired(now)) {
            if (config.getUpgradeRequiredAt() == null) {
                config.setUpgradeRequiredAt(now);
                config.setPinState("UPGRADE_REQUIRED");
                save(config);
                lifecycle.recordHistory(tenant.getId(), pinned.packageId(), "UPGRADE_REQUIRED", pinned.version(), null, "PINNED", SYSTEM_ACTOR,
                        "Final notice: the pinned package retired at " + pinned.retiresAt() + "; an automatic compatible upgrade follows after "
                                + forcedUpgradeGraceDays + " days", null, null);
                audit.record("cbom.rules.upgrade_required", "tenant", tenant.getId().toString(), "{\"pinnedVersion\":" + quote(pinned.version()) + "}");
                return "UPGRADE_REQUIRED";
            }
            if (now.isBefore(config.getUpgradeRequiredAt().plus(Duration.ofDays(forcedUpgradeGraceDays)))) return "NONE";
            Map<String, Integer> parameters = parameters(config);
            var candidate = registry.lowestCompatibleUpgrade(pinned, parameters, now).orElse(null);
            if (candidate == null) {
                return markUnsupported(tenant, config, "No supported package on evaluator major " + pinned.evaluatorMajor()
                        + " accepts the configured parameters and keeps every mandatory rule");
            }
            String impact = impact(pinned, candidate, tenant);
            config.setPinnedVersion(candidate.version());
            config.setPinState("CURRENT");
            config.setDeprecationNoticeAt(null);
            config.setUpgradeRequiredAt(null);
            config.setUpdatedBy(SYSTEM_ACTOR);
            save(config);
            lifecycle.recordAvailability(tenant.getId(), candidate, "EFFECTIVE");
            lifecycle.recordHistory(tenant.getId(), pinned.packageId(), "FORCED_UPGRADE", pinned.version(), candidate.version(), "PINNED",
                    SYSTEM_ACTOR, "Retired pinned package moved to the lowest compatible supported version after the grace period",
                    config.getParametersJson(), impact);
            audit.record("cbom.rules.forced_upgrade", "tenant", tenant.getId().toString(), impact);
            return "FORCED_UPGRADE";
        }
        if (pinned.deprecated(now) && config.getDeprecationNoticeAt() == null) {
            config.setDeprecationNoticeAt(now);
            config.setPinState("DEPRECATED");
            save(config);
            lifecycle.recordHistory(tenant.getId(), pinned.packageId(), "DEPRECATION_NOTICE", pinned.version(), null, "PINNED", SYSTEM_ACTOR,
                    "The pinned package is deprecated and retires at " + pinned.retiresAt(), null, null);
            audit.record("cbom.rules.deprecation_notice", "tenant", tenant.getId().toString(),
                    "{\"pinnedVersion\":" + quote(pinned.version()) + ",\"retiresAt\":" + quote(String.valueOf(pinned.retiresAt())) + "}");
            return "DEPRECATION_NOTICE";
        }
        return "NONE";
    }

    private String markUnsupported(Tenant tenant, CbomRuleConfiguration config, String reason) {
        config.setPinState("UNSUPPORTED");
        save(config);
        lifecycle.recordHistory(tenant.getId(), config.getPackageId(), "UNSUPPORTED", config.getPinnedVersion(), null, "PINNED",
                SYSTEM_ACTOR, reason + "; assessment is paused and the last assessment is retained as stale", config.getParametersJson(), null);
        audit.record("cbom.rules.unsupported", "tenant", tenant.getId().toString(), "{\"pinnedVersion\":" + quote(config.getPinnedVersion()) + "}");
        return "UNSUPPORTED";
    }

    /** Before/after summary: rule additions/removals and how many active CBOMs will be reassessed. */
    private String impact(CbomRulePackageRegistry.RulePackage from, CbomRulePackageRegistry.RulePackage to, Tenant tenant) {
        Set<String> before = new LinkedHashSet<>();
        if (from != null) from.rules().forEach(r -> before.add(r.id()));
        Set<String> after = new LinkedHashSet<>();
        to.rules().forEach(r -> after.add(r.id()));
        Set<String> added = new LinkedHashSet<>(after); added.removeAll(before);
        Set<String> removed = new LinkedHashSet<>(before); removed.removeAll(after);
        long activeCboms = boms.findByTenant_IdAndStatus(tenant.getId(), BomStatus.ACTIVE).stream()
                .filter(b -> b.getBomType() == BomType.CBOM).count();
        Map<String, Object> impact = new LinkedHashMap<>();
        impact.put("fromVersion", from == null ? null : from.version());
        impact.put("toVersion", to.version());
        impact.put("fromDigest", from == null ? null : from.digest());
        impact.put("toDigest", to.digest());
        impact.put("addedRules", added);
        impact.put("removedRules", removed);
        impact.put("activeCbomArtifactsToReassess", activeCboms);
        return write(impact);
    }

    private Map<String, Integer> parameters(CbomRuleConfiguration config) {
        try { return mapper.readValue(config.getParametersJson(), new TypeReference<Map<String, Integer>>() { }); }
        catch (Exception e) { throw new IllegalStateException("Invalid stored CBOM rule configuration", e); }
    }

    private void save(CbomRuleConfiguration config) { config.touch(); configs.save(config); }
    private String write(Object value) { try { return mapper.writeValueAsString(value); } catch (Exception e) { throw new IllegalStateException(e); } }
    private String quote(String value) { return value == null ? "null" : write(value); }
    private static int clampPercent(int value) { return Math.max(0, Math.min(100, value)); }

    private static final class Budget {
        int tenants; int jobs;
        Budget(int tenants, int jobs) { this.tenants = tenants; this.jobs = jobs; }
    }
}
