package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.CbomRuleConfiguration;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.CbomRuleConfigurationRepository;
import java.time.Clock;
import java.time.Instant;
import org.springframework.stereotype.Service;

/**
 * Resolves the tenant's effective application rule package.
 *
 * <ul>
 *   <li>{@code FOLLOW_LATEST}: the version the rollout reconciler last made effective for this
 *       tenant, or the newest GENERAL-stage version when the rollout has not reached it yet.</li>
 *   <li>{@code PINNED}: the pinned version, including a retired one during its forced-upgrade grace
 *       period. An {@code UNSUPPORTED} pin fails closed: assessment stops and the last assessment
 *       is retained, without resetting the tenant's parameters.</li>
 * </ul>
 */
@Service
public class CbomRulePackageService {
    public static final String PACKAGE_ID = "scoutgrid-baseline";

    private final CbomRuleConfigurationRepository repository;
    private final CbomRulePackageRegistry registry;
    private Clock clock = Clock.systemUTC();

    public CbomRulePackageService(CbomRuleConfigurationRepository repository, CbomRulePackageRegistry registry) {
        this.repository = repository;
        this.registry = registry;
    }

    void setClock(Clock value) { clock = value; }

    /** Fail-closed signal: no supported package can evaluate this tenant's pinned configuration. */
    public static class UnsupportedRulePackageException extends IllegalStateException {
        public UnsupportedRulePackageException(String message) { super(message); }
    }

    public EffectivePackage effective(Tenant tenant) {
        CbomRuleConfiguration config = repository.findById(tenant.getId()).orElse(null);
        CbomRulePackageRegistry.RulePackage resolved = resolve(config, Instant.now(clock));
        return new EffectivePackage(resolved.packageId(), resolved.version(), resolved.digest(),
                resolved.evaluatorVersion(), config == null ? "{}" : config.getParametersJson());
    }

    CbomRulePackageRegistry.RulePackage resolve(CbomRuleConfiguration config, Instant now) {
        String packageId = config == null ? PACKAGE_ID : config.getPackageId();
        if (config != null && "PINNED".equals(config.getVersionPolicy())) {
            if ("UNSUPPORTED".equals(config.getPinState())) {
                throw new UnsupportedRulePackageException("Pinned CBOM rule package " + packageId + "@" + config.getPinnedVersion()
                        + " is retired and no compatible supported package exists; update the rule configuration");
            }
            return registry.find(packageId, config.getPinnedVersion())
                    .orElseThrow(() -> new UnsupportedRulePackageException("Pinned CBOM rule package is unavailable: " + config.getPinnedVersion()));
        }
        if (config != null && config.getEffectiveVersion() != null) {
            var recorded = registry.find(packageId, config.getEffectiveVersion()).filter(p -> !p.retired(now));
            if (recorded.isPresent()) return recorded.get();
        }
        return registry.generalDefault(packageId, now)
                .orElseThrow(() -> new UnsupportedRulePackageException("No GENERAL-stage CBOM rule package is available for " + packageId));
    }

    /**
     * The tenant's rule thresholds: the effective package's defaults overlaid with the tenant's
     * stored parameters, each kept inside the package's hard bounds. Out-of-bounds or unknown
     * stored values are ignored rather than trusted.
     */
    public CbomRiskEngine.RuleParameters parameters(Tenant tenant) {
        CbomRuleConfiguration config = repository.findById(tenant.getId()).orElse(null);
        CbomRulePackageRegistry.RulePackage pkg;
        try { pkg = resolve(config, Instant.now(clock)); }
        catch (UnsupportedRulePackageException unsupported) { return CbomRiskEngine.DEFAULTS; }
        java.util.Map<String, Integer> values = pkg.defaults();
        if (config != null && config.getParametersJson() != null) {
            try {
                java.util.Map<String, Integer> stored = MAPPER.readValue(config.getParametersJson(),
                        new com.fasterxml.jackson.core.type.TypeReference<java.util.Map<String, Integer>>() { });
                stored.forEach((name, value) -> {
                    var bounds = pkg.parameters().get(name);
                    if (bounds != null && value != null && value >= bounds.min() && value <= bounds.max()) values.put(name, value);
                });
            } catch (Exception invalid) {
                // Stored JSON that cannot be read leaves the package defaults in force.
            }
        }
        return CbomRiskEngine.RuleParameters.from(values);
    }

    private static final com.fasterxml.jackson.databind.ObjectMapper MAPPER = new com.fasterxml.jackson.databind.ObjectMapper();

    public record EffectivePackage(String id, String version, String digest, String evaluatorVersion, String parametersJson) { }
}
