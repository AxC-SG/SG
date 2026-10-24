package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityRule;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.domain.VersionScheme;
import com.prototype.vulnwatch.dto.AdvisoryBatchRequest;
import com.prototype.vulnwatch.dto.AdvisoryRequest;
import com.prototype.vulnwatch.dto.AdvisoryRuleRequest;
import com.prototype.vulnwatch.dto.IngestionResult;
import com.prototype.vulnwatch.repo.VulnerabilityRuleRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.service.IdentityGraphService;
import com.prototype.vulnwatch.service.ObservationIngestionService;
import com.prototype.vulnwatch.service.VulnerabilityIntelligenceService;
import com.prototype.vulnwatch.util.CpeUtil;
import com.prototype.vulnwatch.util.IdentityUtil;
import jakarta.transaction.Transactional;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;

@Service
public class ManualAdvisoryIngestionService {

    private final ObservationIngestionService observationIngestionService;
    private final VulnerabilityRuleRepository vulnerabilityRuleRepository;
    private final VulnerabilityTargetRepository vulnerabilityTargetRepository;
    private final IdentityGraphService identityGraphService;
    private final VulnerabilityIngestionEffectsService effectsService;
    private final VulnerabilityIngestionCommonSupport support;

    public ManualAdvisoryIngestionService(
            ObservationIngestionService observationIngestionService,
            VulnerabilityRuleRepository vulnerabilityRuleRepository,
            VulnerabilityTargetRepository vulnerabilityTargetRepository,
            IdentityGraphService identityGraphService,
            VulnerabilityIngestionEffectsService effectsService,
            VulnerabilityIngestionCommonSupport support
    ) {
        this.observationIngestionService = observationIngestionService;
        this.vulnerabilityRuleRepository = vulnerabilityRuleRepository;
        this.vulnerabilityTargetRepository = vulnerabilityTargetRepository;
        this.identityGraphService = identityGraphService;
        this.effectsService = effectsService;
        this.support = support;
    }

    private VulnerabilitySyncRunService runs;
    @org.springframework.beans.factory.annotation.Autowired
    void configureRuns(VulnerabilitySyncRunService runs) { this.runs=runs; }

    @Transactional
    public IngestionResult ingestAdvisories(AdvisoryBatchRequest request) {
        var stagingRun=runs.createRunningRun("ADVISORY");
        try {
        List<AdvisoryRequest> advisories = request.advisories() == null ? List.of() : request.advisories();
        int fetched = advisories.size();
        int inserted = 0;
        int updated = 0;
        Set<UUID> changedVulnerabilityIds = new LinkedHashSet<>();

        for (AdvisoryRequest advisory : advisories) {
            String externalId = advisory.externalId() == null || advisory.externalId().isBlank()
                    ? "ADV-" + Instant.now().toEpochMilli() + "-" + inserted
                    : advisory.externalId();
            VulnerabilityIntelligenceService.ObservationUpsertResult upsertResult = observationIngestionService.upsertObservation(
                    new VulnerabilityIntelligenceService.ObservationUpsertRequest(
                            externalId,
                            "advisory",
                            externalId,
                            null,
                            advisory.title() == null ? externalId : advisory.title(),
                            advisory.description(),
                            advisory.severity() == null ? "MEDIUM" : advisory.severity().toUpperCase(Locale.ROOT),
                            advisory.cvssScore(),
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            Instant.now(),
                            support.toJson(advisory)
                    )
            );
            Vulnerability vuln = upsertResult.vulnerability();
            boolean vulnerabilityCreated = upsertResult.vulnerabilityCreated();
            if(Boolean.TRUE.equals(advisory.withdrawn())) { support.withdrawSource(vuln,"advisory",externalId);updated++;continue; }
            support.replaceRules(vuln);
            support.replaceTargets(vuln, List.of("advisory"));

            List<AdvisoryRuleRequest> rules = advisory.rules() == null ? List.of() : advisory.rules();
            for (AdvisoryRuleRequest ruleRequest : rules) {
                VulnerabilityRule rule = new VulnerabilityRule();
                rule.setVulnerability(vuln);
                rule.setEcosystem(ruleRequest.ecosystem() == null ? "generic" : ruleRequest.ecosystem().toLowerCase(Locale.ROOT));
                rule.setPackageName(ruleRequest.packageName() == null ? "unknown" : ruleRequest.packageName().toLowerCase(Locale.ROOT));
                rule.setVersionExact(ruleRequest.versionExact());
                rule.setVersionStart(ruleRequest.versionStart());
                rule.setVersionEnd(ruleRequest.versionEnd());
                rule.setVersionStartInclusive(Boolean.TRUE);
                rule.setVersionEndInclusive(Boolean.TRUE);
                String normalizedRuleCpe = CpeUtil.normalizeCpe23(ruleRequest.cpe());
                rule.setCpe(normalizedRuleCpe);
                if (support.hasText(normalizedRuleCpe)) {
                    CpeUtil.ParsedCpe parsedRuleCpe = CpeUtil.parse(normalizedRuleCpe);
                    rule.setCpeVendor(parsedRuleCpe.vendor());
                    rule.setCpeProduct(parsedRuleCpe.product());
                }
                support.saveRule(rule);

                SoftwareIdentity identity = identityGraphService.resolveFromTarget(
                        rule.getEcosystem(),
                        rule.getPackageName(),
                        null,
                        null,
                        normalizedRuleCpe,
                        null,
                        "advisory"
                );
                support.saveTarget(support.createTarget(
                        vuln,
                        identity,
                        VulnerabilityTargetType.ADVISORY_PACKAGE,
                        IdentityUtil.coordKey(rule.getEcosystem(), rule.getPackageName()),
                        rule.getEcosystem(),
                        null,
                        rule.getPackageName(),
                        null,
                        null,
                        rule.getVersionExact(),
                        rule.getVersionStart(),
                        Boolean.TRUE,
                        rule.getVersionEnd(),
                        Boolean.TRUE,
                        null,
                        null,
                        VersionScheme.UNKNOWN,
                        normalizedRuleCpe,
                        support.cpeWildcardScore(normalizedRuleCpe),
                        null,
                        "advisory",
                        Instant.now().toString()
                ));

                if (support.hasText(normalizedRuleCpe)) {
                    support.saveTarget(support.createTarget(
                            vuln,
                            identity,
                            VulnerabilityTargetType.CPE,
                            normalizedRuleCpe,
                            rule.getEcosystem(),
                            null,
                            rule.getPackageName(),
                            null,
                            normalizedRuleCpe,
                            rule.getVersionExact(),
                            rule.getVersionStart(),
                            Boolean.TRUE,
                            rule.getVersionEnd(),
                            Boolean.TRUE,
                            null,
                            null,
                            VersionScheme.UNKNOWN,
                            normalizedRuleCpe,
                            support.cpeWildcardScore(normalizedRuleCpe),
                            null,
                            "advisory",
                            Instant.now().toString()
                    ));
                }

                String digest = support.normalizeDigestToken(ruleRequest.digest());
                if (support.hasText(digest)) {
                    support.saveTarget(support.createTarget(
                            vuln,
                            identity,
                            VulnerabilityTargetType.DIGEST,
                            digest,
                            rule.getEcosystem(),
                            null,
                            rule.getPackageName(),
                            null,
                            digest,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            VersionScheme.UNKNOWN,
                            null,
                            null,
                            null,
                            "advisory",
                            Instant.now().toString()
                    ));
                }
            }

            if (vulnerabilityCreated) {
                inserted++;
            } else {
                updated++;
            }
            if (vuln.getId() != null) {
                changedVulnerabilityIds.add(vuln.getId());
            }
        }

        effectsService.recomputeCveDeltas(changedVulnerabilityIds);

        runs.completeRun(stagingRun,"completed",fetched,inserted,updated,0,null);
        return new IngestionResult("ok", fetched, inserted, updated, "Advisories ingested");
        } finally { com.prototype.vulnwatch.service.IntelligenceWriteContext.endRun(stagingRun.getId()); }
    }
}
