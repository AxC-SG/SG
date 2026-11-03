package com.prototype.vulnwatch.dto;

import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

public final class CbomGovernanceDtos {
    private CbomGovernanceDtos() {}
    public record RuleConfiguration(String packageId, String versionPolicy, String pinnedVersion,
                                    Map<String,Integer> parameters, long version, String updatedBy,
                                    String effectiveVersion, String pinState, String remediation,
                                    List<PackageVersion> availableVersions, List<SelectionHistory> history,
                                    List<PackageRule> rules) {}
    /** A rule in the effective package; condition and recommendation carry this workspace's thresholds. */
    public record PackageRule(String id, int version, String mode, String title, String severity, String category,
                              String condition, String recommendation, long openFindings) {}
    public record PackageVersion(String version, String title, String digest, int evaluatorMajor, String rolloutStage,
                                 java.time.Instant deprecatedAt, java.time.Instant retiresAt, boolean pinnable,
                                 String tenantStatus) {}
    public record SelectionHistory(UUID id, String action, String fromVersion, String toVersion, String versionPolicy,
                                   String actor, String reason, String impactJson, java.time.Instant createdAt) {}
    public record RuleConfigurationRequest(String versionPolicy, String pinnedVersion,
                                           Map<String,Integer> parameters, String reason) {}
    public record RuleImpactPreview(int activeComponents, int projectedRsaFindings,
                                    int projectedExpiringCertificateFindings, List<String> safetyBounds,
                                    String fromVersion, String toVersion, List<String> addedRules, List<String> removedRules,
                                    List<String> changedRuleModes, Map<String, List<Integer>> changedParameters,
                                    int currentRsaFindings, int currentExpiringCertificateFindings) {}
    /** quantumSafe: symmetric, hash, MAC or KDF at adequate strength; classicallyWeak: broken today regardless of quantum. */
    public record PqcReadiness(int total, int quantumVulnerable, int pqcReady, int unknown,
                               List<ComponentReadiness> highestPriority, int quantumSafe, int classicallyWeak) {}
    public record ComponentReadiness(UUID componentId, String name, String primitive, String readiness,
                                     String migrationPriority, String reason) {}
    public record GateRequest(UUID assessmentRunId, Set<String> failOnSeverities,
                              BigDecimal minimumCompleteness) {}
    public record GateResult(String outcome, UUID assessmentRunId, List<String> reasons,
                             String rulePackageDigest, String artifactChecksum) {}
}
