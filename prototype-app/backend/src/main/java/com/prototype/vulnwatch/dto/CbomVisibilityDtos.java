package com.prototype.vulnwatch.dto;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Tenant CBOM visibility contracts: executive overview, trends, analyst inventory and evidence drawer. */
public final class CbomVisibilityDtos {
    private CbomVisibilityDtos() { }

    public record Overview(Instant observedAt, Risk risk, Assurance assurance, Remediation remediation,
            Rotation rotation, Pqc pqc, List<ProductionAsset> productionAssetsAtRisk, Map<String, Integer> componentsByType,
            String cryptoExposureNote) { }

    /** Open, supported CBOM findings on active components. */
    public record Risk(int openCritical, int openHigh, int openMedium, int openLow, BigDecimal averagePostureScore,
            int assetsWithCriticalOrHigh, int productionAssetsWithCriticalOrHigh) { }

    /** Confidence/completeness come from the latest successful assessment of each active CBOM. */
    public record Assurance(int activeArtifacts, int assessedArtifacts, BigDecimal assessmentCoverage,
            BigDecimal averageConfidence, BigDecimal averageCompleteness, Map<String, Integer> claimsByAssurance) { }

    /** Canonical CRYPTO finding workflow state. slaCompliance is null when nothing is open. */
    public record Remediation(int open, int overdue, BigDecimal slaCompliance, int suppressed,
            int suppressionsExpiringIn30Days, int resolvedLast30Days) { }

    public record Rotation(int expired, int expiringIn30Days, int expiringIn60Days, int expiringIn90Days) { }

    public record Pqc(int quantumVulnerableFindings, int quantumVulnerableComponents) { }

    public record ProductionAsset(UUID assetId, String name, String environment, int critical, int high) { }

    public record TrendPoint(LocalDate date, boolean live, int activeComponents, int activeArtifacts, int assessedArtifacts,
            int openCritical, int openHigh, int openMedium, int openLow, int quantumVulnerable,
            BigDecimal averageRiskScore, BigDecimal averageConfidence, BigDecimal averageCompleteness,
            int openCryptoFindings, int overdueCryptoFindings, int suppressedCryptoFindings) { }

    public record Trends(int days, List<TrendPoint> points) { }

    public record InventoryItem(UUID id, String name, String assetType, String primitive, Integer keySize, String curve,
            String protocolVersion, String storageLocation, LocalDate notAfter, BigDecimal riskScore, UUID assetId,
            String assetName, String environment, UUID sourceBomId, String sourceDocument, int openFindings,
            String highestSeverity, String evidenceState) { }

    /** total is exact up to totalCap; above it, totalCapped is true and total equals the cap. */
    public record InventoryPage(List<InventoryItem> items, int page, int size, long total, boolean totalCapped, boolean hasNext) { }

    public record ComponentDetail(InventoryItem component, Map<String, Object> properties, Provenance provenance,
            List<Claim> claims, List<FindingEvidence> findings, List<Relationship> relationships) { }

    public record Provenance(UUID bomId, String documentName, String serialNumber, String checksumSha256, String sourceType,
            String sourceMethod, String sourceLabel, String bomStatus, Instant ingestedAt, UUID assessmentRunId,
            String rulePackage, String rulePackageDigest, String evaluatorVersion, Instant assessedAt) { }

    public record Claim(String claimPath, String assuranceLevel, String evidenceState, String explanation) { }

    public record FindingEvidence(UUID id, String ruleId, String ruleVersion, String severity, String riskClass, String title,
            String detail, String evidence, String recommendation, String status, String evidenceState,
            Instant firstSeenAt, Instant lastSeenAt, CanonicalFinding canonical) { }

    public record CanonicalFinding(UUID id, String displayId, String status, String assignedTo, Instant dueAt,
            Instant suppressedUntil) { }

    public record Relationship(String direction, String relationshipType, String otherType, UUID otherId, String otherName,
            String evidenceKind) { }
}
