package com.prototype.vulnwatch.dto;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
public record CbomAssessmentResponse(UUID id,UUID bomId,UUID previousBomId,String artifactChecksum,String rulePackageId,
        String rulePackageVersion,String rulePackageDigest,String evaluatorVersion,String status,
        String validationOutcome,int componentCount,int findingCount,BigDecimal confidenceScore,
        BigDecimal completenessScore,Instant startedAt,Instant completedAt,List<ValidationIssue> validationIssues,
        List<ClaimAssurance> claimAssurances) {
    public record ValidationIssue(UUID id,String code,String severity,String jsonPointer,String message){}
    public record ClaimAssurance(UUID id,UUID componentId,String claimPath,String assuranceLevel,String evidenceState,String explanation){}
}
