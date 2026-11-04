package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "cbom_assessment_runs")
public class CbomAssessmentRun {
    @Id private UUID id = UUID.randomUUID();
    @ManyToOne(optional = false) @JoinColumn(name = "tenant_id") private Tenant tenant;
    @ManyToOne(optional = false) @JoinColumn(name = "bom_id") private BomIngestionRecord bom;
    @Column(name = "artifact_checksum", nullable = false, length = 128) private String artifactChecksum;
    @Column(name = "rule_package_id", nullable = false, length = 120) private String rulePackageId;
    @Column(name = "rule_package_version", nullable = false, length = 40) private String rulePackageVersion;
    @Column(name = "rule_package_digest", nullable = false, length = 128) private String rulePackageDigest;
    @Column(name = "evaluator_version", nullable = false, length = 40) private String evaluatorVersion;
    @Column(nullable = false, length = 24) private String status = "QUEUED";
    @Column(name = "validation_outcome", nullable = false, length = 24) private String validationOutcome = "NOT_RUN";
    @Column(name = "component_count", nullable = false) private int componentCount;
    @Column(name = "finding_count", nullable = false) private int findingCount;
    @Column(name = "confidence_score", precision = 6, scale = 5) private BigDecimal confidenceScore;
    @Column(name = "completeness_score", precision = 6, scale = 5) private BigDecimal completenessScore;
    @Column(name = "started_at") private Instant startedAt;
    @Column(name = "completed_at") private Instant completedAt;
    @Column(name = "error_code", length = 80) private String errorCode;
    @Column(name = "error_message", columnDefinition = "text") private String errorMessage;
    @Column(name = "created_at", nullable = false) private Instant createdAt = Instant.now();
    @Column(name = "updated_at", nullable = false) private Instant updatedAt = Instant.now();

    public UUID getId(){return id;} public Tenant getTenant(){return tenant;} public void setTenant(Tenant v){tenant=v;}
    public BomIngestionRecord getBom(){return bom;} public void setBom(BomIngestionRecord v){bom=v;}
    public String getArtifactChecksum(){return artifactChecksum;} public void setArtifactChecksum(String v){artifactChecksum=v;}
    public String getRulePackageId(){return rulePackageId;} public void setRulePackageId(String v){rulePackageId=v;}
    public String getRulePackageVersion(){return rulePackageVersion;} public void setRulePackageVersion(String v){rulePackageVersion=v;}
    public String getRulePackageDigest(){return rulePackageDigest;} public void setRulePackageDigest(String v){rulePackageDigest=v;}
    public String getEvaluatorVersion(){return evaluatorVersion;} public void setEvaluatorVersion(String v){evaluatorVersion=v;}
    public String getStatus(){return status;} public void setStatus(String v){status=v; touch();}
    public String getValidationOutcome(){return validationOutcome;} public void setValidationOutcome(String v){validationOutcome=v;}
    public int getComponentCount(){return componentCount;} public void setComponentCount(int v){componentCount=v;}
    public int getFindingCount(){return findingCount;} public void setFindingCount(int v){findingCount=v;}
    public BigDecimal getConfidenceScore(){return confidenceScore;} public void setConfidenceScore(BigDecimal v){confidenceScore=v;}
    public BigDecimal getCompletenessScore(){return completenessScore;} public void setCompletenessScore(BigDecimal v){completenessScore=v;}
    public Instant getStartedAt(){return startedAt;} public void setStartedAt(Instant v){startedAt=v;}
    public Instant getCompletedAt(){return completedAt;} public void setCompletedAt(Instant v){completedAt=v;}
    public String getErrorCode(){return errorCode;} public void setErrorCode(String v){errorCode=v;}
    public String getErrorMessage(){return errorMessage;} public void setErrorMessage(String v){errorMessage=v;}
    public Instant getCreatedAt(){return createdAt;} public Instant getUpdatedAt(){return updatedAt;} public void touch(){updatedAt=Instant.now();}
}
