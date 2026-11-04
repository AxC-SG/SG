package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity @Table(name="cbom_claim_assurances")
public class CbomClaimAssurance {
    @Id private UUID id=UUID.randomUUID();
    @ManyToOne(optional=false) @JoinColumn(name="tenant_id") private Tenant tenant;
    @ManyToOne(optional=false) @JoinColumn(name="assessment_run_id") private CbomAssessmentRun assessmentRun;
    @ManyToOne @JoinColumn(name="cbom_component_id") private CbomComponent component;
    @Column(name="claim_path",nullable=false,length=1000) private String claimPath;
    @Column(name="assurance_level",nullable=false,length=24) private String assuranceLevel;
    @Column(name="evidence_state",nullable=false,length=32) private String evidenceState;
    @Column(nullable=false,columnDefinition="text") private String explanation;
    @Column(name="created_at",nullable=false) private Instant createdAt=Instant.now();
    public UUID getId(){return id;} public Tenant getTenant(){return tenant;} public void setTenant(Tenant v){tenant=v;}
    public CbomAssessmentRun getAssessmentRun(){return assessmentRun;} public void setAssessmentRun(CbomAssessmentRun v){assessmentRun=v;}
    public CbomComponent getComponent(){return component;} public void setComponent(CbomComponent v){component=v;}
    public String getClaimPath(){return claimPath;} public void setClaimPath(String v){claimPath=v;} public String getAssuranceLevel(){return assuranceLevel;} public void setAssuranceLevel(String v){assuranceLevel=v;}
    public String getEvidenceState(){return evidenceState;} public void setEvidenceState(String v){evidenceState=v;} public String getExplanation(){return explanation;} public void setExplanation(String v){explanation=v;}
    public Instant getCreatedAt(){return createdAt;}
}
