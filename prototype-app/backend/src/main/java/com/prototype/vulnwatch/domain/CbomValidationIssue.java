package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity @Table(name = "cbom_validation_issues")
public class CbomValidationIssue {
    @Id private UUID id = UUID.randomUUID();
    @ManyToOne(optional=false) @JoinColumn(name="tenant_id") private Tenant tenant;
    @ManyToOne(optional=false) @JoinColumn(name="assessment_run_id") private CbomAssessmentRun assessmentRun;
    @Column(nullable=false,length=100) private String code;
    @Column(nullable=false,length=16) private String severity;
    @Column(name="json_pointer",length=1000) private String jsonPointer;
    @Column(nullable=false,columnDefinition="text") private String message;
    @Column(name="created_at",nullable=false) private Instant createdAt=Instant.now();
    public UUID getId(){return id;} public Tenant getTenant(){return tenant;} public void setTenant(Tenant v){tenant=v;}
    public CbomAssessmentRun getAssessmentRun(){return assessmentRun;} public void setAssessmentRun(CbomAssessmentRun v){assessmentRun=v;}
    public String getCode(){return code;} public void setCode(String v){code=v;} public String getSeverity(){return severity;} public void setSeverity(String v){severity=v;}
    public String getJsonPointer(){return jsonPointer;} public void setJsonPointer(String v){jsonPointer=v;} public String getMessage(){return message;} public void setMessage(String v){message=v;}
    public Instant getCreatedAt(){return createdAt;}
}
