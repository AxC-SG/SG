package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "cbom_relationships")
public class CbomRelationship {
    @Id private UUID id = UUID.randomUUID();
    @ManyToOne(optional = false) @JoinColumn(name = "tenant_id") private Tenant tenant;
    @ManyToOne(optional = false) @JoinColumn(name = "source_bom_id") private BomIngestionRecord sourceBom;
    @Column(name = "source_type", nullable = false, length = 40) private String sourceType;
    @Column(name = "source_id", nullable = false) private UUID sourceId;
    @Column(name = "target_type", nullable = false, length = 40) private String targetType;
    @Column(name = "target_id", nullable = false) private UUID targetId;
    @Column(name = "relationship_type", nullable = false, length = 60) private String relationshipType;
    @Column(name = "evidence_kind", nullable = false, length = 20) private String evidenceKind;
    @Column(precision = 6, scale = 5) private BigDecimal confidence;
    @Column(name = "evidence_summary", columnDefinition = "text") private String evidenceSummary;
    @Column(name = "valid_until") private Instant validUntil;
    @Column(name = "created_at", nullable = false) private Instant createdAt = Instant.now();
    @Column(name = "updated_at", nullable = false) private Instant updatedAt = Instant.now();

    public UUID getId(){return id;} public Tenant getTenant(){return tenant;} public void setTenant(Tenant v){tenant=v;}
    public BomIngestionRecord getSourceBom(){return sourceBom;} public void setSourceBom(BomIngestionRecord v){sourceBom=v;}
    public String getSourceType(){return sourceType;} public void setSourceType(String v){sourceType=v;}
    public UUID getSourceId(){return sourceId;} public void setSourceId(UUID v){sourceId=v;}
    public String getTargetType(){return targetType;} public void setTargetType(String v){targetType=v;}
    public UUID getTargetId(){return targetId;} public void setTargetId(UUID v){targetId=v;}
    public String getRelationshipType(){return relationshipType;} public void setRelationshipType(String v){relationshipType=v;}
    public String getEvidenceKind(){return evidenceKind;} public void setEvidenceKind(String v){evidenceKind=v;}
    public BigDecimal getConfidence(){return confidence;} public void setConfidence(BigDecimal v){confidence=v;}
    public String getEvidenceSummary(){return evidenceSummary;} public void setEvidenceSummary(String v){evidenceSummary=v;}
    public Instant getValidUntil(){return validUntil;} public void setValidUntil(Instant v){validUntil=v;}
    public Instant getCreatedAt(){return createdAt;} public Instant getUpdatedAt(){return updatedAt;}
}
