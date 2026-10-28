package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** A CVE a fix remediates, with where that link came from (vendor, KB mapping, analyst). */
@Entity
@Table(name = "fix_record_cves")
public class FixRecordCve {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "fix_id", nullable = false)
    private UUID fixId;

    @Column(name = "cve_id", nullable = false, length = 50)
    private String cveId;

    @Column(name = "source", nullable = false, length = 32)
    private String source;

    @Column(name = "confidence", nullable = false, length = 16)
    private String confidence;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
    public UUID getFixId() { return fixId; }
    public void setFixId(UUID fixId) { this.fixId = fixId; }
    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }
    public String getSource() { return source; }
    public void setSource(String source) { this.source = source; }
    public String getConfidence() { return confidence; }
    public void setConfidence(String confidence) { this.confidence = confidence; }
    public Instant getCreatedAt() { return createdAt; }
    public void setCreatedAt(Instant createdAt) { this.createdAt = createdAt; }
}
