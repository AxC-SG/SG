package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** One patch tool's view of a PATCH fix: the same KB can be reported by several tools. */
@Entity
@Table(name = "fix_patch_details")
public class FixPatchDetail {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "fix_id", nullable = false)
    private UUID fixId;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, length = 16)
    private PatchProviderType provider;

    @Column(name = "external_id", nullable = false, length = 255)
    private String externalId;

    @Column(name = "kb_article", length = 32)
    private String kbArticle;

    @Column(name = "bulletin_id", length = 64)
    private String bulletinId;

    @Column(name = "vendor", length = 255)
    private String vendor;

    @Column(name = "product", length = 255)
    private String product;

    @Column(name = "classification", length = 128)
    private String classification;

    @Column(name = "vendor_severity", length = 64)
    private String vendorSeverity;

    @Column(name = "release_date")
    private Instant releaseDate;

    @Column(name = "superseded", nullable = false)
    private boolean superseded;

    @Column(name = "info_url", length = 1000)
    private String infoUrl;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt = Instant.now();

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
    public UUID getFixId() { return fixId; }
    public void setFixId(UUID fixId) { this.fixId = fixId; }
    public PatchProviderType getProvider() { return provider; }
    public void setProvider(PatchProviderType provider) { this.provider = provider; }
    public String getExternalId() { return externalId; }
    public void setExternalId(String externalId) { this.externalId = externalId; }
    public String getKbArticle() { return kbArticle; }
    public void setKbArticle(String kbArticle) { this.kbArticle = kbArticle; }
    public String getBulletinId() { return bulletinId; }
    public void setBulletinId(String bulletinId) { this.bulletinId = bulletinId; }
    public String getVendor() { return vendor; }
    public void setVendor(String vendor) { this.vendor = vendor; }
    public String getProduct() { return product; }
    public void setProduct(String product) { this.product = product; }
    public String getClassification() { return classification; }
    public void setClassification(String classification) { this.classification = classification; }
    public String getVendorSeverity() { return vendorSeverity; }
    public void setVendorSeverity(String vendorSeverity) { this.vendorSeverity = vendorSeverity; }
    public Instant getReleaseDate() { return releaseDate; }
    public void setReleaseDate(Instant releaseDate) { this.releaseDate = releaseDate; }
    public boolean isSuperseded() { return superseded; }
    public void setSuperseded(boolean superseded) { this.superseded = superseded; }
    public String getInfoUrl() { return infoUrl; }
    public void setInfoUrl(String infoUrl) { this.infoUrl = infoUrl; }
    public Instant getLastSeenAt() { return lastSeenAt; }
    public void setLastSeenAt(Instant lastSeenAt) { this.lastSeenAt = lastSeenAt; }
}
