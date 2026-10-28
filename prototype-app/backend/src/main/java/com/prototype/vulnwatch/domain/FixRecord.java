package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(
        name = "fix_records",
        indexes = {
                @Index(name = "idx_fix_records_tenant_cve", columnList = "tenant_id,cve_id")
        }
)
public class FixRecord {

    public enum FixType {
        UPGRADE,
        PATCH,
        WORKAROUND,
        CONFIGURATION_CHANGE,
        EOL_MIGRATION,
        COMPENSATING_CONTROL,
        NO_FIX
    }

    public enum RecommendationSource {
        VENDOR_INTELLIGENCE,
        REFERENCE,
        AI,
        ANALYST,
        /** Imported from a patch management tool (SCCM, Intune, BigFix, Tanium). */
        PATCH_TOOL
    }

    /** Fix Intelligence lifecycle. Workbench and patch-tool records are ACTIVE on creation. */
    public enum Status {
        DRAFT,
        PROPOSED,
        APPROVED,
        ACTIVE,
        SUPERSEDED,
        RETIRED
    }

    public enum Ecosystem {
        WINDOWS,
        LINUX,
        MACOS,
        CROSS_PLATFORM
    }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    /** Primary CVE, kept for the CVE Workbench; every CVE link lives in fix_record_cves. */
    @Column(name = "cve_id")
    private String cveId;

    /** JSON array of CVE IDs that share the same fix, e.g. ["CVE-2024-1111","CVE-2024-2222"] */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "related_cve_ids", columnDefinition = "jsonb")
    private String relatedCveIdsJson;

    @Column(nullable = false)
    private String summary;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(name = "fix_type", nullable = false, length = 40)
    private String fixType;

    /** JSON array: [{name, ecosystem, version, assetCount}] */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "software_entities", columnDefinition = "jsonb")
    private String softwareEntitiesJson;

    /** null = all platforms; otherwise "Windows", "Linux", "macOS", etc. */
    @Column(name = "os_hint", length = 60)
    private String osHint;

    @Column(name = "recommendation_source", nullable = false, length = 40)
    private String recommendationSource;

    /** JSON array of URLs used to generate this fix. */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "source_urls", columnDefinition = "jsonb")
    private String sourceUrlsJson;

    @Column(name = "generated_at", nullable = false)
    private Instant generatedAt;

    @Column(length = 500)
    private String title;

    /**
     * Lifecycle-managed by Fix Intelligence (patch tools, analyst workarounds and controls).
     * CVE Workbench regeneration only ever replaces unmanaged records.
     */
    @Column(nullable = false)
    private boolean managed;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private Status status = Status.ACTIVE;

    @Column(length = 16)
    private String severity;

    @Enumerated(EnumType.STRING)
    @Column(length = 32)
    private Ecosystem ecosystem;

    @Column(name = "external_key", length = 200)
    private String externalKey;

    @Column(length = 16)
    private String effort;

    @Column(name = "risk_level", length = 16)
    private String riskLevel;

    @Column(name = "requires_reboot")
    private Boolean requiresReboot;

    @Column(name = "estimated_downtime_minutes")
    private Integer estimatedDowntimeMinutes;

    @Column(name = "installation_instructions", columnDefinition = "TEXT")
    private String installationInstructions;

    @Column(name = "rollback_instructions", columnDefinition = "TEXT")
    private String rollbackInstructions;

    @Column(name = "known_limitations", columnDefinition = "TEXT")
    private String knownLimitations;

    @Column(name = "superseded_by_id")
    private UUID supersededById;

    @Column(length = 255)
    private String owner;

    @Column(name = "proposed_by", length = 255)
    private String proposedBy;

    @Column(name = "approved_by", length = 255)
    private String approvedBy;

    @Column(name = "approved_at")
    private Instant approvedAt;

    @Column(name = "review_due_at")
    private Instant reviewDueAt;

    /** Optimistic lock: concurrent analyst edits and tool syncs never silently overwrite. */
    @Version
    @Column(nullable = false)
    private long version;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @PrePersist
    void onCreate() {
        Instant now = Instant.now();
        createdAt = now;
        updatedAt = now;
        if (generatedAt == null) generatedAt = now;
    }

    @PreUpdate
    void onUpdate() {
        updatedAt = Instant.now();
    }

    public UUID getId() { return id; }

    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }

    public String getCveId() { return cveId; }
    public void setCveId(String cveId) { this.cveId = cveId; }

    public String getRelatedCveIdsJson() { return relatedCveIdsJson; }
    public void setRelatedCveIdsJson(String relatedCveIdsJson) { this.relatedCveIdsJson = relatedCveIdsJson; }

    public String getSummary() { return summary; }
    public void setSummary(String summary) { this.summary = summary; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getFixType() { return fixType; }
    public void setFixType(String fixType) { this.fixType = fixType; }

    public String getSoftwareEntitiesJson() { return softwareEntitiesJson; }
    public void setSoftwareEntitiesJson(String softwareEntitiesJson) { this.softwareEntitiesJson = softwareEntitiesJson; }

    public String getOsHint() { return osHint; }
    public void setOsHint(String osHint) { this.osHint = osHint; }

    public String getRecommendationSource() { return recommendationSource; }
    public void setRecommendationSource(String recommendationSource) { this.recommendationSource = recommendationSource; }

    public String getSourceUrlsJson() { return sourceUrlsJson; }
    public void setSourceUrlsJson(String sourceUrlsJson) { this.sourceUrlsJson = sourceUrlsJson; }

    public Instant getGeneratedAt() { return generatedAt; }
    public void setGeneratedAt(Instant generatedAt) { this.generatedAt = generatedAt; }

    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public boolean isManaged() { return managed; }
    public void setManaged(boolean managed) { this.managed = managed; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    public Ecosystem getEcosystem() { return ecosystem; }
    public void setEcosystem(Ecosystem ecosystem) { this.ecosystem = ecosystem; }
    public String getExternalKey() { return externalKey; }
    public void setExternalKey(String externalKey) { this.externalKey = externalKey; }
    public String getEffort() { return effort; }
    public void setEffort(String effort) { this.effort = effort; }
    public String getRiskLevel() { return riskLevel; }
    public void setRiskLevel(String riskLevel) { this.riskLevel = riskLevel; }
    public Boolean getRequiresReboot() { return requiresReboot; }
    public void setRequiresReboot(Boolean requiresReboot) { this.requiresReboot = requiresReboot; }
    public Integer getEstimatedDowntimeMinutes() { return estimatedDowntimeMinutes; }
    public void setEstimatedDowntimeMinutes(Integer estimatedDowntimeMinutes) { this.estimatedDowntimeMinutes = estimatedDowntimeMinutes; }
    public String getInstallationInstructions() { return installationInstructions; }
    public void setInstallationInstructions(String installationInstructions) { this.installationInstructions = installationInstructions; }
    public String getRollbackInstructions() { return rollbackInstructions; }
    public void setRollbackInstructions(String rollbackInstructions) { this.rollbackInstructions = rollbackInstructions; }
    public String getKnownLimitations() { return knownLimitations; }
    public void setKnownLimitations(String knownLimitations) { this.knownLimitations = knownLimitations; }
    public UUID getSupersededById() { return supersededById; }
    public void setSupersededById(UUID supersededById) { this.supersededById = supersededById; }
    public String getOwner() { return owner; }
    public void setOwner(String owner) { this.owner = owner; }
    public String getProposedBy() { return proposedBy; }
    public void setProposedBy(String proposedBy) { this.proposedBy = proposedBy; }
    public String getApprovedBy() { return approvedBy; }
    public void setApprovedBy(String approvedBy) { this.approvedBy = approvedBy; }
    public Instant getApprovedAt() { return approvedAt; }
    public void setApprovedAt(Instant approvedAt) { this.approvedAt = approvedAt; }
    public Instant getReviewDueAt() { return reviewDueAt; }
    public void setReviewDueAt(Instant reviewDueAt) { this.reviewDueAt = reviewDueAt; }
    public long getVersion() { return version; }
}
