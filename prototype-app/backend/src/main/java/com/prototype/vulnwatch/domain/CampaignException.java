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
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "campaign_exceptions")
public class CampaignException {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "campaign_id")
    private Campaign campaign;

    @Column(name = "finding_display_id", length = 64)
    private String findingDisplayId;

    /** Null only for exceptions written before Phase 0B §4.7; those count in no outcome bucket. */
    @Column(name = "finding_id", updatable = false)
    private UUID findingId;

    @Column(name = "owner_team_id_at_request", updatable = false)
    private UUID ownerTeamIdAtRequest;

    @Column(name = "ownership_assignment_id_at_request", updatable = false)
    private UUID ownershipAssignmentIdAtRequest;

    @Column(name = "asset_name", length = 255)
    private String assetName;

    @Column(name = "package_name", length = 255)
    private String packageName;

    @Column(nullable = false, length = 255)
    private String title;

    @Column(nullable = false, columnDefinition = "text")
    private String reason;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private CampaignExceptionStatus status = CampaignExceptionStatus.PENDING_DECISION;

    @Column(name = "requested_by", nullable = false, length = 255)
    private String requestedBy;

    @Column(name = "requested_at", nullable = false)
    private Instant requestedAt = Instant.now();

    @Column(name = "decision_due_at")
    private Instant decisionDueAt;

    @Column(name = "decisioned_by", length = 255)
    private String decisionedBy;

    @Column(name = "decisioned_at")
    private Instant decisionedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public Campaign getCampaign() {
        return campaign;
    }

    public void setCampaign(Campaign campaign) {
        this.campaign = campaign;
    }

    public String getFindingDisplayId() {
        return findingDisplayId;
    }

    public void setFindingDisplayId(String findingDisplayId) {
        this.findingDisplayId = findingDisplayId;
    }

    public String getAssetName() {
        return assetName;
    }

    public void setAssetName(String assetName) {
        this.assetName = assetName;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public CampaignExceptionStatus getStatus() {
        return status;
    }

    public void setStatus(CampaignExceptionStatus status) {
        this.status = status == null ? CampaignExceptionStatus.PENDING_DECISION : status;
    }

    public String getRequestedBy() {
        return requestedBy;
    }

    public void setRequestedBy(String requestedBy) {
        this.requestedBy = requestedBy;
    }

    public Instant getRequestedAt() {
        return requestedAt;
    }

    public void setRequestedAt(Instant requestedAt) {
        this.requestedAt = requestedAt;
    }

    public Instant getDecisionDueAt() {
        return decisionDueAt;
    }

    public void setDecisionDueAt(Instant decisionDueAt) {
        this.decisionDueAt = decisionDueAt;
    }

    public String getDecisionedBy() {
        return decisionedBy;
    }

    public void setDecisionedBy(String decisionedBy) {
        this.decisionedBy = decisionedBy;
    }

    public Instant getDecisionedAt() {
        return decisionedAt;
    }

    public void setDecisionedAt(Instant decisionedAt) {
        this.decisionedAt = decisionedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    @PrePersist
    void onCreate() {
        if (createdAt == null) createdAt = Instant.now();
        if (updatedAt == null) updatedAt = createdAt;
        if (requestedAt == null) requestedAt = createdAt;
    }

    public void touch() {
        updatedAt = Instant.now();
    }

    public UUID getFindingId() {
        return findingId;
    }

    public void setFindingId(UUID findingId) {
        this.findingId = findingId;
    }

    public UUID getOwnerTeamIdAtRequest() {
        return ownerTeamIdAtRequest;
    }

    public void setOwnerTeamIdAtRequest(UUID ownerTeamIdAtRequest) {
        this.ownerTeamIdAtRequest = ownerTeamIdAtRequest;
    }

    public UUID getOwnershipAssignmentIdAtRequest() {
        return ownershipAssignmentIdAtRequest;
    }

    public void setOwnershipAssignmentIdAtRequest(UUID ownershipAssignmentIdAtRequest) {
        this.ownershipAssignmentIdAtRequest = ownershipAssignmentIdAtRequest;
    }
}
