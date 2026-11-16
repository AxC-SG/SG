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
import jakarta.persistence.Table;
import org.hibernate.annotations.DynamicUpdate;
import java.time.Instant;
import java.util.UUID;

/**
 * Membership state and the reconciler columns are written by {@code CampaignLedger} and
 * {@code CampaignMembershipReconciler} through JDBC; {@link DynamicUpdate} and {@code updatable = false} keep a
 * stale entity save from overwriting them (Phase 0B §4.2, §4.3).
 */
@Entity
@DynamicUpdate
@Table(
        name = "campaigns",
        indexes = {
                @Index(name = "idx_campaigns_tenant_status_updated", columnList = "tenant_id,status,updated_at")
        }
)
public class Campaign {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(nullable = false, length = 255)
    private String name;

    @Column(columnDefinition = "text")
    private String summary;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 32)
    private CampaignStatus status = CampaignStatus.DRAFT;

    @Column(name = "created_by", nullable = false, length = 255)
    private String createdBy;

    @Column(name = "due_at")
    private Instant dueAt;

    @Column(name = "started_at")
    private Instant startedAt;

    @Column(name = "paused_at")
    private Instant pausedAt;

    @Column(name = "closed_at")
    private Instant closedAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @Enumerated(EnumType.STRING)
    @Column(name = "scope_kind", nullable = false, length = 16, updatable = false)
    private CampaignScopeKind scopeKind;

    @Enumerated(EnumType.STRING)
    @Column(name = "membership_state", nullable = false, length = 16, updatable = false)
    private CampaignMembershipState membershipState = CampaignMembershipState.COMPLETE;

    @Column(name = "assignee_principal_id", updatable = false)
    private UUID assigneePrincipalId;

    @Column(name = "coordinating_team_id", updatable = false)
    private UUID coordinatingTeamId;

    @Column(name = "include_excepted", nullable = false, updatable = false)
    private boolean includeExcepted;

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public CampaignStatus getStatus() {
        return status;
    }

    public void setStatus(CampaignStatus status) {
        this.status = status == null ? CampaignStatus.DRAFT : status;
    }

    public String getCreatedBy() {
        return createdBy;
    }

    public void setCreatedBy(String createdBy) {
        this.createdBy = createdBy;
    }

    public Instant getDueAt() {
        return dueAt;
    }

    public void setDueAt(Instant dueAt) {
        this.dueAt = dueAt;
    }

    public Instant getStartedAt() {
        return startedAt;
    }

    public void setStartedAt(Instant startedAt) {
        this.startedAt = startedAt;
    }

    public Instant getPausedAt() {
        return pausedAt;
    }

    public void setPausedAt(Instant pausedAt) {
        this.pausedAt = pausedAt;
    }

    public Instant getClosedAt() {
        return closedAt;
    }

    public void setClosedAt(Instant closedAt) {
        this.closedAt = closedAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    @PrePersist
    void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
        if (updatedAt == null) {
            updatedAt = createdAt;
        }
    }

    public void touch() {
        updatedAt = Instant.now();
    }

    public CampaignScopeKind getScopeKind() {
        return scopeKind;
    }

    public void setScopeKind(CampaignScopeKind scopeKind) {
        this.scopeKind = scopeKind;
    }

    public CampaignMembershipState getMembershipState() {
        return membershipState;
    }

    public void setMembershipState(CampaignMembershipState membershipState) {
        this.membershipState = membershipState;
    }

    public UUID getAssigneePrincipalId() {
        return assigneePrincipalId;
    }

    public void setAssigneePrincipalId(UUID assigneePrincipalId) {
        this.assigneePrincipalId = assigneePrincipalId;
    }

    public UUID getCoordinatingTeamId() {
        return coordinatingTeamId;
    }

    public void setCoordinatingTeamId(UUID coordinatingTeamId) {
        this.coordinatingTeamId = coordinatingTeamId;
    }

    public boolean isIncludeExcepted() {
        return includeExcepted;
    }

    public void setIncludeExcepted(boolean includeExcepted) {
        this.includeExcepted = includeExcepted;
    }
}
