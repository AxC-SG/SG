package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "finding_suppression_requests")
public class FindingSuppressionRequest {

    @Id
    private UUID id = UUID.randomUUID();

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @ManyToOne(optional = false, fetch = FetchType.LAZY)
    @JoinColumn(name = "finding_id", nullable = false)
    private Finding finding;

    @Column(name = "finding_kind", nullable = false, length = 32)
    private String findingKind;

    @Column(name = "severity_at_request", length = 32)
    private String severityAtRequest;

    @Column(name = "requested_by", nullable = false, length = 255)
    private String requestedBy;

    @Column(name = "requested_at", nullable = false)
    private Instant requestedAt = Instant.now();

    @Column(name = "decision_due_at", nullable = false)
    private Instant decisionDueAt;

    @Column(nullable = false, columnDefinition = "text")
    private String reason;

    @Column(name = "compensating_control", nullable = false, columnDefinition = "text")
    private String compensatingControl;

    @Column(name = "proposed_suppressed_until", nullable = false)
    private Instant proposedSuppressedUntil;

    @Column(nullable = false, length = 32)
    private String status = "REQUESTED";

    @Column(name = "decided_by", length = 255)
    private String decidedBy;

    @Column(name = "decided_at")
    private Instant decidedAt;

    @Column(name = "decision_reason", columnDefinition = "text")
    private String decisionReason;

    @Column(name = "applied_event_id")
    private UUID appliedEventId;

    @Version
    @Column(nullable = false)
    private long version;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
    public Finding getFinding() { return finding; }
    public void setFinding(Finding finding) { this.finding = finding; }
    public String getFindingKind() { return findingKind; }
    public void setFindingKind(String findingKind) { this.findingKind = findingKind; }
    public String getSeverityAtRequest() { return severityAtRequest; }
    public void setSeverityAtRequest(String severityAtRequest) { this.severityAtRequest = severityAtRequest; }
    public String getRequestedBy() { return requestedBy; }
    public void setRequestedBy(String requestedBy) { this.requestedBy = requestedBy; }
    public Instant getRequestedAt() { return requestedAt; }
    public void setRequestedAt(Instant requestedAt) { this.requestedAt = requestedAt; }
    public Instant getDecisionDueAt() { return decisionDueAt; }
    public void setDecisionDueAt(Instant decisionDueAt) { this.decisionDueAt = decisionDueAt; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public String getCompensatingControl() { return compensatingControl; }
    public void setCompensatingControl(String compensatingControl) { this.compensatingControl = compensatingControl; }
    public Instant getProposedSuppressedUntil() { return proposedSuppressedUntil; }
    public void setProposedSuppressedUntil(Instant proposedSuppressedUntil) { this.proposedSuppressedUntil = proposedSuppressedUntil; }
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    public String getDecidedBy() { return decidedBy; }
    public void setDecidedBy(String decidedBy) { this.decidedBy = decidedBy; }
    public Instant getDecidedAt() { return decidedAt; }
    public void setDecidedAt(Instant decidedAt) { this.decidedAt = decidedAt; }
    public String getDecisionReason() { return decisionReason; }
    public void setDecisionReason(String decisionReason) { this.decisionReason = decisionReason; }
    public UUID getAppliedEventId() { return appliedEventId; }
    public void setAppliedEventId(UUID appliedEventId) { this.appliedEventId = appliedEventId; }
    public long getVersion() { return version; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void touch() { this.updatedAt = Instant.now(); }
}
