package com.prototype.vulnwatch.domain;

import jakarta.persistence.Basic;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

@Entity
@Table(
        name = "findings",
        indexes = {
                @Index(name = "idx_findings_tenant_status_updated", columnList = "tenant_id,status,updated_at"),
                @Index(name = "idx_findings_tenant_component_vuln", columnList = "tenant_id,component_id,vulnerability_id"),
                @Index(name = "idx_findings_asset_id", columnList = "asset_id"),
                @Index(name = "idx_findings_vulnerability_id", columnList = "vulnerability_id"),
                @Index(name = "idx_findings_vulnerability_status", columnList = "vulnerability_id,status"),
                @Index(name = "idx_findings_vex_status", columnList = "vex_status"),
                @Index(name = "idx_findings_vex_freshness", columnList = "vex_freshness"),
                @Index(name = "idx_findings_vex_provider", columnList = "vex_provider"),
                @Index(name = "idx_findings_auto_close_eligible", columnList = "tenant_id,status,auto_close_eligible_at")
        }
)
public class Finding {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "display_id", nullable = false, updatable = false, length = 16)
    private String displayId;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne
    @JoinColumn(name = "asset_id")
    private Asset asset;

    @ManyToOne
    @JoinColumn(name = "component_id")
    private InventoryComponent component;

    @ManyToOne
    @JoinColumn(name = "vulnerability_id")
    private Vulnerability vulnerability;

    @Column(name = "finding_kind", nullable = false, length = 32)
    private String findingKind = "VULNERABILITY";

    @Column(name = "fingerprint", length = 64)
    private String fingerprint;

    @Column(name = "workflow_class", length = 32)
    private String workflowClass;

    @Column(name = "workflow_substate", length = 40)
    private String workflowSubstate;

    @Column(name = "target_state", length = 80)
    private String targetState;

    @Column(name = "verification_required", nullable = false)
    private boolean verificationRequired;

    @Column(name = "verification_status", nullable = false, length = 24)
    private String verificationStatus = "NOT_REQUIRED";

    @Column(name = "verification_evidence", columnDefinition = "text")
    private String verificationEvidence;

    @Column(name = "verification_requested_at")
    private Instant verificationRequestedAt;

    @Column(name = "verification_completed_at")
    private Instant verificationCompletedAt;

    @Column(name = "verification_actor", length = 255)
    private String verificationActor;

    @Column(name = "title", length = 512)
    private String title;

    @Column(name = "policy_id", length = 128)
    private String policyId;

    @Column(name = "policy_version", length = 32)
    private String policyVersion;

    @Column(name = "reason_code", length = 128)
    private String reasonCode;

    @Column(name = "assessment_id")
    private UUID assessmentId;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private FindingStatus status = FindingStatus.OPEN;

    @Enumerated(EnumType.STRING)
    @Column(name = "decision_state", length = 40)
    private FindingDecisionState decisionState = FindingDecisionState.NEEDS_REVIEW;

    @Enumerated(EnumType.STRING)
    @Column(name = "creation_source", nullable = false, length = 32)
    private FindingCreationSource creationSource = FindingCreationSource.AUTOMATIC;

    @Column(nullable = false)
    private double riskScore;

    @Column
    private double confidenceScore;

    @Column(nullable = false)
    private String matchedBy;

    @Column(length = 255)
    private String assignedTo;

    @Column(length = 255)
    private String assignedBy;

    @Column
    private Instant assignedAt;

    @Column
    private Instant dueAt;

    @Column(name = "severity_override", length = 16)
    private String severityOverride;

    @Column(length = 2000)
    private String suppressionReason;

    @Column
    private Instant suppressedUntil;

    @Basic(fetch = FetchType.LAZY)
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(columnDefinition = "jsonb")
    private String evidence;

    @Column(name = "vex_status", length = 64)
    private String vexStatus;

    @Column(name = "vex_freshness", length = 64)
    private String vexFreshness;

    @Column(name = "vex_provider", length = 128)
    private String vexProvider;

    @Column(name = "matched_vex_assertion_id")
    private UUID matchedVexAssertionId;

    @Basic(fetch = FetchType.LAZY)
    @Column(name = "precedence_trace", columnDefinition = "TEXT")
    private String precedenceTrace;

    @Column(name = "suppressed_by_rule_id")
    private UUID suppressedByRuleId;

    @Column(name = "suppressed_by_rule_name")
    private String suppressedByRuleName;

    @Column(name = "owner_group", length = 255)
    private String ownerGroup;

    /** Ticket identifier in the originating system (e.g. INC0010005, or a Jira key like SEC-42) */
    @Column(name = "incident_id", length = 64)
    private String incidentId;

    /** Last known status of the linked ticket, in the originating system's own vocabulary */
    @Column(name = "incident_status", length = 64)
    private String incidentStatus;

    /**
     * Which ticketing system raised {@link #incidentId}, as
     * {@link com.prototype.vulnwatch.ticketing.TicketingSystem#key()}.
     *
     * <p>Recorded per finding rather than inferred from the tenant's current connector: after a
     * tenant switches from ServiceNow to Jira, historical findings still hold ServiceNow
     * incident numbers, and status sync has to keep polling ServiceNow for those. Null means
     * the ticket predates provider tracking and is treated as ServiceNow.
     */
    @Column(name = "incident_provider", length = 32)
    private String incidentProvider;

    /**
     * The finding status already reflected on the ticket.
     *
     * <p>This is the loop breaker for bidirectional sync. The push side only acts when
     * {@link #status} differs from this value, and both directions write it: when a resolved
     * ticket closes the finding, the pull side records the status here in the same
     * transaction, so the push side does not immediately echo that same change back to the
     * ticket that caused it.
     */
    @Column(name = "incident_pushed_status", length = 32)
    private String incidentPushedStatus;

    @Column(name = "incident_pushed_at")
    private Instant incidentPushedAt;

    @Column
    private Instant firstObservedAt = Instant.now();

    @Column
    private Instant lastObservedAt = Instant.now();

    @Column(name = "last_observed_run_id")
    private UUID lastObservedRunId;

    @Column(name = "consecutive_misses", nullable = false)
    private int consecutiveMisses = 0;

    @Column(name = "auto_close_eligible_at")
    private Instant autoCloseEligibleAt;

    @Column(name = "closed_at")
    private Instant closedAt;

    @Column(name = "closed_by", length = 255)
    private String closedBy;

    @Enumerated(EnumType.STRING)
    @Column(name = "closed_reason", length = 80)
    private FindingCloseReason closedReason;

    @Column(name = "closed_rule_id")
    private UUID closedRuleId;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    @Column(name="intelligence_merged_into_id")
    private UUID intelligenceMergedIntoId;
    public UUID getIntelligenceMergedIntoId() { return intelligenceMergedIntoId; }
    public void setIntelligenceMergedIntoId(UUID value) { intelligenceMergedIntoId=value; }

    @Column(name="intelligence_eligibility",nullable=false)
    private String intelligenceEligibility="ELIGIBLE";
    @Column(name="intelligence_release_id")
    private UUID intelligenceReleaseId;
    @Column(name="intelligence_revision",nullable=false)
    private long intelligenceRevision;
    @Column(name="intelligence_severity")
    private String intelligenceSeverity;
    @Column(name="intelligence_epss")
    private Double intelligenceEpss;
    @Column(name="intelligence_in_kev")
    private Boolean intelligenceInKev;

    public String getIntelligenceEligibility() { return intelligenceEligibility; }
    public void setIntelligenceEligibility(String value) { intelligenceEligibility=value; }
    public UUID getIntelligenceReleaseId() { return intelligenceReleaseId; }
    public void setIntelligenceReleaseId(UUID value) { intelligenceReleaseId=value; }
    public long getIntelligenceRevision() { return intelligenceRevision; }
    public void setIntelligenceRevision(long value) { intelligenceRevision=value; }
    public String getIntelligenceSeverity() { return intelligenceSeverity; }
    public void setIntelligenceSeverity(String value) { intelligenceSeverity=value; }
    public Double getIntelligenceEpss() { return intelligenceEpss; }
    public void setIntelligenceEpss(Double value) { intelligenceEpss=value; }
    public Boolean getIntelligenceInKev() { return intelligenceInKev; }
    public void setIntelligenceInKev(Boolean value) { intelligenceInKev=value; }

    public UUID getId() {
        return id;
    }

    public String getDisplayId() {
        return displayId;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public Asset getAsset() {
        return asset;
    }

    public void setAsset(Asset asset) {
        this.asset = asset;
    }

    public InventoryComponent getComponent() {
        return component;
    }

    public void setComponent(InventoryComponent component) {
        this.component = component;
    }

    public Vulnerability getVulnerability() {
        return vulnerability;
    }

    public void setVulnerability(Vulnerability vulnerability) {
        this.vulnerability = vulnerability;
    }

    public String getFindingKind() { return findingKind; }
    public void setFindingKind(String findingKind) { this.findingKind = findingKind; }
    public String getFingerprint() { return fingerprint; }
    public void setFingerprint(String fingerprint) { this.fingerprint = fingerprint; }
    public String getWorkflowClass() { return workflowClass; }
    public void setWorkflowClass(String workflowClass) { this.workflowClass = workflowClass; }
    public String getWorkflowSubstate() { return workflowSubstate; }
    public void setWorkflowSubstate(String value) { workflowSubstate = value; }
    public String getTargetState() { return targetState; }
    public void setTargetState(String value) { targetState = value; }
    public boolean isVerificationRequired() { return verificationRequired; }
    public void setVerificationRequired(boolean value) { verificationRequired = value; }
    public String getVerificationStatus() { return verificationStatus; }
    public void setVerificationStatus(String value) { verificationStatus = value; }
    public String getVerificationEvidence() { return verificationEvidence; }
    public void setVerificationEvidence(String value) { verificationEvidence = value; }
    public Instant getVerificationRequestedAt() { return verificationRequestedAt; }
    public void setVerificationRequestedAt(Instant value) { verificationRequestedAt = value; }
    public Instant getVerificationCompletedAt() { return verificationCompletedAt; }
    public void setVerificationCompletedAt(Instant value) { verificationCompletedAt = value; }
    public String getVerificationActor() { return verificationActor; }
    public void setVerificationActor(String value) { verificationActor = value; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getPolicyId() { return policyId; }
    public void setPolicyId(String policyId) { this.policyId = policyId; }
    public String getPolicyVersion() { return policyVersion; }
    public void setPolicyVersion(String policyVersion) { this.policyVersion = policyVersion; }
    public String getReasonCode() { return reasonCode; }
    public void setReasonCode(String reasonCode) { this.reasonCode = reasonCode; }
    public UUID getAssessmentId() { return assessmentId; }
    public void setAssessmentId(UUID assessmentId) { this.assessmentId = assessmentId; }

    public FindingStatus getStatus() {
        return status;
    }

    public void setStatus(FindingStatus status) {
        this.status = status;
    }

    public FindingDecisionState getDecisionState() {
        return decisionState;
    }

    public void setDecisionState(FindingDecisionState decisionState) {
        this.decisionState = decisionState;
    }

    public FindingCreationSource getCreationSource() {
        return creationSource;
    }

    public void setCreationSource(FindingCreationSource creationSource) {
        this.creationSource = creationSource == null ? FindingCreationSource.AUTOMATIC : creationSource;
    }

    public double getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(double riskScore) {
        this.riskScore = riskScore;
    }

    public double getConfidenceScore() {
        return confidenceScore;
    }

    public void setConfidenceScore(double confidenceScore) {
        this.confidenceScore = confidenceScore;
    }

    public String getMatchedBy() {
        return matchedBy;
    }

    public void setMatchedBy(String matchedBy) {
        this.matchedBy = matchedBy;
    }

    public String getAssignedTo() {
        return assignedTo;
    }

    public void setAssignedTo(String assignedTo) {
        this.assignedTo = assignedTo;
    }

    public String getAssignedBy() {
        return assignedBy;
    }

    public void setAssignedBy(String assignedBy) {
        this.assignedBy = assignedBy;
    }

    public Instant getAssignedAt() {
        return assignedAt;
    }

    public void setAssignedAt(Instant assignedAt) {
        this.assignedAt = assignedAt;
    }

    public Instant getDueAt() {
        return dueAt;
    }

    public void setDueAt(Instant dueAt) {
        this.dueAt = dueAt;
    }

    public String getSuppressionReason() {
        return suppressionReason;
    }

    public void setSuppressionReason(String suppressionReason) {
        this.suppressionReason = suppressionReason;
    }

    public Instant getSuppressedUntil() {
        return suppressedUntil;
    }

    public void setSuppressedUntil(Instant suppressedUntil) {
        this.suppressedUntil = suppressedUntil;
    }

    public String getEvidence() {
        return evidence;
    }

    public void setEvidence(String evidence) {
        this.evidence = evidence;
    }

    public String getVexStatus() {
        return vexStatus;
    }

    public void setVexStatus(String vexStatus) {
        this.vexStatus = vexStatus;
    }

    public String getVexFreshness() {
        return vexFreshness;
    }

    public void setVexFreshness(String vexFreshness) {
        this.vexFreshness = vexFreshness;
    }

    public String getVexProvider() {
        return vexProvider;
    }

    public void setVexProvider(String vexProvider) {
        this.vexProvider = vexProvider;
    }

    public UUID getMatchedVexAssertionId() {
        return matchedVexAssertionId;
    }

    public void setMatchedVexAssertionId(UUID matchedVexAssertionId) {
        this.matchedVexAssertionId = matchedVexAssertionId;
    }

    public String getPrecedenceTrace() {
        return precedenceTrace;
    }

    public void setPrecedenceTrace(String precedenceTrace) {
        this.precedenceTrace = precedenceTrace;
    }

    public Instant getFirstObservedAt() {
        return firstObservedAt;
    }

    public void setFirstObservedAt(Instant firstObservedAt) {
        this.firstObservedAt = firstObservedAt;
    }

    public Instant getLastObservedAt() {
        return lastObservedAt;
    }

    public void setLastObservedAt(Instant lastObservedAt) {
        this.lastObservedAt = lastObservedAt;
    }

    public UUID getLastObservedRunId() {
        return lastObservedRunId;
    }

    public void setLastObservedRunId(UUID lastObservedRunId) {
        this.lastObservedRunId = lastObservedRunId;
    }

    public int getConsecutiveMisses() {
        return consecutiveMisses;
    }

    public void setConsecutiveMisses(int consecutiveMisses) {
        this.consecutiveMisses = Math.max(0, consecutiveMisses);
    }

    public Instant getAutoCloseEligibleAt() {
        return autoCloseEligibleAt;
    }

    public void setAutoCloseEligibleAt(Instant autoCloseEligibleAt) {
        this.autoCloseEligibleAt = autoCloseEligibleAt;
    }

    public Instant getClosedAt() {
        return closedAt;
    }

    public void setClosedAt(Instant closedAt) {
        this.closedAt = closedAt;
    }

    public String getClosedBy() {
        return closedBy;
    }

    public void setClosedBy(String closedBy) {
        this.closedBy = closedBy;
    }

    public FindingCloseReason getClosedReason() {
        return closedReason;
    }

    public void setClosedReason(FindingCloseReason closedReason) {
        this.closedReason = closedReason;
    }

    public UUID getClosedRuleId() {
        return closedRuleId;
    }

    public void setClosedRuleId(UUID closedRuleId) {
        this.closedRuleId = closedRuleId;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public UUID getSuppressedByRuleId() { return suppressedByRuleId; }
    public void setSuppressedByRuleId(UUID suppressedByRuleId) { this.suppressedByRuleId = suppressedByRuleId; }

    public String getSuppressedByRuleName() { return suppressedByRuleName; }
    public void setSuppressedByRuleName(String suppressedByRuleName) { this.suppressedByRuleName = suppressedByRuleName; }

    public String getOwnerGroup() { return ownerGroup; }
    public void setOwnerGroup(String ownerGroup) { this.ownerGroup = ownerGroup; }

    public String getIncidentId() {
        return incidentId;
    }

    public void setIncidentId(String incidentId) {
        this.incidentId = incidentId;
    }

    public String getIncidentStatus() {
        return incidentStatus;
    }

    public void setIncidentStatus(String incidentStatus) {
        this.incidentStatus = incidentStatus;
    }

    public String getIncidentProvider() {
        return incidentProvider;
    }

    public void setIncidentProvider(String incidentProvider) {
        this.incidentProvider = incidentProvider;
    }

    public String getIncidentPushedStatus() {
        return incidentPushedStatus;
    }

    public void setIncidentPushedStatus(String incidentPushedStatus) {
        this.incidentPushedStatus = incidentPushedStatus;
    }

    public Instant getIncidentPushedAt() {
        return incidentPushedAt;
    }

    public void setIncidentPushedAt(Instant incidentPushedAt) {
        this.incidentPushedAt = incidentPushedAt;
    }

    public String getSeverityOverride() {
        return severityOverride;
    }

    public void setSeverityOverride(String severityOverride) {
        this.severityOverride = severityOverride;
    }

    @PrePersist
    void ensureIdentifiers() {
        if (id == null) {
            id = UUID.randomUUID();
        }
        if (displayId == null || displayId.isBlank()) {
            String compactId = id.toString().replace("-", "").toUpperCase();
            displayId = "F-" + compactId.substring(0, 12);
        }
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
