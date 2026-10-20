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

@Entity
@org.hibernate.annotations.DynamicUpdate
@Table(name = "ingestion_jobs")
public class IngestionJob {

    private UUID claimToken;
    private Instant leaseExpiresAt;
    private Instant heartbeatAt;

    public UUID getClaimToken() { return claimToken; }
    public void setClaimToken(UUID value) { claimToken = value; }
    public Instant getLeaseExpiresAt() { return leaseExpiresAt; }
    public void setLeaseExpiresAt(Instant value) { leaseExpiresAt = value; }
    public Instant getHeartbeatAt() { return heartbeatAt; }
    public void setHeartbeatAt(Instant value) { heartbeatAt = value; }

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(nullable = false, length = 80)
    private String jobType;

    @Column(nullable = false, length = 80)
    private String sourceType;

    @Column(nullable = false, length = 500)
    private String assetIdentifier;

    @Column(nullable = false, length = 32)
    private String status = "QUEUED";

    @Column(length = 255)
    private String requestedBy;

    @Column(nullable = false)
    private Instant requestedAt = Instant.now();

    private Instant startedAt;

    private Instant completedAt;

    @Column(nullable = false)
    private int attemptCount = 0;

    @Column(nullable = false, length = 700)
    private String dedupeKey;

    @Column(columnDefinition = "TEXT")
    private String payloadJson;

    @Column(columnDefinition = "TEXT")
    private String resultJson;

    @Column(length = 120)
    private String failureCode;

    @Column(columnDefinition = "TEXT")
    private String failureMessage;

    @Column(nullable = false)
    private Instant visibleAt = Instant.now();

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne
    @JoinColumn(name = "sbom_upload_id")
    private SbomUpload sbomUpload;

    public UUID getId() {
        return id;
    }

    public String getJobType() {
        return jobType;
    }

    public void setJobType(String jobType) {
        this.jobType = jobType;
    }

    public String getSourceType() {
        return sourceType;
    }

    public void setSourceType(String sourceType) {
        this.sourceType = sourceType;
    }

    public String getAssetIdentifier() {
        return assetIdentifier;
    }

    public void setAssetIdentifier(String assetIdentifier) {
        this.assetIdentifier = assetIdentifier;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
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

    public Instant getStartedAt() {
        return startedAt;
    }

    public void setStartedAt(Instant startedAt) {
        this.startedAt = startedAt;
    }

    public Instant getCompletedAt() {
        return completedAt;
    }

    public void setCompletedAt(Instant completedAt) {
        this.completedAt = completedAt;
    }

    public int getAttemptCount() {
        return attemptCount;
    }

    public void setAttemptCount(int attemptCount) {
        this.attemptCount = attemptCount;
    }

    public String getDedupeKey() {
        return dedupeKey;
    }

    public void setDedupeKey(String dedupeKey) {
        this.dedupeKey = dedupeKey;
    }

    public String getPayloadJson() {
        return payloadJson;
    }

    public void setPayloadJson(String payloadJson) {
        this.payloadJson = payloadJson;
    }

    public String getResultJson() {
        return resultJson;
    }

    public void setResultJson(String resultJson) {
        this.resultJson = resultJson;
    }

    public String getFailureCode() {
        return failureCode;
    }

    public void setFailureCode(String failureCode) {
        this.failureCode = failureCode;
    }

    public String getFailureMessage() {
        return failureMessage;
    }

    public void setFailureMessage(String failureMessage) {
        this.failureMessage = failureMessage;
    }

    public Instant getVisibleAt() {
        return visibleAt;
    }

    public void setVisibleAt(Instant visibleAt) {
        this.visibleAt = visibleAt;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public SbomUpload getSbomUpload() {
        return sbomUpload;
    }

    public void setSbomUpload(SbomUpload sbomUpload) {
        this.sbomUpload = sbomUpload;
    }
}
