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

@org.hibernate.annotations.DynamicUpdate
@Entity
@Table(schema = "platform", name = "sync_runs")
public class SyncRun {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = true)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(nullable = false)
    private String syncType;

    @Column(nullable = false, length = 64)
    private String runScope = "PLATFORM_VULNERABILITY";

    @Column(nullable = false)
    private String status = "running";

    @Column(nullable = false)
    private int recordsFetched = 0;

    @Column(nullable = false)
    private int recordsInserted = 0;

    @Column(nullable = false)
    private int recordsUpdated = 0;

    @Column(nullable = false)
    private int recordsFailed = 0;

    @Column(nullable = false)
    private Instant startedAt = Instant.now();

    private Instant completedAt;

    @Column(length = 2000)
    private String errorMessage;

    @Column(columnDefinition = "TEXT")
    private String metadataJson;

    @Column(insertable=false,updatable=false)
    private UUID claimToken;
    @Column(insertable=false,updatable=false)
    private Instant leaseExpiresAt;
    @Column(insertable=false,updatable=false)
    private Instant heartbeatAt;
    @Column(insertable=false,updatable=false)
    private int attemptCount;

    public UUID getClaimToken() { return claimToken; }
    public void setClaimToken(UUID value) { claimToken=value; }
    public Instant getLeaseExpiresAt() { return leaseExpiresAt; }
    public void setLeaseExpiresAt(Instant value) { leaseExpiresAt=value; }
    public Instant getHeartbeatAt() { return heartbeatAt; }
    public void setHeartbeatAt(Instant value) { heartbeatAt=value; }
    public int getAttemptCount() { return attemptCount; }
    public void setAttemptCount(int value) { attemptCount=value; }

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public String getSyncType() {
        return syncType;
    }

    public void setSyncType(String syncType) {
        this.syncType = syncType;
    }

    public String getRunScope() {
        return runScope;
    }

    public void setRunScope(String runScope) {
        this.runScope = runScope;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public int getRecordsFetched() {
        return recordsFetched;
    }

    public void setRecordsFetched(int recordsFetched) {
        this.recordsFetched = recordsFetched;
    }

    public int getRecordsInserted() {
        return recordsInserted;
    }

    public void setRecordsInserted(int recordsInserted) {
        this.recordsInserted = recordsInserted;
    }

    public int getRecordsUpdated() {
        return recordsUpdated;
    }

    public void setRecordsUpdated(int recordsUpdated) {
        this.recordsUpdated = recordsUpdated;
    }

    public int getRecordsFailed() {
        return recordsFailed;
    }

    public void setRecordsFailed(int recordsFailed) {
        this.recordsFailed = recordsFailed;
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

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getMetadataJson() {
        return metadataJson;
    }

    public void setMetadataJson(String metadataJson) {
        this.metadataJson = metadataJson;
    }
}
