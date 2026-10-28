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

/** One fix on one asset as one source reports it: applicability, deployment and schedule. */
@Entity
@Table(name = "fix_assets")
public class FixAsset {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "fix_id", nullable = false)
    private UUID fixId;

    @Column(name = "asset_id", nullable = false)
    private UUID assetId;

    @Column(name = "provider", nullable = false, length = 16)
    private String provider;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 32)
    private FixAssetStatus status;

    @Column(name = "deployment_id")
    private UUID deploymentId;

    @Column(name = "scheduled_at")
    private Instant scheduledAt;

    @Column(name = "deadline_at")
    private Instant deadlineAt;

    @Column(name = "installed_at")
    private Instant installedAt;

    @Column(name = "error_code", length = 128)
    private String errorCode;

    @Column(name = "first_detected_at", nullable = false)
    private Instant firstDetectedAt = Instant.now();

    @Column(name = "last_reported_at", nullable = false)
    private Instant lastReportedAt = Instant.now();

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
    public UUID getFixId() { return fixId; }
    public void setFixId(UUID fixId) { this.fixId = fixId; }
    public UUID getAssetId() { return assetId; }
    public void setAssetId(UUID assetId) { this.assetId = assetId; }
    public String getProvider() { return provider; }
    public void setProvider(String provider) { this.provider = provider; }
    public FixAssetStatus getStatus() { return status; }
    public void setStatus(FixAssetStatus status) { this.status = status; }
    public UUID getDeploymentId() { return deploymentId; }
    public void setDeploymentId(UUID deploymentId) { this.deploymentId = deploymentId; }
    public Instant getScheduledAt() { return scheduledAt; }
    public void setScheduledAt(Instant scheduledAt) { this.scheduledAt = scheduledAt; }
    public Instant getDeadlineAt() { return deadlineAt; }
    public void setDeadlineAt(Instant deadlineAt) { this.deadlineAt = deadlineAt; }
    public Instant getInstalledAt() { return installedAt; }
    public void setInstalledAt(Instant installedAt) { this.installedAt = installedAt; }
    public String getErrorCode() { return errorCode; }
    public void setErrorCode(String errorCode) { this.errorCode = errorCode; }
    public Instant getFirstDetectedAt() { return firstDetectedAt; }
    public void setFirstDetectedAt(Instant firstDetectedAt) { this.firstDetectedAt = firstDetectedAt; }
    public Instant getLastReportedAt() { return lastReportedAt; }
    public void setLastReportedAt(Instant lastReportedAt) { this.lastReportedAt = lastReportedAt; }
}
