package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "cbom_tenant_settings")
public class CbomTenantSettings {

    @Id
    @Column(name = "tenant_id")
    private UUID tenantId;

    @Column(name = "require_distinct_suppression_approver", nullable = false)
    private boolean requireDistinctSuppressionApprover;

    @Column(name = "suppression_request_deadline_days", nullable = false)
    private int suppressionRequestDeadlineDays = 14;

    @Column(name = "low_suppression_max_days", nullable = false)
    private int lowSuppressionMaxDays = 365;

    @Column(name = "medium_suppression_max_days", nullable = false)
    private int mediumSuppressionMaxDays = 180;

    @Column(name = "high_suppression_max_days", nullable = false)
    private int highSuppressionMaxDays = 90;

    @Column(name = "critical_suppression_max_days", nullable = false)
    private int criticalSuppressionMaxDays = 30;

    @Column(name = "updated_by", nullable = false, length = 255)
    private String updatedBy = "system";

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    @Version
    @Column(nullable = false)
    private long version;

    public UUID getTenantId() { return tenantId; }
    public void setTenantId(UUID tenantId) { this.tenantId = tenantId; }
    public boolean isRequireDistinctSuppressionApprover() { return requireDistinctSuppressionApprover; }
    public void setRequireDistinctSuppressionApprover(boolean value) { this.requireDistinctSuppressionApprover = value; }
    public int getSuppressionRequestDeadlineDays() { return suppressionRequestDeadlineDays; }
    public void setSuppressionRequestDeadlineDays(int value) { this.suppressionRequestDeadlineDays = value; }
    public int getLowSuppressionMaxDays() { return lowSuppressionMaxDays; }
    public void setLowSuppressionMaxDays(int value) { this.lowSuppressionMaxDays = value; }
    public int getMediumSuppressionMaxDays() { return mediumSuppressionMaxDays; }
    public void setMediumSuppressionMaxDays(int value) { this.mediumSuppressionMaxDays = value; }
    public int getHighSuppressionMaxDays() { return highSuppressionMaxDays; }
    public void setHighSuppressionMaxDays(int value) { this.highSuppressionMaxDays = value; }
    public int getCriticalSuppressionMaxDays() { return criticalSuppressionMaxDays; }
    public void setCriticalSuppressionMaxDays(int value) { this.criticalSuppressionMaxDays = value; }
    public String getUpdatedBy() { return updatedBy; }
    public void setUpdatedBy(String value) { this.updatedBy = value; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void touch() { this.updatedAt = Instant.now(); }
    public long getVersion() { return version; }
}
