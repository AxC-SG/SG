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
import jakarta.persistence.OneToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "cis",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_cis_tenant_sys_id", columnNames = {"tenant_id", "sys_id"}),
                @UniqueConstraint(name = "uk_cis_asset_id", columnNames = {"asset_id"})
        },
        indexes = {
                @Index(name = "idx_cis_tenant_display", columnList = "tenant_id,display_name"),
                @Index(name = "idx_cis_tenant_env", columnList = "tenant_id,environment")
        }
)
public class Ci {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @OneToOne(optional = false)
    @JoinColumn(name = "asset_id")
    private Asset asset;

    @Column(name = "sys_id", nullable = false, length = 255)
    private String sysId;

    @Column(name = "display_name", nullable = false, length = 255)
    private String displayName;

    @Enumerated(EnumType.STRING)
    @Column(name = "business_criticality", nullable = false, length = 32)
    private BusinessCriticality businessCriticality = BusinessCriticality.MEDIUM;

    @Column(length = 64)
    private String environment;

    @Column(name = "owner_email", length = 255)
    private String ownerEmail;

    @Column(name = "managed_by", length = 255)
    private String managedBy;

    @Column(length = 255)
    private String department;

    @Column(name = "support_group", length = 255)
    private String supportGroup;

    /** The referenced sys_user_group sys_id (lower case), kept beside the display name (Phase 0B §1.8, tenant V24). */
    @Column(name = "support_group_sys_id", length = 32)
    private String supportGroupSysId;

    @Column(name = "assigned_to", length = 255)
    private String assignedTo;

    @Column(name = "last_inventory_at")
    private Instant lastInventoryAt;

    @Column(name = "last_cmdb_sync_at")
    private Instant lastCmdbSyncAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
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

    public String getSysId() {
        return sysId;
    }

    public void setSysId(String sysId) {
        this.sysId = sysId;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public BusinessCriticality getBusinessCriticality() {
        return businessCriticality;
    }

    public void setBusinessCriticality(BusinessCriticality businessCriticality) {
        this.businessCriticality = businessCriticality;
    }

    public String getEnvironment() {
        return environment;
    }

    public void setEnvironment(String environment) {
        this.environment = environment;
    }

    public String getOwnerEmail() {
        return ownerEmail;
    }

    public void setOwnerEmail(String ownerEmail) {
        this.ownerEmail = ownerEmail;
    }

    public String getManagedBy() {
        return managedBy;
    }

    public void setManagedBy(String managedBy) {
        this.managedBy = managedBy;
    }

    public String getDepartment() {
        return department;
    }

    public void setDepartment(String department) {
        this.department = department;
    }

    public String getSupportGroup() {
        return supportGroup;
    }

    public void setSupportGroup(String supportGroup) {
        this.supportGroup = supportGroup;
    }

    public String getSupportGroupSysId() {
        return supportGroupSysId;
    }

    public void setSupportGroupSysId(String supportGroupSysId) {
        this.supportGroupSysId = supportGroupSysId;
    }

    public String getAssignedTo() {
        return assignedTo;
    }

    public void setAssignedTo(String assignedTo) {
        this.assignedTo = assignedTo;
    }

    public Instant getLastInventoryAt() {
        return lastInventoryAt;
    }

    public void setLastInventoryAt(Instant lastInventoryAt) {
        this.lastInventoryAt = lastInventoryAt;
    }

    public Instant getLastCmdbSyncAt() {
        return lastCmdbSyncAt;
    }

    public void setLastCmdbSyncAt(Instant lastCmdbSyncAt) {
        this.lastCmdbSyncAt = lastCmdbSyncAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void touch() {
        this.updatedAt = Instant.now();
    }
}
