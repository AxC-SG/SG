package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "aws_discovery_targets",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_aws_discovery_targets_config_account",
                        columnNames = {"config_id", "account_id"}
                )
        },
        indexes = {
                @Index(name = "idx_aws_discovery_targets_config", columnList = "config_id"),
                @Index(name = "idx_aws_discovery_targets_tenant_enabled", columnList = "tenant_id,enabled")
        }
)
public class AwsDiscoveryTarget {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @ManyToOne(optional = false)
    @JoinColumn(name = "config_id")
    private AwsDiscoveryConfig config;

    @Column(name = "account_id", length = 32)
    private String accountId;

    @Column(name = "account_name", length = 255)
    private String accountName;

    @Column(name = "role_arn", length = 2048)
    private String roleArn;

    @Column(name = "external_id", length = 255)
    private String externalId;

    @Column(name = "credential_binding_version", nullable = false)
    private int credentialBindingVersion;

    public int getCredentialBindingVersion() { return credentialBindingVersion; }
    public void setCredentialBindingVersion(int value) { credentialBindingVersion = value; }

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "regions_json", nullable = false)
    private String regionsJson = "[\"us-east-1\"]";

    @Column(name = "resource_types_json", nullable = false)
    private String resourceTypesJson = "[\"EC2\"]";

    @Column(name = "last_test_status", length = 64)
    private String lastTestStatus;

    @Column(name = "last_test_message", length = 2000)
    private String lastTestMessage;

    @Column(name = "last_tested_at")
    private Instant lastTestedAt;

    @Column(name = "last_sync_at")
    private Instant lastSyncAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
    public AwsDiscoveryConfig getConfig() { return config; }
    public void setConfig(AwsDiscoveryConfig config) { this.config = config; }
    public String getAccountId() { return accountId; }
    public void setAccountId(String accountId) { this.accountId = accountId; }
    public String getAccountName() { return accountName; }
    public void setAccountName(String accountName) { this.accountName = accountName; }
    public String getRoleArn() { return roleArn; }
    public void setRoleArn(String roleArn) { this.roleArn = roleArn; }
    public String getExternalId() { return externalId; }
    public void setExternalId(String externalId) { this.externalId = externalId; }
    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }
    public String getRegionsJson() { return regionsJson; }
    public void setRegionsJson(String regionsJson) { this.regionsJson = regionsJson; }
    public String getResourceTypesJson() { return resourceTypesJson; }
    public void setResourceTypesJson(String resourceTypesJson) { this.resourceTypesJson = resourceTypesJson; }
    public String getLastTestStatus() { return lastTestStatus; }
    public void setLastTestStatus(String lastTestStatus) { this.lastTestStatus = lastTestStatus; }
    public String getLastTestMessage() { return lastTestMessage; }
    public void setLastTestMessage(String lastTestMessage) { this.lastTestMessage = lastTestMessage; }
    public Instant getLastTestedAt() { return lastTestedAt; }
    public void setLastTestedAt(Instant lastTestedAt) { this.lastTestedAt = lastTestedAt; }
    public Instant getLastSyncAt() { return lastSyncAt; }
    public void setLastSyncAt(Instant lastSyncAt) { this.lastSyncAt = lastSyncAt; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public void touch() { this.updatedAt = Instant.now(); }
}
