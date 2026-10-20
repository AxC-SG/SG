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
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(
        name = "aws_discovery_configs",
        uniqueConstraints = {
                @UniqueConstraint(
                        name = "uk_aws_discovery_configs_tenant_source",
                        columnNames = {"tenant_id", "source_system"}
                )
        },
        indexes = {
                @Index(name = "idx_aws_discovery_configs_enabled", columnList = "enabled,auto_sync_enabled"),
                @Index(name = "idx_aws_discovery_configs_tenant", columnList = "tenant_id")
        }
)
public class AwsDiscoveryConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "source_system", nullable = false, length = 80)
    private String sourceSystem = "aws";

    // ── Authentication ──────────────────────────────────────────────────────────────────────────

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_type", nullable = false, length = 32)
    private AwsAuthType authType = AwsAuthType.INSTANCE_METADATA;

    @Column(name = "access_key_id", length = 255)
    private String accessKeyId;

    /** Secret access key — NEVER logged, NEVER returned in API responses. */
    @Column(name = "credential_secret", length = 4000)
    private String credentialSecret;

    @Column(name = "cross_account_role_arn", length = 2048)
    private String crossAccountRoleArn;

    @Column(name = "external_id", length = 255)
    private String externalId;

    @Column(name = "credential_binding_version", nullable = false)
    private int credentialBindingVersion;

    public int getCredentialBindingVersion() { return credentialBindingVersion; }
    public void setCredentialBindingVersion(int value) { credentialBindingVersion = value; }

    /** AWS account ID resolved via STS GetCallerIdentity; stored after a successful test. */
    @Column(name = "aws_account_id", length = 32)
    private String awsAccountId;

    // ── Scope ───────────────────────────────────────────────────────────────────────────────────

    /** JSON array of region strings, e.g. ["us-east-1","eu-west-1"]. */
    @Column(name = "regions_json", nullable = false)
    private String regionsJson = "[\"us-east-1\"]";

    /** JSON array of resource type strings. AWS discovery is scoped to EC2 compute instances. */
    @Column(name = "resource_types_json", nullable = false)
    private String resourceTypesJson = "[\"EC2\"]";

    // ── Schedule ────────────────────────────────────────────────────────────────────────────────

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "auto_sync_enabled", nullable = false)
    private boolean autoSyncEnabled = false;

    @Column(name = "interval_minutes", nullable = false)
    private Integer intervalMinutes = 1440;

    // ── Test / sync status ──────────────────────────────────────────────────────────────────────

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

    // ── Accessors ───────────────────────────────────────────────────────────────────────────────

    public UUID getId() { return id; }

    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }

    public String getSourceSystem() { return sourceSystem; }
    public void setSourceSystem(String sourceSystem) { this.sourceSystem = sourceSystem; }

    public AwsAuthType getAuthType() { return authType; }
    public void setAuthType(AwsAuthType authType) { this.authType = authType; }

    public String getAccessKeyId() { return accessKeyId; }
    public void setAccessKeyId(String accessKeyId) { this.accessKeyId = accessKeyId; }

    public String getCredentialSecret() { return credentialSecret; }
    public void setCredentialSecret(String credentialSecret) { this.credentialSecret = credentialSecret; }

    public String getCrossAccountRoleArn() { return crossAccountRoleArn; }
    public void setCrossAccountRoleArn(String crossAccountRoleArn) { this.crossAccountRoleArn = crossAccountRoleArn; }

    public String getExternalId() { return externalId; }
    public void setExternalId(String externalId) { this.externalId = externalId; }

    public String getAwsAccountId() { return awsAccountId; }
    public void setAwsAccountId(String awsAccountId) { this.awsAccountId = awsAccountId; }

    public String getRegionsJson() { return regionsJson; }
    public void setRegionsJson(String regionsJson) { this.regionsJson = regionsJson; }

    public String getResourceTypesJson() { return resourceTypesJson; }
    public void setResourceTypesJson(String resourceTypesJson) { this.resourceTypesJson = resourceTypesJson; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public boolean isAutoSyncEnabled() { return autoSyncEnabled; }
    public void setAutoSyncEnabled(boolean autoSyncEnabled) { this.autoSyncEnabled = autoSyncEnabled; }

    public Integer getIntervalMinutes() { return intervalMinutes; }
    public void setIntervalMinutes(Integer intervalMinutes) { this.intervalMinutes = intervalMinutes; }

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
