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
        name = "assets",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_assets_tenant_identifier", columnNames = {"tenant_id", "identifier"})
        },
        indexes = {
                @Index(name = "idx_assets_tenant_id", columnList = "tenant_id")
        }
)
public class Asset {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AssetType type;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String identifier;

    @Column(length = 255)
    private String serviceName;

    @Column(length = 64)
    private String environment;

    @Column(length = 255)
    private String ownerTeam;

    @Column(length = 255)
    private String ownerEmail;

    @Column(name = "managed_by", length = 255)
    private String managedBy;

    @Column(length = 255)
    private String department;

    @Column(name = "support_group", length = 255)
    private String supportGroup;

    @Column(name = "assigned_to", length = 255)
    private String assignedTo;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private BusinessCriticality businessCriticality = BusinessCriticality.MEDIUM;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AssetState state = AssetState.ACTIVE;

    /** sha256:... digest of the container image manifest (CONTAINER_IMAGE assets). */
    @Column(length = 255)
    private String imageDigest;

    /** Mutable image tag (e.g. v1.2.3, latest). Optional; digest is the stable identity. */
    @Column(length = 255)
    private String imageTag;

    /** Registry + repository path (e.g. registry.example.com/myorg/myapp). */
    @Column(length = 500)
    private String imageRepository;

    /** Digest of the base image manifest; enables layered-analysis correlation. */
    @Column(length = 255)
    private String baseImageDigest;

    // ── Cloud metadata (populated only for assets originating from cloud discovery) ──────────

    /** Cloud provider identifier, e.g. "aws", "azure", "gcp". */
    @Column(name = "cloud_provider", length = 32)
    private String cloudProvider;

    /** AWS region or equivalent, e.g. "us-east-1". */
    @Column(name = "cloud_region", length = 64)
    private String cloudRegion;

    /** Availability zone within the region, e.g. "us-east-1a". */
    @Column(name = "cloud_availability_zone", length = 64)
    private String cloudAvailabilityZone;

    /** Cloud account/subscription/project ID. */
    @Column(name = "cloud_account_id", length = 64)
    private String cloudAccountId;

    /** Cloud resource type classification, e.g. "EC2". */
    @Column(name = "cloud_resource_type", length = 64)
    private String cloudResourceType;

    /** Instance type, e.g. "t3.medium" (EC2). */
    @Column(name = "cloud_instance_type", length = 64)
    private String cloudInstanceType;

    /** VPC ID the resource belongs to. */
    @Column(name = "cloud_vpc_id", length = 128)
    private String cloudVpcId;

    /** Subnet ID the resource belongs to. */
    @Column(name = "cloud_subnet_id", length = 128)
    private String cloudSubnetId;

    /** Full AWS ARN used as the stable unique identifier for this resource. */
    @Column(name = "cloud_arn", length = 2048)
    private String cloudArn;

    /** JSON object of all raw AWS resource tags, e.g. {"Name":"my-db","Env":"prod"}. */
    @Column(name = "cloud_tags_json", columnDefinition = "text")
    private String cloudTagsJson;

    /** Launch/creation time reported by the cloud provider. */
    @Column(name = "cloud_launch_time")
    private Instant cloudLaunchTime;

    @Column(name = "ssm_managed")
    private Boolean ssmManaged;

    @Column(name = "ssm_ping_status", length = 64)
    private String ssmPingStatus;

    @Column(name = "ssm_last_ping_at")
    private Instant ssmLastPingAt;

    @Column(name = "ssm_inventory_available")
    private Boolean ssmInventoryAvailable;

    @Column(name = "ssm_inventory_last_captured_at")
    private Instant ssmInventoryLastCapturedAt;

    @Column(name = "missing_iam_instance_profile")
    private Boolean missingIamInstanceProfile;

    @Column
    private Instant lastInventoryAt;

    @Column
    private Instant lastCmdbSyncAt;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public AssetType getType() {
        return type;
    }

    public void setType(AssetType type) {
        this.type = type;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    public String getServiceName() {
        return serviceName;
    }

    public void setServiceName(String serviceName) {
        this.serviceName = serviceName;
    }

    public String getEnvironment() {
        return environment;
    }

    public void setEnvironment(String environment) {
        this.environment = environment;
    }

    public String getOwnerTeam() {
        return ownerTeam;
    }

    public void setOwnerTeam(String ownerTeam) {
        this.ownerTeam = ownerTeam;
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

    public String getAssignedTo() {
        return assignedTo;
    }

    public void setAssignedTo(String assignedTo) {
        this.assignedTo = assignedTo;
    }

    public BusinessCriticality getBusinessCriticality() {
        return businessCriticality;
    }

    public void setBusinessCriticality(BusinessCriticality businessCriticality) {
        this.businessCriticality = businessCriticality;
    }

    public AssetState getState() {
        return state;
    }

    public void setState(AssetState state) {
        this.state = state;
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

    public String getImageDigest() {
        return imageDigest;
    }

    public void setImageDigest(String imageDigest) {
        this.imageDigest = imageDigest;
    }

    public String getImageTag() {
        return imageTag;
    }

    public void setImageTag(String imageTag) {
        this.imageTag = imageTag;
    }

    public String getImageRepository() {
        return imageRepository;
    }

    public void setImageRepository(String imageRepository) {
        this.imageRepository = imageRepository;
    }

    public String getBaseImageDigest() {
        return baseImageDigest;
    }

    public void setBaseImageDigest(String baseImageDigest) {
        this.baseImageDigest = baseImageDigest;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public String getCloudProvider() {
        return cloudProvider;
    }

    public void setCloudProvider(String cloudProvider) {
        this.cloudProvider = cloudProvider;
    }

    public String getCloudRegion() {
        return cloudRegion;
    }

    public void setCloudRegion(String cloudRegion) {
        this.cloudRegion = cloudRegion;
    }

    public String getCloudAvailabilityZone() {
        return cloudAvailabilityZone;
    }

    public void setCloudAvailabilityZone(String cloudAvailabilityZone) {
        this.cloudAvailabilityZone = cloudAvailabilityZone;
    }

    public String getCloudAccountId() {
        return cloudAccountId;
    }

    public void setCloudAccountId(String cloudAccountId) {
        this.cloudAccountId = cloudAccountId;
    }

    public String getCloudResourceType() {
        return cloudResourceType;
    }

    public void setCloudResourceType(String cloudResourceType) {
        this.cloudResourceType = cloudResourceType;
    }

    public String getCloudInstanceType() {
        return cloudInstanceType;
    }

    public void setCloudInstanceType(String cloudInstanceType) {
        this.cloudInstanceType = cloudInstanceType;
    }

    public String getCloudVpcId() {
        return cloudVpcId;
    }

    public void setCloudVpcId(String cloudVpcId) {
        this.cloudVpcId = cloudVpcId;
    }

    public String getCloudSubnetId() {
        return cloudSubnetId;
    }

    public void setCloudSubnetId(String cloudSubnetId) {
        this.cloudSubnetId = cloudSubnetId;
    }

    public String getCloudArn() {
        return cloudArn;
    }

    public void setCloudArn(String cloudArn) {
        this.cloudArn = cloudArn;
    }

    public String getCloudTagsJson() {
        return cloudTagsJson;
    }

    public void setCloudTagsJson(String cloudTagsJson) {
        this.cloudTagsJson = cloudTagsJson;
    }

    public Instant getCloudLaunchTime() {
        return cloudLaunchTime;
    }

    public void setCloudLaunchTime(Instant cloudLaunchTime) {
        this.cloudLaunchTime = cloudLaunchTime;
    }

    public Boolean getSsmManaged() {
        return ssmManaged;
    }

    public void setSsmManaged(Boolean ssmManaged) {
        this.ssmManaged = ssmManaged;
    }

    public String getSsmPingStatus() {
        return ssmPingStatus;
    }

    public void setSsmPingStatus(String ssmPingStatus) {
        this.ssmPingStatus = ssmPingStatus;
    }

    public Instant getSsmLastPingAt() {
        return ssmLastPingAt;
    }

    public void setSsmLastPingAt(Instant ssmLastPingAt) {
        this.ssmLastPingAt = ssmLastPingAt;
    }

    public Boolean getSsmInventoryAvailable() {
        return ssmInventoryAvailable;
    }

    public void setSsmInventoryAvailable(Boolean ssmInventoryAvailable) {
        this.ssmInventoryAvailable = ssmInventoryAvailable;
    }

    public Instant getSsmInventoryLastCapturedAt() {
        return ssmInventoryLastCapturedAt;
    }

    public void setSsmInventoryLastCapturedAt(Instant ssmInventoryLastCapturedAt) {
        this.ssmInventoryLastCapturedAt = ssmInventoryLastCapturedAt;
    }

    public Boolean getMissingIamInstanceProfile() {
        return missingIamInstanceProfile;
    }

    public void setMissingIamInstanceProfile(Boolean missingIamInstanceProfile) {
        this.missingIamInstanceProfile = missingIamInstanceProfile;
    }
}
