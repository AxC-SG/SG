package com.prototype.vulnwatch.domain;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;

@Entity @Table(name="cbom_rule_configurations")
public class CbomRuleConfiguration {
    @Id @Column(name="tenant_id") private UUID tenantId;
    @Column(name="package_id",nullable=false,length=120) private String packageId="scoutgrid-baseline";
    @Column(name="version_policy",nullable=false,length=24) private String versionPolicy="FOLLOW_LATEST";
    @Column(name="pinned_version",length=40) private String pinnedVersion;
    @org.hibernate.annotations.JdbcTypeCode(org.hibernate.type.SqlTypes.JSON)
    @Column(name="parameters_json",nullable=false,columnDefinition="jsonb") private String parametersJson="{}";
    @Column(name="updated_by",nullable=false,length=255) private String updatedBy="system";
    @Column(name="updated_at",nullable=false) private Instant updatedAt=Instant.now();
    @Column(name="effective_version",length=40) private String effectiveVersion;
    @Column(name="pin_state",nullable=false,length=24) private String pinState="CURRENT";
    @Column(name="deprecation_notice_at") private Instant deprecationNoticeAt;
    @Column(name="upgrade_required_at") private Instant upgradeRequiredAt;
    @Version private long version;
    public UUID getTenantId(){return tenantId;} public void setTenantId(UUID v){tenantId=v;} public String getPackageId(){return packageId;} public void setPackageId(String v){packageId=v;}
    public String getVersionPolicy(){return versionPolicy;} public void setVersionPolicy(String v){versionPolicy=v;} public String getPinnedVersion(){return pinnedVersion;} public void setPinnedVersion(String v){pinnedVersion=v;}
    public String getParametersJson(){return parametersJson;} public void setParametersJson(String v){parametersJson=v;} public String getUpdatedBy(){return updatedBy;} public void setUpdatedBy(String v){updatedBy=v;}
    public String getEffectiveVersion(){return effectiveVersion;} public void setEffectiveVersion(String v){effectiveVersion=v;}
    public String getPinState(){return pinState;} public void setPinState(String v){pinState=v;}
    public Instant getDeprecationNoticeAt(){return deprecationNoticeAt;} public void setDeprecationNoticeAt(Instant v){deprecationNoticeAt=v;}
    public Instant getUpgradeRequiredAt(){return upgradeRequiredAt;} public void setUpgradeRequiredAt(Instant v){upgradeRequiredAt=v;}
    public Instant getUpdatedAt(){return updatedAt;} public void touch(){updatedAt=Instant.now();} public long getVersion(){return version;}
}
