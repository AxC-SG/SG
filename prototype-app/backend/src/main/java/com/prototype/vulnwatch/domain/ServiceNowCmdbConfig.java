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
        name = "servicenow_cmdb_configs",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_servicenow_cmdb_configs_tenant_source", columnNames = {"tenant_id", "source_system"})
        },
        indexes = {
                @Index(name = "idx_servicenow_cmdb_configs_enabled", columnList = "enabled,auto_sync_enabled"),
                @Index(name = "idx_servicenow_cmdb_configs_tenant", columnList = "tenant_id")
        }
)
public class ServiceNowCmdbConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "source_system", nullable = false, length = 80)
    private String sourceSystem = "servicenow";

    @Column(name = "base_url", length = 1000)
    private String baseUrl;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_type", nullable = false, length = 32)
    private ServiceNowAuthType authType = ServiceNowAuthType.BASIC;

    @Column(length = 255)
    private String username;

    @Column(name = "credential_secret", length = 4000)
    private String credentialSecret;

    @Column(name = "install_table", nullable = false, length = 255)
    private String installTable = "cmdb_sam_sw_install";

    @Column(name = "discovery_model_table", nullable = false, length = 255)
    private String discoveryModelTable = "cmdb_sam_sw_discovery_model";

    @Column(name = "ci_table", nullable = false, length = 255)
    private String ciTable = "cmdb_ci";

    @Column(name = "install_query", length = 4000)
    private String installQuery;

    @Column(name = "discovery_query", length = 4000)
    private String discoveryQuery;

    @Column(name = "install_fields", length = 4000)
    private String installFields;

    @Column(name = "discovery_fields", length = 4000)
    private String discoveryFields;

    @Column(name = "page_size", nullable = false)
    private Integer pageSize = 1000;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "auto_sync_enabled", nullable = false)
    private boolean autoSyncEnabled = false;

    @Column(name = "interval_minutes", nullable = false)
    private Integer intervalMinutes = 1440;

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

    public UUID getId() {
        return id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public String getSourceSystem() {
        return sourceSystem;
    }

    public void setSourceSystem(String sourceSystem) {
        this.sourceSystem = sourceSystem;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public ServiceNowAuthType getAuthType() {
        return authType;
    }

    public void setAuthType(ServiceNowAuthType authType) {
        this.authType = authType;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getCredentialSecret() {
        return credentialSecret;
    }

    public void setCredentialSecret(String credentialSecret) {
        this.credentialSecret = credentialSecret;
    }

    public String getInstallTable() {
        return installTable;
    }

    public void setInstallTable(String installTable) {
        this.installTable = installTable;
    }

    public String getDiscoveryModelTable() {
        return discoveryModelTable;
    }

    public void setDiscoveryModelTable(String discoveryModelTable) {
        this.discoveryModelTable = discoveryModelTable;
    }

    public String getCiTable() {
        return ciTable;
    }

    public void setCiTable(String ciTable) {
        this.ciTable = ciTable;
    }

    public String getInstallQuery() {
        return installQuery;
    }

    public void setInstallQuery(String installQuery) {
        this.installQuery = installQuery;
    }

    public String getDiscoveryQuery() {
        return discoveryQuery;
    }

    public void setDiscoveryQuery(String discoveryQuery) {
        this.discoveryQuery = discoveryQuery;
    }

    public String getInstallFields() {
        return installFields;
    }

    public void setInstallFields(String installFields) {
        this.installFields = installFields;
    }

    public String getDiscoveryFields() {
        return discoveryFields;
    }

    public void setDiscoveryFields(String discoveryFields) {
        this.discoveryFields = discoveryFields;
    }

    public Integer getPageSize() {
        return pageSize;
    }

    public void setPageSize(Integer pageSize) {
        this.pageSize = pageSize;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isAutoSyncEnabled() {
        return autoSyncEnabled;
    }

    public void setAutoSyncEnabled(boolean autoSyncEnabled) {
        this.autoSyncEnabled = autoSyncEnabled;
    }

    public Integer getIntervalMinutes() {
        return intervalMinutes;
    }

    public void setIntervalMinutes(Integer intervalMinutes) {
        this.intervalMinutes = intervalMinutes;
    }

    public String getLastTestStatus() {
        return lastTestStatus;
    }

    public void setLastTestStatus(String lastTestStatus) {
        this.lastTestStatus = lastTestStatus;
    }

    public String getLastTestMessage() {
        return lastTestMessage;
    }

    public void setLastTestMessage(String lastTestMessage) {
        this.lastTestMessage = lastTestMessage;
    }

    public Instant getLastTestedAt() {
        return lastTestedAt;
    }

    public void setLastTestedAt(Instant lastTestedAt) {
        this.lastTestedAt = lastTestedAt;
    }

    public Instant getLastSyncAt() {
        return lastSyncAt;
    }

    public void setLastSyncAt(Instant lastSyncAt) {
        this.lastSyncAt = lastSyncAt;
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

    /**
     * Explicit tenant default assignment group for canonical ticket routing (Phase 0B §4.9, §4.11); null means the
     * user must select one. Never an implicit fallback.
     */
    @jakarta.persistence.Column(name = "default_assignment_group", length = 255)
    private String defaultAssignmentGroup;

    public String getDefaultAssignmentGroup() {
        return defaultAssignmentGroup;
    }

    public void setDefaultAssignmentGroup(String defaultAssignmentGroup) {
        this.defaultAssignmentGroup = defaultAssignmentGroup;
    }
}
