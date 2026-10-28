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

/** Per-tenant Jira connector settings for raising remediation tickets. */
@Entity
@Table(
        name = "jira_ticketing_configs",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_jira_ticketing_configs_tenant", columnNames = {"tenant_id"})
        },
        indexes = {
                @Index(name = "idx_jira_ticketing_configs_enabled", columnList = "enabled")
        }
)
public class JiraTicketingConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "base_url", length = 1000)
    private String baseUrl;

    @Enumerated(EnumType.STRING)
    @Column(name = "auth_type", nullable = false, length = 32)
    private JiraAuthType authType = JiraAuthType.BASIC;

    /** Atlassian account email for BASIC auth; unused for BEARER. */
    @Column(name = "username", length = 255)
    private String username;

    /** Encrypted API token or personal access token. */
    @Column(name = "credential_secret", length = 4000)
    private String credentialSecret;

    @Column(name = "project_key", length = 64)
    private String projectKey;

    @Column(name = "issue_type_id", length = 64)
    private String issueTypeId;

    @Column(name = "issue_type_name", length = 128)
    private String issueTypeName = "Task";

    /** Comma-separated labels applied to every created issue. */
    @Column(name = "default_labels", length = 1000)
    private String defaultLabels;

    /**
     * Whether to send a priority on creation. Jira rejects fields that are absent from the
     * project's create screen, so instances that have removed Priority need this off.
     */
    @Column(name = "include_priority", nullable = false)
    private boolean includePriority = true;

    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;

    @Column(name = "last_test_status", length = 64)
    private String lastTestStatus;

    @Column(name = "last_test_message", length = 2000)
    private String lastTestMessage;

    @Column(name = "last_tested_at")
    private Instant lastTestedAt;

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

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public JiraAuthType getAuthType() {
        return authType;
    }

    public void setAuthType(JiraAuthType authType) {
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

    public String getProjectKey() {
        return projectKey;
    }

    public void setProjectKey(String projectKey) {
        this.projectKey = projectKey;
    }

    public String getIssueTypeId() {
        return issueTypeId;
    }

    public void setIssueTypeId(String issueTypeId) {
        this.issueTypeId = issueTypeId;
    }

    public String getIssueTypeName() {
        return issueTypeName;
    }

    public void setIssueTypeName(String issueTypeName) {
        this.issueTypeName = issueTypeName;
    }

    public String getDefaultLabels() {
        return defaultLabels;
    }

    public void setDefaultLabels(String defaultLabels) {
        this.defaultLabels = defaultLabels;
    }

    public boolean isIncludePriority() {
        return includePriority;
    }

    public void setIncludePriority(boolean includePriority) {
        this.includePriority = includePriority;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
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
