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

@Entity
@Table(name = "campaign_notify_groups")
public class CampaignNotifyGroup {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "campaign_id")
    private Campaign campaign;

    @Column(name = "group_name", nullable = false, length = 255)
    private String groupName;

    @Column(name = "role_label", length = 128)
    private String roleLabel;

    @Column(name = "trigger_summary", length = 255)
    private String triggerSummary;

    @Column(name = "notifications_paused", nullable = false)
    private boolean notificationsPaused;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    // Phase 0B §4.6: TEAM rows name a team and use its channel; CUSTOM rows keep a label and an encrypted address.
    @Enumerated(EnumType.STRING)
    @Column(name = "recipient_type", nullable = false, length = 16)
    private CampaignRecipientType recipientType = CampaignRecipientType.CUSTOM;

    @Column(name = "team_id")
    private UUID teamId;

    /** Tenant ciphertext ({@code TenantDataCipher}); never plaintext. */
    @Column(name = "group_email_enc", columnDefinition = "text")
    private String groupEmailEnc;

    public UUID getId() {
        return id;
    }

    public Campaign getCampaign() {
        return campaign;
    }

    public void setCampaign(Campaign campaign) {
        this.campaign = campaign;
    }

    public String getGroupName() {
        return groupName;
    }

    public void setGroupName(String groupName) {
        this.groupName = groupName;
    }

    public String getRoleLabel() {
        return roleLabel;
    }

    public void setRoleLabel(String roleLabel) {
        this.roleLabel = roleLabel;
    }

    public String getTriggerSummary() {
        return triggerSummary;
    }

    public void setTriggerSummary(String triggerSummary) {
        this.triggerSummary = triggerSummary;
    }

    public boolean isNotificationsPaused() {
        return notificationsPaused;
    }

    public void setNotificationsPaused(boolean notificationsPaused) {
        this.notificationsPaused = notificationsPaused;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public CampaignRecipientType getRecipientType() {
        return recipientType;
    }

    public void setRecipientType(CampaignRecipientType recipientType) {
        this.recipientType = recipientType;
    }

    public UUID getTeamId() {
        return teamId;
    }

    public void setTeamId(UUID teamId) {
        this.teamId = teamId;
    }

    public String getGroupEmailEnc() {
        return groupEmailEnc;
    }

    public void setGroupEmailEnc(String groupEmailEnc) {
        this.groupEmailEnc = groupEmailEnc;
    }
}
