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

    @Column(name = "group_email", length = 255)
    private String groupEmail;

    @Column(name = "trigger_summary", length = 255)
    private String triggerSummary;

    @Column(name = "notifications_paused", nullable = false)
    private boolean notificationsPaused;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt = Instant.now();

    // Only CUSTOM recipients exist until the E10 TEAM recipient path; the check constraint keeps TEAM rows linked.
    @Enumerated(EnumType.STRING)
    @Column(name = "recipient_type", nullable = false, length = 16)
    private CampaignRecipientType recipientType = CampaignRecipientType.CUSTOM;

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

    public String getGroupEmail() {
        return groupEmail;
    }

    public void setGroupEmail(String groupEmail) {
        this.groupEmail = groupEmail;
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
}
