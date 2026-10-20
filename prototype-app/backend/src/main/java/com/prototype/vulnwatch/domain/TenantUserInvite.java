package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import jakarta.persistence.Transient;
import com.prototype.vulnwatch.service.InvitationTokens;
import java.time.Instant;
import java.util.UUID;

@Entity
@Table(schema = "platform", name = "tenant_user_invites")
public class TenantUserInvite {

    @Id
    private UUID id = UUID.randomUUID();

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id", nullable = false)
    private Tenant tenant;

    @ManyToOne
    @JoinColumn(name = "invited_by")
    private AppUser invitedBy;

    @Column(nullable = false, length = 320)
    private String email;

    @Column(name = "display_name", length = 255)
    private String displayName;

    @Column(name = "external_subject", nullable = false, length = 320)
    private String externalSubject;

    @Column(nullable = false, length = 64)
    private String role;

    @Column(nullable = false, length = 32)
    private String status = "READY";

    @Transient
    private String token;

    @Column(name = "token_hash", nullable = false, length = 64, unique = true)
    private String tokenHash;

    @Column(name = "provider_message_id", length = 255)
    private String providerMessageId;

    @Column(name = "delivery_detail", length = 500)
    private String deliveryDetail;

    @Column(nullable = false)
    private Instant expiresAt;

    private Instant acceptedAt;

    private Instant lastSentAt;

    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    @Column(nullable = false)
    private Instant updatedAt = Instant.now();

    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public Tenant getTenant() {
        return tenant;
    }

    public void setTenant(Tenant tenant) {
        this.tenant = tenant;
    }

    public AppUser getInvitedBy() {
        return invitedBy;
    }

    public void setInvitedBy(AppUser invitedBy) {
        this.invitedBy = invitedBy;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getDisplayName() {
        return displayName;
    }

    public void setDisplayName(String displayName) {
        this.displayName = displayName;
    }

    public String getExternalSubject() {
        return externalSubject;
    }

    public void setExternalSubject(String externalSubject) {
        this.externalSubject = externalSubject;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getTokenHash() { return tokenHash; }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
        this.tokenHash = InvitationTokens.hash(token);
    }

    public String getProviderMessageId() {
        return providerMessageId;
    }

    public void setProviderMessageId(String providerMessageId) {
        this.providerMessageId = providerMessageId;
    }

    public String getDeliveryDetail() {
        return deliveryDetail;
    }

    public void setDeliveryDetail(String deliveryDetail) {
        this.deliveryDetail = deliveryDetail;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getAcceptedAt() {
        return acceptedAt;
    }

    public void setAcceptedAt(Instant acceptedAt) {
        this.acceptedAt = acceptedAt;
    }

    public Instant getLastSentAt() {
        return lastSentAt;
    }

    public void setLastSentAt(Instant lastSentAt) {
        this.lastSentAt = lastSentAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public Instant getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
}
