package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import org.hibernate.annotations.DynamicUpdate;

@Entity
@DynamicUpdate
@Table(schema = "platform", name = "app_users")
public class AppUser {

    @Id
    private UUID id = UUID.randomUUID();

    @Column(nullable = false, unique = true)
    private String externalSubject;

    @Column(length = 320)
    private String email;

    private String displayName;

    @Column(nullable = false, length = 32)
    private String status = "ACTIVE";

    @Column(name = "password_hash", length = 255)
    private String passwordHash;

    @Column(name = "password_set_at")
    private Instant passwordSetAt;

    @Column(name = "platform_owner", nullable = false)
    private boolean platformOwner;

    @Column(name = "password_setup_token_hash", length = 64)
    private String passwordSetupTokenHash;

    @Column(name = "password_setup_token_expires_at")
    private Instant passwordSetupTokenExpiresAt;

    private Instant lastSeenAt;

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

    public String getExternalSubject() {
        return externalSubject;
    }

    public void setExternalSubject(String externalSubject) {
        this.externalSubject = externalSubject;
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

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public Instant getLastSeenAt() {
        return lastSeenAt;
    }

    public void setLastSeenAt(Instant lastSeenAt) {
        this.lastSeenAt = lastSeenAt;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public void setPasswordHash(String passwordHash) {
        this.passwordHash = passwordHash;
    }

    public Instant getPasswordSetAt() {
        return passwordSetAt;
    }

    public void setPasswordSetAt(Instant passwordSetAt) {
        this.passwordSetAt = passwordSetAt;
    }

    public boolean isPlatformOwner() {
        return platformOwner;
    }

    public void setPlatformOwner(boolean platformOwner) {
        this.platformOwner = platformOwner;
    }

    public String getPasswordSetupTokenHash() {
        return passwordSetupTokenHash;
    }

    public void setPasswordSetupTokenHash(String passwordSetupTokenHash) {
        this.passwordSetupTokenHash = passwordSetupTokenHash;
    }

    public Instant getPasswordSetupTokenExpiresAt() {
        return passwordSetupTokenExpiresAt;
    }

    public void setPasswordSetupTokenExpiresAt(Instant passwordSetupTokenExpiresAt) {
        this.passwordSetupTokenExpiresAt = passwordSetupTokenExpiresAt;
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
