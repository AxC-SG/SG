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

/** A patch tool's device mapped to a tenant asset, so every tool's reports land on one host. */
@Entity
@Table(name = "device_identities")
public class DeviceIdentity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "asset_id", nullable = false)
    private UUID assetId;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false, length = 16)
    private PatchProviderType provider;

    @Column(name = "external_id", nullable = false, length = 255)
    private String externalId;

    @Column(name = "hostname", length = 255)
    private String hostname;

    @Column(name = "normalized_hostname", length = 255)
    private String normalizedHostname;

    @Column(name = "serial_number", length = 255)
    private String serialNumber;

    @Column(name = "os_name", length = 255)
    private String osName;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt = Instant.now();

    public UUID getId() { return id; }
    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
    public UUID getAssetId() { return assetId; }
    public void setAssetId(UUID assetId) { this.assetId = assetId; }
    public PatchProviderType getProvider() { return provider; }
    public void setProvider(PatchProviderType provider) { this.provider = provider; }
    public String getExternalId() { return externalId; }
    public void setExternalId(String externalId) { this.externalId = externalId; }
    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    public String getNormalizedHostname() { return normalizedHostname; }
    public void setNormalizedHostname(String normalizedHostname) { this.normalizedHostname = normalizedHostname; }
    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }
    public String getOsName() { return osName; }
    public void setOsName(String osName) { this.osName = osName; }
    public Instant getLastSeenAt() { return lastSeenAt; }
    public void setLastSeenAt(Instant lastSeenAt) { this.lastSeenAt = lastSeenAt; }
}
