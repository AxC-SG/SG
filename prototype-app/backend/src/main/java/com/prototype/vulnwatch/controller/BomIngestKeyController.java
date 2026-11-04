package com.prototype.vulnwatch.controller;

import com.prototype.vulnwatch.security.SensitiveTenantAction;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.BomIngestApiKeyService;
import com.prototype.vulnwatch.service.BomIngestApiKeyService.CreatedKey;
import com.prototype.vulnwatch.service.BomIngestApiKeyService.KeyInfo;
import com.prototype.vulnwatch.service.BomIngestException;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import com.prototype.vulnwatch.service.TenantAccessControlService;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Management of the keys a pipeline uses to push BOMs. A key is shown once, at creation; after
 * that only its prefix and state are visible.
 */
@RestController
@RequestMapping("/api/bom/ingest-keys")
public class BomIngestKeyController {

    private static final int MAX_EXPIRY_DAYS = 3650;

    public record CreateKeyRequest(String name, Integer expiresInDays) {
    }

    public record KeyResponse(
            UUID id, String name, String keyPrefix, String state, String createdBy,
            Instant createdAt, Instant expiresAt, Instant lastUsedAt, Instant revokedAt) {
    }

    /** {@code token} is the only time the full key is ever returned. */
    public record CreatedKeyResponse(KeyResponse key, String token) {
    }

    private final BomIngestApiKeyService keys;
    private final RequestActorService requestActorService;
    private final TenantAccessControlService tenantAccessControlService;
    private final AuditEventService auditEventService;

    public BomIngestKeyController(
            BomIngestApiKeyService keys,
            RequestActorService requestActorService,
            TenantAccessControlService tenantAccessControlService,
            AuditEventService auditEventService
    ) {
        this.keys = keys;
        this.requestActorService = requestActorService;
        this.tenantAccessControlService = tenantAccessControlService;
        this.auditEventService = auditEventService;
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('TENANT_ADMIN','INVENTORY_ADMIN')")
    public List<KeyResponse> list() {
        RequestActor actor = authorizedActor();
        Instant now = Instant.now();
        return keys.list(actor.tenantId()).stream().map(key -> toResponse(key, now)).toList();
    }

    @PostMapping
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("bom_ingest_key.created")
    public ResponseEntity<CreatedKeyResponse> create(@RequestBody CreateKeyRequest request) {
        RequestActor actor = authorizedActor();
        Integer days = request == null ? null : request.expiresInDays();
        if (days != null && (days < 1 || days > MAX_EXPIRY_DAYS)) {
            throw new BomIngestException(HttpStatus.BAD_REQUEST, "INVALID_PARAMETER",
                    "expiresInDays must be between 1 and " + MAX_EXPIRY_DAYS + ".");
        }
        Instant expiresAt = days == null ? null : Instant.now().plus(days, ChronoUnit.DAYS);
        CreatedKey created = keys.create(actor.tenantId(), request == null ? null : request.name(),
                actor.userId(), expiresAt);
        auditEventService.record("bom_ingest_key.created", "bom_ingest_key", created.id().toString(),
                "{\"tenantId\":\"" + actor.tenantId() + "\",\"keyPrefix\":\"" + created.keyPrefix() + "\"}");
        KeyResponse key = new KeyResponse(created.id(), created.name(), created.keyPrefix(), "ACTIVE",
                actor.userId(), created.createdAt(), created.expiresAt(), null, null);
        return ResponseEntity.status(HttpStatus.CREATED).body(new CreatedKeyResponse(key, created.token()));
    }

    @DeleteMapping("/{keyId}")
    @PreAuthorize("hasRole('TENANT_ADMIN')")
    @SensitiveTenantAction("bom_ingest_key.revoked")
    public ResponseEntity<Void> revoke(@PathVariable UUID keyId) {
        RequestActor actor = authorizedActor();
        if (!keys.revoke(actor.tenantId(), keyId)) {
            throw new BomIngestException(HttpStatus.NOT_FOUND, "KEY_NOT_FOUND",
                    "No active ingest key with that id.");
        }
        auditEventService.record("bom_ingest_key.revoked", "bom_ingest_key", keyId.toString(),
                "{\"tenantId\":\"" + actor.tenantId() + "\"}");
        return ResponseEntity.noContent().build();
    }

    private RequestActor authorizedActor() {
        RequestActor actor = requestActorService.currentActor();
        tenantAccessControlService.assertTenantAccess(actor, actor.tenantId());
        return actor;
    }

    private static KeyResponse toResponse(KeyInfo key, Instant now) {
        return new KeyResponse(key.id(), key.name(), key.keyPrefix(), key.state(now), key.createdBy(),
                key.createdAt(), key.expiresAt(), key.lastUsedAt(), key.revokedAt());
    }
}
