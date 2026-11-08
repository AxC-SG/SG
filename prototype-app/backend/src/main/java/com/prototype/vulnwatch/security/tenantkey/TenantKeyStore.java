package com.prototype.vulnwatch.security.tenantkey;

import java.util.Optional;
import java.util.UUID;

/** Persistence of wrapped tenant keys ({@code platform.tenant_data_keys}). */
public interface TenantKeyStore {

    enum State { ACTIVE, DECRYPT_ONLY, DESTROYED }

    record StoredKey(UUID tenantId, int version, String wrapperKind, String keyRef, byte[] wrappedKey, State state) { }

    Optional<StoredKey> active(UUID tenantId);

    Optional<StoredKey> find(UUID tenantId, int version);

    /** Inserts the first ACTIVE key; returns false when another writer already provisioned one. */
    boolean insertInitial(StoredKey key);

    /**
     * Atomically demotes {@code expectedActiveVersion} to DECRYPT_ONLY and inserts {@code next} as
     * ACTIVE. Returns false when the active version changed concurrently.
     */
    boolean rotate(UUID tenantId, int expectedActiveVersion, StoredKey next);
}
