package com.prototype.vulnwatch.security.tenantkey;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.prototype.vulnwatch.security.tenantkey.TenantKeyUnavailableException.Reason;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Arrays;
import java.util.Optional;
import java.util.UUID;

/**
 * Resolves per-tenant data keys. Wrapped keys live in {@link TenantKeyStore}; unwrapped keys are
 * held only in a bounded in-memory cache with a TTL. When the wrapper is
 * unavailable, keys already cached keep working until their TTL expires; {@link #readiness(UUID)}
 * always performs a live unwrap so PII-writing workflows fail closed during an outage.
 */
public class TenantKeyRegistry {

    public record ActiveKey(int version, byte[] key) { }

    public record Readiness(boolean ready, Reason reason) {
        static final Readiness READY = new Readiness(true, null);
    }

    private record CacheKey(UUID tenantId, int version) { }

    private static final int KEY_BYTES = 32;

    private final TenantKeyStore store;
    private final KeyWrapper wrapper;
    private final Cache<CacheKey, byte[]> keys;
    private final SecureRandom random = new SecureRandom();

    /** @param wrapper the configured key wrapper, or {@code null} when tenant encryption is disabled */
    public TenantKeyRegistry(TenantKeyStore store, KeyWrapper wrapper, Duration cacheTtl, long maxCachedKeys) {
        this.store = store;
        this.wrapper = wrapper;
        this.keys = Caffeine.newBuilder()
                .expireAfterWrite(cacheTtl)
                .maximumSize(maxCachedKeys)
                .build();
        // Cached arrays are never handed out (callers get copies) and are not zeroed on eviction:
        // zeroing could race a concurrent copy and silently encrypt under an all-zero key.
    }

    public boolean configured() {
        return wrapper != null;
    }

    /** Creates version 1 for the tenant if no active key exists. Idempotent under concurrency. */
    public int provision(UUID tenantId) {
        KeyWrapper w = requireWrapper();
        Optional<TenantKeyStore.StoredKey> existing = store.active(tenantId);
        if (existing.isPresent()) return existing.get().version();
        byte[] dek = newKey();
        try {
            TenantKeyStore.StoredKey row = new TenantKeyStore.StoredKey(tenantId, 1, w.kind(), w.activeKeyRef(),
                    w.wrap(dek, new KeyContext(tenantId, 1)), TenantKeyStore.State.ACTIVE);
            if (store.insertInitial(row)) return 1;
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
        return store.active(tenantId).map(TenantKeyStore.StoredKey::version)
                .orElseThrow(() -> new TenantKeyUnavailableException(Reason.NOT_PROVISIONED, "Tenant key provisioning conflict"));
    }

    /** Creates a new ACTIVE version; the previous version stays decryptable. Returns the new version. */
    public int rotate(UUID tenantId) {
        KeyWrapper w = requireWrapper();
        TenantKeyStore.StoredKey current = store.active(tenantId)
                .orElseThrow(() -> new TenantKeyUnavailableException(Reason.NOT_PROVISIONED, "Tenant key is not provisioned"));
        int next = current.version() + 1;
        byte[] dek = newKey();
        try {
            TenantKeyStore.StoredKey row = new TenantKeyStore.StoredKey(tenantId, next, w.kind(), w.activeKeyRef(),
                    w.wrap(dek, new KeyContext(tenantId, next)), TenantKeyStore.State.ACTIVE);
            if (!store.rotate(tenantId, current.version(), row)) {
                throw new TenantKeyUnavailableException(Reason.NOT_PROVISIONED, "Tenant key rotation raced with another rotation");
            }
            return next;
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    /** Key for new encryption. The returned array is a copy the caller may zero. */
    public ActiveKey activeKey(UUID tenantId) {
        requireWrapper();
        TenantKeyStore.StoredKey row = store.active(tenantId)
                .orElseThrow(() -> new TenantKeyUnavailableException(Reason.NOT_PROVISIONED, "Tenant key is not provisioned"));
        return new ActiveKey(row.version(), cached(row).clone());
    }

    /** Key for decrypting values written under {@code version}. The returned array is a copy. */
    public byte[] key(UUID tenantId, int version) {
        byte[] hit = keys.getIfPresent(new CacheKey(tenantId, version));
        if (hit != null) return hit.clone();
        requireWrapper();
        TenantKeyStore.StoredKey row = store.find(tenantId, version)
                .orElseThrow(() -> new TenantKeyUnavailableException(Reason.UNKNOWN_KEY_VERSION, "Unknown tenant key version"));
        return cached(row).clone();
    }

    /** Live check used before enabling identity sources or writing PII. Never served from cache. */
    public Readiness readiness(UUID tenantId) {
        if (wrapper == null) return new Readiness(false, Reason.NOT_CONFIGURED);
        try {
            Optional<TenantKeyStore.StoredKey> row = store.active(tenantId);
            if (row.isEmpty()) return new Readiness(false, Reason.NOT_PROVISIONED);
            byte[] dek = unwrap(row.get());
            Arrays.fill(dek, (byte) 0);
            return Readiness.READY;
        } catch (TenantKeyUnavailableException ex) {
            return new Readiness(false, ex.reason());
        } catch (RuntimeException ex) {
            return new Readiness(false, Reason.WRAPPER_UNAVAILABLE);
        }
    }

    /** Drops cached plaintext keys for a tenant (rotation, offboarding, suspected compromise). */
    public void evict(UUID tenantId) {
        keys.asMap().keySet().removeIf(k -> k.tenantId().equals(tenantId));
    }

    private byte[] cached(TenantKeyStore.StoredKey row) {
        return keys.get(new CacheKey(row.tenantId(), row.version()), k -> unwrap(row));
    }

    private byte[] unwrap(TenantKeyStore.StoredKey row) {
        if (row.state() == TenantKeyStore.State.DESTROYED || row.wrappedKey() == null) {
            throw new TenantKeyUnavailableException(Reason.KEY_DESTROYED, "Tenant key version was destroyed");
        }
        KeyWrapper w = requireWrapper();
        if (!w.kind().equals(row.wrapperKind())) {
            throw new TenantKeyUnavailableException(Reason.WRAPPER_UNAVAILABLE, "Tenant key was wrapped by a different wrapper kind");
        }
        byte[] dek = w.unwrap(row.wrappedKey(), row.keyRef(), new KeyContext(row.tenantId(), row.version()));
        if (dek.length != KEY_BYTES) {
            Arrays.fill(dek, (byte) 0);
            throw new TenantKeyUnavailableException(Reason.WRAPPER_UNAVAILABLE, "Unwrapped tenant key has the wrong length");
        }
        return dek;
    }

    private KeyWrapper requireWrapper() {
        if (wrapper == null) throw new TenantKeyUnavailableException(Reason.NOT_CONFIGURED, "Tenant encryption is not configured");
        return wrapper;
    }

    private byte[] newKey() {
        byte[] dek = new byte[KEY_BYTES];
        random.nextBytes(dek);
        return dek;
    }
}
