package com.prototype.vulnwatch.security.tenantkey;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

final class InMemoryTenantKeyStore implements TenantKeyStore {

    final Map<UUID, Map<Integer, StoredKey>> rows = new ConcurrentHashMap<>();

    @Override
    public synchronized Optional<StoredKey> active(UUID tenantId) {
        return rows.getOrDefault(tenantId, Map.of()).values().stream().filter(k -> k.state() == State.ACTIVE).findFirst();
    }

    @Override
    public synchronized Optional<StoredKey> find(UUID tenantId, int version) {
        return Optional.ofNullable(rows.getOrDefault(tenantId, Map.of()).get(version));
    }

    @Override
    public synchronized boolean insertInitial(StoredKey key) {
        Map<Integer, StoredKey> tenant = rows.computeIfAbsent(key.tenantId(), t -> new ConcurrentHashMap<>());
        if (!tenant.isEmpty()) return false;
        tenant.put(key.version(), key);
        return true;
    }

    @Override
    public synchronized boolean rotate(UUID tenantId, int expectedActiveVersion, StoredKey next) {
        Map<Integer, StoredKey> tenant = rows.get(tenantId);
        StoredKey current = tenant == null ? null : tenant.get(expectedActiveVersion);
        if (current == null || current.state() != State.ACTIVE || tenant.containsKey(next.version())) return false;
        tenant.put(current.version(), new StoredKey(tenantId, current.version(), current.wrapperKind(), current.keyRef(),
                current.wrappedKey(), State.DECRYPT_ONLY));
        tenant.put(next.version(), next);
        return true;
    }

    void put(StoredKey key) {
        rows.computeIfAbsent(key.tenantId(), t -> new ConcurrentHashMap<>()).put(key.version(), key);
    }
}
