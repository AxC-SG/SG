package com.prototype.vulnwatch.security.tenantkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.prototype.vulnwatch.security.tenantkey.TenantKeyUnavailableException.Reason;
import java.time.Duration;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class TenantDataCipherTest {

    private static final String MASTER = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    private static final String OTHER_MASTER = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    private final UUID tenantA = UUID.randomUUID();
    private final UUID tenantB = UUID.randomUUID();
    private InMemoryTenantKeyStore store;
    private FlakyWrapper wrapper;
    private TenantKeyRegistry registry;
    private TenantDataCipher cipher;

    @BeforeEach
    void setUp() {
        store = new InMemoryTenantKeyStore();
        wrapper = new FlakyWrapper(new LocalKeyWrapper("test", MASTER));
        registry = new TenantKeyRegistry(store, wrapper, Duration.ofMinutes(10), 100);
        cipher = new AesGcmTenantDataCipher(registry);
        registry.provision(tenantA);
        registry.provision(tenantB);
    }

    @Test
    void roundTripsAndUsesTenantPrefix() {
        String ct = cipher.encrypt(tenantA, "directory_user.email", "ada@example.com");
        assertThat(ct).startsWith("enc:t1:1:").doesNotContain("ada");
        assertThat(cipher.decrypt(tenantA, "directory_user.email", ct)).isEqualTo("ada@example.com");
        assertThat(cipher.encrypt(tenantA, "directory_user.email", "ada@example.com")).isNotEqualTo(ct);
        assertThat(cipher.encrypt(tenantA, "x", null)).isNull();
        assertThat(cipher.decrypt(tenantA, "x", null)).isNull();
    }

    @Test
    void ciphertextIsBoundToTenantAndPurpose() {
        String ct = cipher.encrypt(tenantA, "directory_user.email", "ada@example.com");
        assertThatThrownBy(() -> cipher.decrypt(tenantB, "directory_user.email", ct))
                .isInstanceOfSatisfying(TenantKeyUnavailableException.class, ex -> assertThat(ex.reason()).isEqualTo(Reason.INVALID_CIPHERTEXT));
        assertThatThrownBy(() -> cipher.decrypt(tenantA, "directory_user.display_name", ct))
                .isInstanceOf(TenantKeyUnavailableException.class);
    }

    @Test
    void rejectsMalformedCiphertextAndPurpose() {
        for (String bad : new String[] {"plain", "enc:t1:", "enc:t1:x:AAAA", "enc:t1:0:AAAA", "enc:t1:1:!!!", "enc:t1:1:AAAA", "enc:v2:primary:AAAA"}) {
            assertThatThrownBy(() -> cipher.decrypt(tenantA, "p", bad)).isInstanceOf(TenantKeyUnavailableException.class);
        }
        assertThatThrownBy(() -> cipher.encrypt(tenantA, "Bad Purpose", "v")).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rotationKeepsOldValuesReadableAndBlindIndexStable() {
        String before = cipher.encrypt(tenantA, "p", "secret");
        byte[] indexBefore = cipher.blindIndex(tenantA, "directory_user.email", "ada@example.com");
        assertThat(registry.rotate(tenantA)).isEqualTo(2);
        String after = cipher.encrypt(tenantA, "p", "secret");
        assertThat(cipher.keyVersionOf(before)).isEqualTo(1);
        assertThat(cipher.keyVersionOf(after)).isEqualTo(2);
        assertThat(cipher.decrypt(tenantA, "p", before)).isEqualTo("secret");
        assertThat(cipher.decrypt(tenantA, "p", after)).isEqualTo("secret");
        assertThat(cipher.blindIndex(tenantA, "directory_user.email", "ada@example.com")).isEqualTo(indexBefore);
        assertThat(store.find(tenantA, 1).orElseThrow().state()).isEqualTo(TenantKeyStore.State.DECRYPT_ONLY);
    }

    @Test
    void blindIndexIsDeterministicPerTenantAndPurpose() {
        byte[] a = cipher.blindIndex(tenantA, "directory_user.email", "ada@example.com");
        assertThat(a).hasSize(32).isEqualTo(cipher.blindIndex(tenantA, "directory_user.email", "ada@example.com"));
        assertThat(cipher.blindIndex(tenantB, "directory_user.email", "ada@example.com")).isNotEqualTo(a);
        assertThat(cipher.blindIndex(tenantA, "directory_user.employee_id", "ada@example.com")).isNotEqualTo(a);
    }

    @Test
    void provisionIsIdempotent() {
        assertThat(registry.provision(tenantA)).isEqualTo(1);
        assertThat(store.rows.get(tenantA)).hasSize(1);
    }

    @Test
    void cachedKeysSurviveWrapperOutageButReadinessFailsClosed() {
        String ct = cipher.encrypt(tenantA, "p", "secret");
        wrapper.down.set(true);
        assertThat(cipher.decrypt(tenantA, "p", ct)).isEqualTo("secret");
        assertThat(cipher.readiness(tenantA)).isEqualTo(new TenantKeyRegistry.Readiness(false, Reason.WRAPPER_UNAVAILABLE));
        registry.evict(tenantA);
        assertThatThrownBy(() -> cipher.decrypt(tenantA, "p", ct)).isInstanceOf(TenantKeyUnavailableException.class);
        wrapper.down.set(false);
        assertThat(cipher.readiness(tenantA).ready()).isTrue();
    }

    @Test
    void unconfiguredOrUnprovisionedFailsClosed() {
        TenantKeyRegistry disabled = new TenantKeyRegistry(store, null, Duration.ofMinutes(1), 10);
        TenantDataCipher off = new AesGcmTenantDataCipher(disabled);
        assertThat(off.readiness(tenantA)).isEqualTo(new TenantKeyRegistry.Readiness(false, Reason.NOT_CONFIGURED));
        assertThatThrownBy(() -> off.encrypt(tenantA, "p", "v"))
                .isInstanceOfSatisfying(TenantKeyUnavailableException.class, ex -> assertThat(ex.reason()).isEqualTo(Reason.NOT_CONFIGURED));
        UUID fresh = UUID.randomUUID();
        assertThat(cipher.readiness(fresh).reason()).isEqualTo(Reason.NOT_PROVISIONED);
        assertThatThrownBy(() -> cipher.encrypt(fresh, "p", "v")).isInstanceOf(TenantKeyUnavailableException.class);
    }

    @Test
    void wrappedKeyCannotBeMovedBetweenTenants() {
        TenantKeyStore.StoredKey a = store.find(tenantA, 1).orElseThrow();
        UUID thief = UUID.randomUUID();
        store.put(new TenantKeyStore.StoredKey(thief, 1, a.wrapperKind(), a.keyRef(), a.wrappedKey(), TenantKeyStore.State.ACTIVE));
        assertThat(registry.readiness(thief).ready()).isFalse();
        assertThatThrownBy(() -> cipher.encrypt(thief, "p", "v")).isInstanceOf(TenantKeyUnavailableException.class);
    }

    @Test
    void differentMasterKeyCannotUnwrap() {
        TenantKeyRegistry other = new TenantKeyRegistry(store, new LocalKeyWrapper("local", OTHER_MASTER), Duration.ofMinutes(1), 10);
        assertThat(other.readiness(tenantA).ready()).isFalse();
    }

    @Test
    void destroyedVersionIsUnreadable() {
        String ct = cipher.encrypt(tenantA, "p", "secret");
        TenantKeyStore.StoredKey a = store.find(tenantA, 1).orElseThrow();
        store.put(new TenantKeyStore.StoredKey(tenantA, 1, a.wrapperKind(), a.keyRef(), null, TenantKeyStore.State.DESTROYED));
        registry.evict(tenantA);
        assertThatThrownBy(() -> cipher.decrypt(tenantA, "p", ct))
                .isInstanceOfSatisfying(TenantKeyUnavailableException.class, ex -> assertThat(ex.reason()).isEqualTo(Reason.KEY_DESTROYED));
    }

    @Test
    void localWrapperRefusesDeployedEnvironmentsAndBadKeys() {
        for (String env : new String[] {"production", "preproduction", "", null}) {
            assertThatThrownBy(() -> new LocalKeyWrapper(env, MASTER)).isInstanceOf(IllegalStateException.class);
        }
        assertThatThrownBy(() -> new LocalKeyWrapper("test", "AAAA")).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> new LocalKeyWrapper("test", "not base64!")).isInstanceOf(IllegalStateException.class);
    }

    /** Delegating wrapper whose unwrap can be switched off to simulate a KMS outage. */
    static final class FlakyWrapper implements KeyWrapper {
        final AtomicBoolean down = new AtomicBoolean();
        private final KeyWrapper delegate;

        FlakyWrapper(KeyWrapper delegate) { this.delegate = delegate; }

        @Override public String kind() { return delegate.kind(); }
        @Override public String activeKeyRef() { return delegate.activeKeyRef(); }
        @Override public byte[] wrap(byte[] key, KeyContext ctx) { return delegate.wrap(key, ctx); }

        @Override
        public byte[] unwrap(byte[] wrapped, String ref, KeyContext ctx) {
            if (down.get()) throw new TenantKeyUnavailableException(Reason.WRAPPER_UNAVAILABLE, "simulated outage");
            return delegate.unwrap(wrapped, ref, ctx);
        }
    }
}
