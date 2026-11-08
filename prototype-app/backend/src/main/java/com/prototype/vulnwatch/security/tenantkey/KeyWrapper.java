package com.prototype.vulnwatch.security.tenantkey;

/**
 * Wraps and unwraps tenant data-encryption keys with a key-encryption key that never leaves the
 * wrapper (a KMS key in deployed environments). The encryption context is bound to every wrap so a
 * wrapped key copied to another tenant or version cannot be unwrapped.
 */
public interface KeyWrapper {

    /** Value stored in {@code platform.tenant_data_keys.wrapper_kind}. */
    String kind();

    /** Reference of the key-encryption key used for new wraps, stored with each wrapped key. */
    String activeKeyRef();

    byte[] wrap(byte[] plaintextKey, KeyContext context);

    byte[] unwrap(byte[] wrappedKey, String keyRef, KeyContext context);
}
