package com.prototype.vulnwatch.security.tenantkey;

/** Thrown when tenant encryption cannot be used. Callers must fail closed; the message never carries key material. */
public class TenantKeyUnavailableException extends IllegalStateException {

    public enum Reason { NOT_CONFIGURED, NOT_PROVISIONED, WRAPPER_UNAVAILABLE, UNKNOWN_KEY_VERSION, KEY_DESTROYED, INVALID_CIPHERTEXT }

    private final Reason reason;

    public TenantKeyUnavailableException(Reason reason, String message) {
        super(message);
        this.reason = reason;
    }

    public TenantKeyUnavailableException(Reason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
