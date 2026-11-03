package com.prototype.vulnwatch.service;

public class CryptoSuppressionPolicyException extends RuntimeException {
    private final String reasonCode;

    public CryptoSuppressionPolicyException(String reasonCode, String message) {
        super(message);
        this.reasonCode = reasonCode;
    }

    public String getReasonCode() {
        return reasonCode;
    }
}
