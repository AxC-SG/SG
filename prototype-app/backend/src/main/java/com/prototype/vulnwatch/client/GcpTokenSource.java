package com.prototype.vulnwatch.client;

/**
 * Short-lived OAuth access tokens for GCP calls, minted from the customer's own service account
 * key. An interface so tests and the discovery code never depend on real Google credentials.
 */
public interface GcpTokenSource {

    /** An access token for the service account whose key JSON is given. */
    String token(String serviceAccountKeyJson);
}
