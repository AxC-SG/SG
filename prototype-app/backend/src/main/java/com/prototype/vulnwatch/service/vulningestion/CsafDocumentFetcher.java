package com.prototype.vulnwatch.service.vulningestion;

import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;

@Service
public class CsafDocumentFetcher {

    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;

    @Value("${app.csaf.document-fetch-max-attempts:3}")
    private int csafDocumentFetchMaxAttempts;

    @Value("${app.csaf.document-retry-backoff-ms:300}")
    private long csafDocumentRetryBackoffMs;

    public CsafDocumentFetcher(
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory
    ) {
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
    }

    public CsafDocumentFetchResult fetch(String url, String providerKey) {
        OutboundPolicy policy = outboundPolicyFactory.forProvider(
                "csaf-" + (providerKey == null ? "" : providerKey.trim().toLowerCase(Locale.ROOT)),
                0L,
                Math.max(1, csafDocumentFetchMaxAttempts),
                Math.max(0L, csafDocumentRetryBackoffMs)
        );
        AtomicInteger attemptCounter = new AtomicInteger(0);
        try {
            return outboundHttpClient.execute(
                    url,
                    HttpMethod.GET,
                    HttpEntity.EMPTY,
                    String.class,
                    "CSAF document fetch",
                    policy,
                    context -> classifyFailure(context, policy, attemptCounter),
                    response -> {
                        String body = response.getBody();
                        if (body == null || body.isBlank()) {
                            throw new IllegalStateException("CSAF document body is empty");
                        }
                        return CsafDocumentFetchResult.success(body, Math.max(1, attemptCounter.get() + 1));
                    }
            );
        } catch (RuntimeException error) {
            String category = failureCategory(error);
            return CsafDocumentFetchResult.failure(Math.max(1, attemptCounter.get()), category, error.getMessage());
        } catch (Exception checkedException) {
            String category = failureCategory(checkedException);
            return CsafDocumentFetchResult.failure(Math.max(1, attemptCounter.get()), category, checkedException.getMessage());
        }
    }

    public String failureCategory(Exception error) {
        if (error instanceof HttpStatusCodeException httpStatusError) {
            return "HTTP_" + httpStatusError.getStatusCode().value();
        }
        if (error instanceof ResourceAccessException) {
            return "NETWORK_ACCESS";
        }
        String message = error.getMessage() == null ? "" : error.getMessage().toLowerCase(Locale.ROOT);
        if (message.contains("timed out")) {
            return "TIMEOUT";
        }
        if (message.contains("parse")) {
            return "PARSE_ERROR";
        }
        if (message.contains("empty")) {
            return "EMPTY_BODY";
        }
        return "UNKNOWN_ERROR";
    }

    private boolean isRetryableCategory(String category) {
        if (category == null || category.isBlank()) {
            return false;
        }
        if (category.startsWith("HTTP_")) {
            try {
                int code = Integer.parseInt(category.substring("HTTP_".length()));
                return code == 408 || code == 429 || code >= 500;
            } catch (NumberFormatException ignored) {
                return false;
            }
        }
        return "NETWORK_ACCESS".equals(category) || "TIMEOUT".equals(category);
    }

    private OutboundFailureDecision<RuntimeException> classifyFailure(
            com.prototype.vulnwatch.client.http.OutboundFailureContext context,
            OutboundPolicy policy,
            AtomicInteger attemptCounter
    ) {
        attemptCounter.set(context.attempt());
        RuntimeException terminalException = context.error() instanceof RuntimeException runtimeException
                ? runtimeException
                : new RuntimeException(context.error());
        String category = failureCategory(terminalException);
        boolean retryable = context.attempt() < policy.maxRetries() && isRetryableCategory(category);
        Long retryDelay = context.retryAfterDelayMs();
        return new OutboundFailureDecision<>(retryable, retryDelay, terminalException);
    }
}
