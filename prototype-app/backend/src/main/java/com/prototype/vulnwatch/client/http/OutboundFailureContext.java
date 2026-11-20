package com.prototype.vulnwatch.client.http;

import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.ResourceAccessException;

public record OutboundFailureContext(
        String endpoint,
        String operationName,
        OutboundPolicy policy,
        Exception error,
        int attempt,
        int maxAttempts
) {

    public Integer statusCodeValue() {
        if (error instanceof HttpStatusCodeException httpStatusError) {
            return httpStatusError.getStatusCode().value();
        }
        return null;
    }

    public String responseBody() {
        return error instanceof HttpStatusCodeException httpError ? httpError.getResponseBodyAsString() : "";
    }

    public String retryAfterHeader() {
        if (error instanceof HttpStatusCodeException httpStatusError) {
            HttpHeaders headers = httpStatusError.getResponseHeaders();
            return headers == null ? null : headers.getFirst(HttpHeaders.RETRY_AFTER);
        }
        return null;
    }

    public boolean isNetworkAccessError() {
        if (error instanceof ResourceAccessException) {
            return true;
        }
        Throwable cause = error;
        while (cause != null) {
            if (cause instanceof SocketTimeoutException
                    || cause instanceof ConnectException
                    || cause instanceof UnknownHostException) {
                return true;
            }
            cause = cause.getCause();
        }
        return false;
    }

    public boolean isRetryableByDefault() {
        Integer statusCode = statusCodeValue();
        if (statusCode != null) {
            return policy.isRetryableStatus(statusCode);
        }
        return policy.retryOnNetworkErrors() && isNetworkAccessError();
    }

    public Long retryAfterDelayMs() {
        if (!policy.honorRetryAfter()) {
            return null;
        }
        String retryAfterHeader = retryAfterHeader();
        if (retryAfterHeader == null || retryAfterHeader.isBlank()) {
            return null;
        }
        String normalized = retryAfterHeader.trim();
        try {
            return Math.max(0L, Long.parseLong(normalized) * 1000L);
        } catch (NumberFormatException ignored) {
            // fall through
        }
        try {
            ZonedDateTime retryAt = ZonedDateTime.parse(normalized, DateTimeFormatter.RFC_1123_DATE_TIME);
            long delayMs = retryAt.toInstant().toEpochMilli() - Instant.now().toEpochMilli();
            return Math.max(0L, delayMs);
        } catch (Exception ignored) {
            return null;
        }
    }
}
