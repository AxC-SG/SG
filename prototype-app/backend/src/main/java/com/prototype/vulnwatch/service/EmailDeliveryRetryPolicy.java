package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.client.ResendEmailClient;
import java.time.Duration;
import java.time.Instant;

/** Resend retains an idempotency key for 24 hours. Stop automatic replay after 23 hours. */
public final class EmailDeliveryRetryPolicy {
    private EmailDeliveryRetryPolicy() { }
    public static boolean replayWindowExpired(Instant first,Instant now) {
        return first!=null && !now.isBefore(first.plus(Duration.ofHours(23)));
    }
    public static String outcome(ResendEmailClient.DeliveryResult result,int attempts) {
        return switch(result.state()) {
            case SENT -> "ACCEPTED";
            case FAILED -> "FAILED";
            case UNKNOWN -> "UNKNOWN";
            default -> attempts>=8 ? "UNKNOWN" : "PENDING";
        };
    }
}
