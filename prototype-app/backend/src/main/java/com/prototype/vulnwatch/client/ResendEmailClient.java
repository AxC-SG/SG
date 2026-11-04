package com.prototype.vulnwatch.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class ResendEmailClient {

    public enum DeliveryState {
        QUEUED,
        RETRYABLE,
        UNKNOWN,
        SENT,
        SKIPPED,
        FAILED
    }

    public record EmailMessage(
            String to,
            String subject,
            String html,
            String text,
            Map<String, String> tags,
            String idempotencyKey,
            String from
    ) {
        public EmailMessage(String to,String subject,String html,String text,Map<String,String> tags,String idempotencyKey) {
            this(to,subject,html,text,tags,idempotencyKey,null);
        }
    }

    public record DeliveryResult(
            DeliveryState state,
            String providerMessageId,
            String detail
    ) {
        public static DeliveryResult sent(String providerMessageId) {
            return new DeliveryResult(DeliveryState.SENT, providerMessageId, null);
        }

        public static DeliveryResult skipped(String detail) {
            return new DeliveryResult(DeliveryState.SKIPPED, null, detail);
        }

        public static DeliveryResult failed(String detail) {
            return new DeliveryResult(DeliveryState.FAILED, null, detail);
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(ResendEmailClient.class);
    private static final String DEFAULT_BASE_URL = "https://api.resend.com";
    private static final String DEFAULT_USER_AGENT = "vulnwatch-backend/resend";
    private static final String DEFAULT_FROM_DOMAIN = "scoutgrid.io";
    private static final String DEFAULT_FROM_ADDRESS = "Scout.ai <noreply@" + DEFAULT_FROM_DOMAIN + ">";
    private static final Duration CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(20);
    private static final Pattern EMAIL_ADDRESS_PATTERN = Pattern.compile("<?\\s*([^<>\\s]+@[^<>\\s]+)\\s*>?$");

    private final ObjectMapper objectMapper;
    private final com.prototype.vulnwatch.client.http.CheckedHttpTransport httpClient;
    private final String baseUrl;
    private final String apiKey;
    private final String fromAddress;
    private final String fromDomain;

    public ResendEmailClient(
            ObjectMapper objectMapper,
            @Value("${app.email.resend.base-url:https://api.resend.com}") String baseUrl,
            @Value("${app.email.resend.api-key:${RESEND_API_KEY:}}") String apiKey,
            @Value("${app.email.resend.from:${RESEND_FROM_EMAIL:}}") String fromAddress,
            @Value("${app.email.resend.from-domain:${RESEND_FROM_DOMAIN:scoutgrid.io}}") String fromDomain
    ) {
        this.objectMapper = objectMapper;
        this.httpClient = new com.prototype.vulnwatch.client.http.CheckedHttpTransport();
        this.baseUrl = normalize(baseUrl, DEFAULT_BASE_URL);
        this.apiKey = normalize(apiKey, "");
        this.fromDomain = normalize(fromDomain, DEFAULT_FROM_DOMAIN).toLowerCase();
        this.fromAddress = normalizeFromAddress(fromAddress, this.fromDomain);
    }

    public DeliveryResult send(EmailMessage message) {
        if (!isConfigured()) {
            return DeliveryResult.skipped("Resend delivery is not configured");
        }
        try {
            HttpRequest request = HttpRequest.newBuilder(URI.create(baseUrl + "/emails"))
                    .timeout(REQUEST_TIMEOUT)
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .header("Accept", "application/json")
                    .header("User-Agent", DEFAULT_USER_AGENT)
                    .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payloadFor(message))))
                    .build();
            if (message.idempotencyKey() != null && !message.idempotencyKey().isBlank()) {
                request = HttpRequest.newBuilder(request.uri())
                        .timeout(REQUEST_TIMEOUT)
                        .header("Authorization", "Bearer " + apiKey)
                        .header("Content-Type", "application/json")
                        .header("Accept", "application/json")
                        .header("User-Agent", DEFAULT_USER_AGENT)
                        .header("Idempotency-Key", message.idempotencyKey().trim())
                        .POST(HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(payloadFor(message))))
                        .build();
            }
            var response = httpClient.sendString(request, 1_000_000);
            if (response.statusCode() >= 200 && response.statusCode() < 300) {
                return DeliveryResult.sent(parseMessageId(response.body()));
            }
            LOG.warn("Resend request rejected with HTTP status {}",response.statusCode());
            return new DeliveryResult(response.statusCode()==429 || response.statusCode()>=500 ? DeliveryState.RETRYABLE : DeliveryState.FAILED,
                    null,"HTTP_"+response.statusCode());
        } catch (Exception ex) {
            if (ex instanceof InterruptedException) Thread.currentThread().interrupt();
            LOG.warn("Resend request outcome is unknown");
            return new DeliveryResult(DeliveryState.RETRYABLE,null,"PROVIDER_OUTCOME_UNKNOWN");
        }
    }

    public EmailMessage freeze(EmailMessage message,String deliveryKey) {
        return new EmailMessage(message.to(),message.subject(),message.html(),message.text(),message.tags()==null ? Map.of() : Map.copyOf(message.tags()),deliveryKey,fromAddress);
    }

    public boolean isConfigured() {
        return !apiKey.isBlank() && !fromAddress.isBlank();
    }

    private Map<String, Object> payloadFor(EmailMessage message) {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("from", message.from()==null ? fromAddress : message.from());
        payload.put("to", List.of(message.to()));
        payload.put("subject", message.subject());
        payload.put("html", message.html());
        payload.put("text", message.text());
        if (message.tags() != null && !message.tags().isEmpty()) {
            payload.put("tags", message.tags().entrySet().stream()
                    .map(entry -> Map.of("name", entry.getKey(), "value", entry.getValue()))
                    .toList());
        }
        return payload;
    }

    private String parseMessageId(String body) {
        if (body == null || body.isBlank()) {
            return null;
        }
        try {
            JsonNode payload = objectMapper.readTree(body);
            return payload.path("id").asText(null);
        } catch (Exception ex) {
            LOG.debug("Unable to parse Resend acceptance identifier");
            return null;
        }
    }

    private String normalize(String value, String fallback) {
        return value == null || value.isBlank()
                ? fallback
                : value.trim().replaceAll("/+$", "");
    }

    private String normalizeFromAddress(String configuredFromAddress, String verifiedDomain) {
        String normalized = configuredFromAddress == null ? "" : configuredFromAddress.trim();
        if (normalized.isBlank()) {
            return defaultFromAddress(verifiedDomain);
        }
        String domain = domainForAddress(normalized);
        if (domain == null || !domain.equalsIgnoreCase(verifiedDomain)) {
            LOG.warn("Configured Resend from address '{}' does not match verified domain '{}'; using fallback sender", normalized, verifiedDomain);
            return defaultFromAddress(verifiedDomain);
        }
        return normalized;
    }

    private String defaultFromAddress(String verifiedDomain) {
        return DEFAULT_FROM_DOMAIN.equalsIgnoreCase(verifiedDomain)
                ? DEFAULT_FROM_ADDRESS
                : "Scout.ai <noreply@" + verifiedDomain + ">";
    }

    private String domainForAddress(String address) {
        Matcher matcher = EMAIL_ADDRESS_PATTERN.matcher(address);
        if (!matcher.find()) {
            return null;
        }
        String email = matcher.group(1);
        int atIndex = email.lastIndexOf('@');
        if (atIndex < 0 || atIndex == email.length() - 1) {
            return null;
        }
        return email.substring(atIndex + 1).toLowerCase();
    }
}
