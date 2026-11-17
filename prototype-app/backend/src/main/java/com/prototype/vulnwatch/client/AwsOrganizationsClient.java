package com.prototype.vulnwatch.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.auth.aws.signer.AwsV4HttpSigner;
import software.amazon.awssdk.http.auth.spi.signer.SignedRequest;

/**
 * AWS Organizations reads for account-level ownership tags (Phase 0B §2.2.1): {@code ListTagsForResource} for an
 * account and {@code DescribeAccount} for the connection test. Requests are AWS JSON 1.1, signed with SigV4 from the
 * Organizations role's credentials and sent through {@link OutboundHttpClient} under the {@code aws} provider policy,
 * so they get the same host allowlist, bounded retries and {@code Retry-After} handling as every other provider call.
 * Organizations is a global service served from us-east-1.
 */
@Component
public class AwsOrganizationsClient {

    public static final String PROVIDER_KEY = "aws";
    static final String ENDPOINT = "https://organizations.us-east-1.amazonaws.com/";
    private static final String TARGET_PREFIX = "AWSOrganizationsV20161128.";
    private static final int MAX_TAG_PAGES = 20;
    private static final Pattern ERROR_TYPE = Pattern.compile("\"__type\"\\s*:\\s*\"(?:[^\"#]*#)?([A-Za-z]+)\"");

    /** A failed Organizations call: {@code code} is the AWS error type (for example {@code AccessDeniedException}). */
    public static class AwsOrganizationsException extends RuntimeException {
        private final String code;
        private final Integer status;

        public AwsOrganizationsException(String code, Integer status, String message) {
            super(message);
            this.code = code;
            this.status = status;
        }

        public String code() {
            return code;
        }

        public Integer status() {
            return status;
        }
    }

    public record AccountDescription(String accountId, String name, String status) { }

    private final OutboundHttpClient http;
    private final OutboundPolicyFactory policies;
    private final ObjectMapper json;

    public AwsOrganizationsClient(OutboundHttpClient http, OutboundPolicyFactory policies, ObjectMapper json) {
        this.http = http;
        this.policies = policies;
        this.json = json;
    }

    /** Every tag on the account, following {@code NextToken}. */
    public Map<String, String> accountTags(AwsCredentialsProvider credentials, String accountId) {
        Map<String, String> tags = new LinkedHashMap<>();
        String next = null;
        for (int page = 0; page < MAX_TAG_PAGES; page++) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("ResourceId", accountId);
            if (next != null) body.put("NextToken", next);
            JsonNode response = call(credentials, "ListTagsForResource", body);
            response.path("Tags").forEach(tag -> tags.put(tag.path("Key").asText(), tag.path("Value").asText()));
            next = response.path("NextToken").isTextual() ? response.path("NextToken").asText() : null;
            if (next == null || next.isBlank()) return tags;
        }
        throw new AwsOrganizationsException("TooManyPages", null, "AWS account tags did not finish within " + MAX_TAG_PAGES + " pages");
    }

    public AccountDescription describeAccount(AwsCredentialsProvider credentials, String accountId) {
        JsonNode account = call(credentials, "DescribeAccount", Map.of("AccountId", accountId)).path("Account");
        return new AccountDescription(account.path("Id").asText(accountId), account.path("Name").asText(null), account.path("Status").asText(null));
    }

    private JsonNode call(AwsCredentialsProvider credentials, String operation, Map<String, Object> body) {
        String payload;
        try {
            payload = json.writeValueAsString(body);
        } catch (Exception impossible) {
            throw new IllegalStateException("Could not serialize the AWS Organizations request", impossible);
        }
        HttpHeaders headers = signedHeaders(credentials, operation, payload);
        OutboundPolicy policy = policies.forProvider(PROVIDER_KEY, null, null, null);
        String label = "AWS Organizations " + operation;
        ResponseEntity<String> response = http.exchange(ENDPOINT, HttpMethod.POST, new HttpEntity<>(payload, headers), String.class, label, policy,
                context -> new OutboundFailureDecision<RuntimeException>(
                        retryable(context.statusCodeValue(), context.error(), context.isRetryableByDefault()),
                        context.retryAfterDelayMs(),
                        failure(label, context.statusCodeValue(), context.error())));
        String text = response.getBody();
        try {
            return text == null || text.isBlank() ? json.createObjectNode() : json.readTree(text);
        } catch (Exception malformed) {
            throw new AwsOrganizationsException("MalformedResponse", 502, label + " returned a malformed response");
        }
    }

    private static HttpHeaders signedHeaders(AwsCredentialsProvider credentials, String operation, String payload) {
        SdkHttpRequest request = SdkHttpRequest.builder()
                .method(SdkHttpMethod.POST)
                .uri(URI.create(ENDPOINT))
                .putHeader("Content-Type", "application/x-amz-json-1.1")
                .putHeader("X-Amz-Target", TARGET_PREFIX + operation)
                .build();
        SignedRequest signed = AwsV4HttpSigner.create().sign(r -> r
                .identity(credentials.resolveCredentials())
                .request(request)
                .payload(ContentStreamProvider.fromUtf8String(payload))
                .putProperty(AwsV4HttpSigner.SERVICE_SIGNING_NAME, "organizations")
                .putProperty(AwsV4HttpSigner.REGION_NAME, "us-east-1"));
        HttpHeaders headers = new HttpHeaders();
        signed.request().forEachHeader((name, values) -> {
            if (!"Host".equalsIgnoreCase(name)) headers.put(name, List.copyOf(values));
        });
        return headers;
    }

    /**
     * AWS reports throttling as HTTP 400 with an error type, so the type decides: throttling and service errors are
     * retried, access and organization errors are final, and anything untyped follows the provider policy's default.
     */
    private static boolean retryable(Integer status, Exception error, boolean retryableByDefault) {
        String code = errorType(error);
        if ("TooManyRequestsException".equals(code) || "ThrottlingException".equals(code) || "ServiceException".equals(code)) return true;
        if (code != null) return false;
        return retryableByDefault;
    }

    private static RuntimeException failure(String label, Integer status, Exception error) {
        String code = errorType(error);
        if (code == null) code = status == null ? "Unreachable" : "HTTP" + status;
        String detail = switch (code) {
            case "AccessDeniedException" -> "the Organizations role is not allowed to read this account";
            case "AWSOrganizationsNotInUseException" -> "this AWS account is not part of an organization";
            case "AccountNotFoundException" -> "the account is not in the organization";
            case "TooManyRequestsException", "ThrottlingException" -> "AWS throttled the request";
            default -> status == null ? "the service could not be reached" : "HTTP " + status;
        };
        return new AwsOrganizationsException(code, status, label + " failed: " + detail);
    }

    static String errorType(Exception error) {
        // The transport's error text carries the AWS JSON error body, as it does for the other provider clients.
        if (error == null || error.getMessage() == null) return null;
        Matcher matcher = ERROR_TYPE.matcher(error.getMessage());
        return matcher.find() ? matcher.group(1) : null;
    }
}
