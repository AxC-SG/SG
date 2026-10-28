package com.prototype.vulnwatch.service.patch.intune;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Microsoft Graph reads for the Intune patch connector, through {@link OutboundHttpClient}
 * (provider {@value #PROVIDER_KEY}: only {@code graph.microsoft.com} and
 * {@code login.microsoftonline.com}). Paging follows {@code @odata.nextLink} only while it stays
 * on Graph, and every listing reports whether it was complete.
 */
@Component
public class IntuneGraphClient {

    public static final String PROVIDER_KEY = "intune";
    static final String GRAPH = "https://graph.microsoft.com/";
    static final String LOGIN = "https://login.microsoftonline.com/";
    static final Pattern GUID = Pattern.compile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$");
    private static final Pattern GRAPH_ERROR = Pattern.compile("\"(?:message|error_description)\"\\s*:\\s*\"((?:[^\"\\\\]|\\\\.)*)\"");

    private final OutboundHttpClient http;
    private final OutboundPolicyFactory policies;
    private final ObjectMapper objectMapper;

    public IntuneGraphClient(OutboundHttpClient http, OutboundPolicyFactory policies, ObjectMapper objectMapper) {
        this.http = http;
        this.policies = policies;
        this.objectMapper = objectMapper;
    }

    /** All items of one listing, and whether every page was read. */
    public record Listing(List<JsonNode> items, boolean complete, String warning) {}

    public static class GraphException extends RuntimeException {
        private final int status;

        public GraphException(int status, String message) {
            super(message);
            this.status = status;
        }

        public int status() {
            return status;
        }
    }

    /** An app-only Graph token via the client-credentials flow. The secret is never logged. */
    public String token(String directoryId, String clientId, String clientSecret) {
        if (!GUID.matcher(directoryId == null ? "" : directoryId).matches()) {
            throw new GraphException(400, "Directory (tenant) ID must be a GUID");
        }
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        form.add("scope", GRAPH + ".default");
        form.add("grant_type", "client_credentials");
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        JsonNode body = send(LOGIN + directoryId + "/oauth2/v2.0/token", HttpMethod.POST,
                new HttpEntity<>(form, headers), "Entra ID sign-in");
        String token = body.path("access_token").asText(null);
        if (token == null || token.isBlank()) throw new GraphException(502, "Entra ID returned no access token");
        return token;
    }

    /** One page only, for connection tests. */
    public JsonNode first(String token, String path) {
        return send(GRAPH + path, HttpMethod.GET, new HttpEntity<Void>(bearer(token)), operation(path));
    }

    public Listing list(String token, String path, int maxPages, int maxItems) {
        List<JsonNode> items = new ArrayList<>();
        String url = GRAPH + path;
        int pages = 0;
        while (url != null) {
            if (pages >= maxPages || items.size() >= maxItems) {
                return new Listing(items, false, operation(path) + " exceeded the import limit");
            }
            JsonNode page = send(url, HttpMethod.GET, new HttpEntity<Void>(bearer(token)), operation(path));
            page.path("value").forEach(items::add);
            pages++;
            String next = page.path("@odata.nextLink").asText(null);
            if (next != null && !next.startsWith(GRAPH)) {
                return new Listing(items, false, operation(path) + " returned a next page outside Microsoft Graph");
            }
            url = next;
        }
        return new Listing(items, true, null);
    }

    private JsonNode send(String url, HttpMethod method, HttpEntity<?> entity, String operation) {
        OutboundPolicy policy = policies.forProvider(PROVIDER_KEY, null, null, null);
        ResponseEntity<String> response = http.exchange(url, method, entity, String.class, operation, policy,
                context -> new OutboundFailureDecision<RuntimeException>(
                        context.isRetryableByDefault(),
                        context.retryAfterDelayMs(),
                        failure(operation, context.statusCodeValue(), context.error())));
        String body = response.getBody();
        if (body == null || body.isBlank()) return objectMapper.createObjectNode();
        try {
            return objectMapper.readTree(body);
        } catch (Exception malformed) {
            throw new GraphException(502, operation + " returned a malformed response");
        }
    }

    private static RuntimeException failure(String operation, Integer status, Exception error) {
        if (status == null) {
            return new GraphException(503, operation + " failed: " + (error == null ? "network error" : error.getClass().getSimpleName()));
        }
        String detail = graphMessage(error == null ? null : error.getMessage());
        String hint = status == 401 || status == 403 ? " Check the application's Graph permissions and admin consent." : "";
        return new GraphException(status, operation + " failed (HTTP " + status + ")" + (detail == null ? "" : ": " + detail) + hint);
    }

    /** Graph's {@code error.message} or Entra's {@code error_description}, carried in the HTTP error text. */
    static String graphMessage(String errorText) {
        if (errorText == null) return null;
        Matcher matcher = GRAPH_ERROR.matcher(errorText);
        if (!matcher.find()) return null;
        String message = matcher.group(1);
        // Entra descriptions append trace and correlation ids; the first sentence is the useful part.
        int trace = message.indexOf("\\r\\nTrace ID");
        if (trace > 0) message = message.substring(0, trace);
        return message.length() <= 300 ? message : message.substring(0, 300);
    }

    private static HttpHeaders bearer(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        return headers;
    }

    private static String operation(String path) {
        String trimmed = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
        return "Graph " + trimmed;
    }
}
