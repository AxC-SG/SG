package com.prototype.vulnwatch.service.patch.tanium;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.prototype.vulnwatch.client.http.CheckedHttpTransport;
import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * Tanium Cloud Gateway GraphQL client.
 *
 * <p>The API host must be the tenant's own {@code *.cloud.tanium.com} host; the checked transport
 * then refuses anything but a public address on port 443 and pins the address it checked. Queries
 * are constants and every value travels as a GraphQL variable.
 */
@Component
public class TaniumGateway {

    static final String GRAPHQL_PATH = "/plugin/products/gateway/graphql";
    static final int MAX_RESPONSE_BYTES = 50 * 1024 * 1024;
    private static final Pattern HOST = Pattern.compile("^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.cloud\\.tanium\\.com$");
    private static final Duration TIMEOUT = Duration.ofSeconds(120);

    private final CheckedHttpTransport transport;
    private final ObjectMapper objectMapper;

    @org.springframework.beans.factory.annotation.Autowired
    public TaniumGateway(ObjectMapper objectMapper) {
        this(new CheckedHttpTransport(), objectMapper);
    }

    TaniumGateway(CheckedHttpTransport transport, ObjectMapper objectMapper) {
        this.transport = transport;
        this.objectMapper = objectMapper;
    }

    /** {@code https://<tenant>.cloud.tanium.com}, or an operator-facing reason. */
    public static URI validateBaseUrl(String baseUrl) {
        URI uri;
        try {
            uri = new URI(baseUrl == null ? "" : baseUrl.trim());
        } catch (Exception malformed) {
            throw new IllegalArgumentException("Tanium Cloud API URL is not a valid URL");
        }
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || !HOST.matcher(host).matches()) {
            throw new IllegalArgumentException("Tanium Cloud API URL must be https://<your-tenant>.cloud.tanium.com");
        }
        if (uri.getUserInfo() != null || uri.getRawQuery() != null || uri.getRawFragment() != null
                || (uri.getPort() != -1 && uri.getPort() != 443)
                || (uri.getRawPath() != null && !uri.getRawPath().isEmpty() && !"/".equals(uri.getRawPath()))) {
            throw new IllegalArgumentException("Tanium Cloud API URL must be just https://<your-tenant>.cloud.tanium.com");
        }
        return URI.create("https://" + host);
    }

    /** Runs one query; GraphQL errors become an exception with the first message. */
    public JsonNode query(URI baseUrl, String token, String query, Map<String, Object> variables) {
        URI base = validateBaseUrl(baseUrl.toString());
        String body = body(query, variables);
        HttpRequest request = HttpRequest.newBuilder(base.resolve(GRAPHQL_PATH))
                .timeout(TIMEOUT)
                .header("session", token)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();
        CheckedHttpTransport.Response<String> response;
        try {
            response = transport.sendString(request, MAX_RESPONSE_BYTES);
        } catch (Exception failure) {
            throw new IllegalStateException("Tanium Gateway request failed: " + failure.getClass().getSimpleName());
        }
        if (response.statusCode() == 401 || response.statusCode() == 403) {
            throw new IllegalStateException("Tanium rejected the API token (HTTP " + response.statusCode() + ")");
        }
        if (response.statusCode() < 200 || response.statusCode() >= 300) {
            throw new IllegalStateException("Tanium Gateway request failed (HTTP " + response.statusCode() + ")");
        }
        return data(response.body());
    }

    String body(String query, Map<String, Object> variables) {
        ObjectNode payload = objectMapper.createObjectNode();
        payload.put("query", query);
        payload.set("variables", objectMapper.valueToTree(variables == null ? Map.of() : variables));
        return payload.toString();
    }

    JsonNode data(String body) {
        JsonNode root;
        try {
            root = objectMapper.readTree(body == null ? "" : body);
        } catch (Exception malformed) {
            throw new IllegalStateException("Tanium Gateway returned a malformed response");
        }
        JsonNode errors = root.path("errors");
        if (errors.isArray() && !errors.isEmpty()) {
            String message = errors.path(0).path("message").asText("unknown error");
            throw new IllegalStateException("Tanium Gateway error: " + (message.length() <= 300 ? message : message.substring(0, 300)));
        }
        return root.path("data");
    }
}
