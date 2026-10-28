package com.prototype.vulnwatch.client.http;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.io.support.ClassicRequestBuilder;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.util.Timeout;
import org.springframework.stereotype.Component;

/**
 * HTTPS client for an operator-approved BigFix server.
 *
 * <p>Name resolution goes through {@link BigFixHostPolicy#resolveForConnection}, so the socket only
 * ever connects to addresses the policy checked. Redirects, retries and cookies are disabled, TLS
 * certificates are verified by the JVM trust store, and responses are bounded in size and time.
 */
@Component
public class BigFixHttpTransport {

    static final long MAX_RESPONSE_BYTES = 200L * 1024 * 1024;
    private static final Timeout CONNECT_TIMEOUT = Timeout.ofSeconds(15);
    private static final Timeout RESPONSE_TIMEOUT = Timeout.ofSeconds(300);
    private static final long MAX_DURATION_NANOS = java.util.concurrent.TimeUnit.MINUTES.toNanos(10);

    private final BigFixHostPolicy policy;

    public BigFixHttpTransport(BigFixHostPolicy policy) {
        this.policy = policy;
    }

    public record Response(int status, String body) {}

    public Response get(URI baseUrl, String path, String username, String password) throws IOException {
        URI target = target(baseUrl, path);
        return send(ClassicRequestBuilder.get(target), username, password);
    }

    /** POST a form; used for {@code /api/query} so relevance travels in the body, not the URL. */
    public Response postForm(URI baseUrl, String path, List<BasicNameValuePair> form, String username, String password)
            throws IOException {
        URI target = target(baseUrl, path);
        ClassicRequestBuilder builder = ClassicRequestBuilder.post(target)
                .setEntity(new UrlEncodedFormEntity(form, StandardCharsets.UTF_8));
        return send(builder, username, password);
    }

    private URI target(URI baseUrl, String path) {
        // Re-validate: the stored URL may predate an allowlist change.
        URI base = policy.validateBaseUrl(baseUrl == null ? null : baseUrl.toString());
        if (path == null || !path.startsWith("/api/")) throw new IllegalArgumentException("Unexpected BigFix API path");
        return base.resolve(path);
    }

    private Response send(ClassicRequestBuilder builder, String username, String password) throws IOException {
        String credentials = Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        ClassicHttpRequest request = builder
                .addHeader("Authorization", "Basic " + credentials)
                .addHeader("Accept", "application/xml")
                .build();
        DnsResolver resolver = new DnsResolver() {
            @Override
            public InetAddress[] resolve(String host) throws UnknownHostException {
                try {
                    return policy.resolveForConnection(host);
                } catch (IllegalArgumentException rejected) {
                    UnknownHostException failure = new UnknownHostException("BigFix server address rejected");
                    failure.initCause(rejected);
                    throw failure;
                }
            }

            @Override
            public String resolveCanonicalHostname(String host) {
                return host;
            }
        };
        var manager = PoolingHttpClientConnectionManagerBuilder.create()
                .setDnsResolver(resolver)
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(CONNECT_TIMEOUT).setSocketTimeout(RESPONSE_TIMEOUT).build())
                .build();
        long deadline = System.nanoTime() + MAX_DURATION_NANOS;
        try (CloseableHttpClient client = HttpClients.custom().setConnectionManager(manager)
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(CONNECT_TIMEOUT).setResponseTimeout(RESPONSE_TIMEOUT).build())
                .disableRedirectHandling().disableAutomaticRetries().disableCookieManagement().build()) {
            return client.execute(request, response -> {
                HttpEntity entity = response.getEntity();
                String body = entity == null ? "" : readBounded(entity, deadline);
                return new Response(response.getCode(), body);
            });
        }
    }

    private static String readBounded(HttpEntity entity, long deadline) throws IOException {
        if (entity.getContentLength() > MAX_RESPONSE_BYTES) {
            throw new IOException("BigFix response exceeds the size limit");
        }
        try (InputStream in = entity.getContent()) {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] buffer = new byte[64 * 1024];
            int read;
            while ((read = in.read(buffer)) != -1) {
                if (out.size() + (long) read > MAX_RESPONSE_BYTES || System.nanoTime() > deadline) {
                    throw new IOException("BigFix response exceeded its size or time budget");
                }
                out.write(buffer, 0, read);
            }
            return out.toString(StandardCharsets.UTF_8);
        }
    }
}
