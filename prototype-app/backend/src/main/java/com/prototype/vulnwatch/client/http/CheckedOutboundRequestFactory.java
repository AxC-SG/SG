package com.prototype.vulnwatch.client.http;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.core5.util.Timeout;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;

/** Pins address validation to the resolver used by the socket transport. */
public final class CheckedOutboundRequestFactory implements ClientHttpRequestFactory, AutoCloseable {
    private final HttpComponentsClientHttpRequestFactory delegate;
    private final OutboundHostPolicy policy;

    public CheckedOutboundRequestFactory(OutboundHostPolicy policy, long connectTimeoutMs, long readTimeoutMs) {
        this.policy = policy;
        var manager = PoolingHttpClientConnectionManagerBuilder.create()
                .setDnsResolver(new CheckedDnsResolver(policy))
                .setDefaultConnectionConfig(ConnectionConfig.custom()
                        .setConnectTimeout(Timeout.ofMilliseconds(connectTimeoutMs))
                        .setSocketTimeout(Timeout.ofMilliseconds(readTimeoutMs)).build())
                .build();
        var client = HttpClients.custom().setConnectionManager(manager)
                .setDefaultRequestConfig(RequestConfig.custom()
                        .setConnectionRequestTimeout(Timeout.ofMilliseconds(connectTimeoutMs))
                        .setResponseTimeout(Timeout.ofMilliseconds(readTimeoutMs)).build())
                .disableRedirectHandling().disableAutomaticRetries().disableCookieManagement().build();
        delegate = new HttpComponentsClientHttpRequestFactory(client);
    }

    @Override
    public ClientHttpRequest createRequest(URI uri, HttpMethod method) throws IOException {
        policy.validateAny(uri);
        return delegate.createRequest(uri, method);
    }

    @Override
    public void close() throws Exception {
        delegate.destroy();
    }

    static final class CheckedDnsResolver implements DnsResolver {
        private final OutboundHostPolicy policy;

        CheckedDnsResolver(OutboundHostPolicy policy) { this.policy = policy; }

        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {
            try {
                return policy.resolveForConnection(host);
            } catch (IllegalArgumentException failure) {
                UnknownHostException rejected = new UnknownHostException("Outbound address rejected");
                rejected.initCause(failure);
                throw rejected;
            }
        }

        @Override
        public String resolveCanonicalHostname(String host) { return host; }
    }

    /** Enforce the byte limit before converters or error handlers can buffer the response. */
    public static ClientHttpResponse bounded(ClientHttpResponse response, long maxBytes, long deadlineNanos) throws IOException {
        if (response.getHeaders().getContentLength() > maxBytes) {
            response.close();
            throw new IOException("Outbound response exceeds the byte limit");
        }
        InputStream body = new FilterInputStream(response.getBody()) {
            private long count;
            private void check(int read) throws IOException {
                if (read > 0) count += read;
                if (count > maxBytes || System.nanoTime() > deadlineNanos) {
                    throw new IOException("Outbound response exceeded its byte or time budget");
                }
            }
            @Override public int read() throws IOException {
                check(0);
                int value = in.read();
                check(value < 0 ? 0 : 1);
                return value;
            }
            @Override public int read(byte[] bytes, int offset, int length) throws IOException {
                check(0);
                int read = in.read(bytes, offset, (int) Math.min(length, Math.max(1, maxBytes - count + 1)));
                check(read);
                return read;
            }
            @Override public long skip(long amount) throws IOException {
                long skipped = 0;
                byte[] buffer = new byte[(int) Math.min(8192, Math.max(1, amount))];
                while (skipped < amount) {
                    int read = read(buffer, 0, (int) Math.min(buffer.length, amount - skipped));
                    if (read < 0) break;
                    skipped += read;
                }
                return skipped;
            }
        };
        return new ClientHttpResponse() {
            @Override public HttpStatusCode getStatusCode() throws IOException { return response.getStatusCode(); }
            @Override public String getStatusText() throws IOException { return response.getStatusText(); }
            @Override public HttpHeaders getHeaders() { return response.getHeaders(); }
            @Override public InputStream getBody() { return body; }
            @Override public void close() { response.close(); }
        };
    }
}
