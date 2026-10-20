package com.prototype.vulnwatch.client.http;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.http.HttpRequest;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import org.springframework.http.HttpMethod;
import org.springframework.web.client.RestTemplate;

/** Bounded socket-checked transport for clients that already validate their provider-specific URI. */
public class CheckedHttpTransport {
    public Response<String> sendString(HttpRequest request, int maxBytes) throws Exception {
        Response<byte[]> response = send(request, maxBytes);
        return new Response<>(response.statusCode(), response.headers(), new String(response.body(), StandardCharsets.UTF_8));
    }

    public Response<InputStream> sendStream(HttpRequest request, int maxBytes) throws Exception {
        Response<byte[]> response = send(request, maxBytes);
        return new Response<>(response.statusCode(), response.headers(), new ByteArrayInputStream(response.body()));
    }

    private Response<byte[]> send(HttpRequest request, int maxBytes) throws Exception {
        if (maxBytes < 1) throw new IllegalArgumentException("Response budget must be positive");
        var policy = new OutboundHostPolicy("provider=" + request.uri().getHost());
        policy.validateAny(request.uri());
        long timeoutMs = Math.min(120_000, request.timeout().orElse(java.time.Duration.ofSeconds(30)).toMillis());
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        byte[] requestBody = requestBody(request, timeoutMs);
        try (var factory = new CheckedOutboundRequestFactory(policy, Math.min(timeoutMs, 15_000), timeoutMs)) {
            var template = new RestTemplate(factory);
            // Preserve the provider clients' own status/error classification.
            template.setErrorHandler(new org.springframework.web.client.NoOpResponseErrorHandler());
            return template.execute(request.uri(), HttpMethod.valueOf(request.method()), outbound -> {
                request.headers().map().forEach((name, values) -> outbound.getHeaders().put(name, values));
                outbound.getBody().write(requestBody);
            }, incoming -> {
                try (var response = CheckedOutboundRequestFactory.bounded(incoming, maxBytes, deadline)) {
                    byte[] body = response.getBody().readAllBytes();
                    return new Response<>(response.getStatusCode().value(),
                            java.net.http.HttpHeaders.of(response.getHeaders(), (name, value) -> true), body);
                }
            });
        }
    }

    private byte[] requestBody(HttpRequest request, long timeoutMs) throws Exception {
        if (request.bodyPublisher().isEmpty()) return new byte[0];
        CompletableFuture<byte[]> result = new CompletableFuture<>();
        request.bodyPublisher().orElseThrow().subscribe(new Flow.Subscriber<ByteBuffer>() {
            private final ByteArrayOutputStream body = new ByteArrayOutputStream();
            private Flow.Subscription subscription;
            @Override public void onSubscribe(Flow.Subscription value) { subscription = value; value.request(Long.MAX_VALUE); }
            @Override public void onNext(ByteBuffer item) {
                if ((long) body.size() + item.remaining() > 2_000_000) {
                    subscription.cancel();
                    result.completeExceptionally(new IllegalArgumentException("Outbound request exceeds its byte budget"));
                    return;
                }
                byte[] bytes = new byte[item.remaining()];
                item.get(bytes);
                body.writeBytes(bytes);
            }
            @Override public void onError(Throwable failure) { result.completeExceptionally(failure); }
            @Override public void onComplete() { result.complete(body.toByteArray()); }
        });
        return result.get(timeoutMs, TimeUnit.MILLISECONDS);
    }

    public record Response<T>(int statusCode, java.net.http.HttpHeaders headers, T body) { }
}
