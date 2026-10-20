package com.prototype.vulnwatch.client.http;

import java.net.URI;
import java.io.FilterInputStream;
import java.io.InputStream;
import java.io.IOException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.ResponseErrorHandler;
import java.util.function.Supplier;
import org.springframework.web.client.ResponseExtractor;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import com.prototype.vulnwatch.util.LogUtil;

public class OutboundHttpClient {

    private static final Logger LOG = LoggerFactory.getLogger(OutboundHttpClient.class);

    private final RestTemplate restTemplate;
    private final OutboundHostPolicy hostPolicy;
    private final LongSupplier currentTimeMillis;
    private final SleepStrategy sleepStrategy;
    private final ConcurrentHashMap<String, ProviderPacingState> pacingByProvider = new ConcurrentHashMap<>();

    public OutboundHttpClient(RestTemplate restTemplate) {
        this(
                restTemplate,
                OutboundHostPolicy.forTests(),
                System::currentTimeMillis,
                millis -> {
                    if (millis > 0) {
                        Thread.sleep(millis);
                    }
                }
        );
    }

    public OutboundHttpClient(RestTemplate restTemplate, OutboundHostPolicy hostPolicy) {
        this(
                restTemplate,
                hostPolicy,
                System::currentTimeMillis,
                millis -> {
                    if (millis > 0L) Thread.sleep(millis);
                }
        );
    }

    OutboundHttpClient(
            RestTemplate restTemplate,
            OutboundHostPolicy hostPolicy,
            LongSupplier currentTimeMillis,
            SleepStrategy sleepStrategy
    ) {
        this.restTemplate = restTemplate;
        this.hostPolicy = hostPolicy;
        this.currentTimeMillis = currentTimeMillis;
        this.sleepStrategy = sleepStrategy;
    }

    OutboundHttpClient(
            RestTemplate restTemplate,
            LongSupplier currentTimeMillis,
            SleepStrategy sleepStrategy
    ) {
        this(restTemplate, OutboundHostPolicy.forTests(), currentTimeMillis, sleepStrategy);
    }

    public <T, E extends Exception> ResponseEntity<T> exchange(
            String endpoint,
            HttpMethod method,
            HttpEntity<?> requestEntity,
            Class<T> responseType,
            String operationName,
            OutboundPolicy policy,
            OutboundFailureClassifier<E> classifier
    ) throws E {
        return execute(
                endpoint,
                method,
                requestEntity,
                responseType,
                operationName,
                policy,
                classifier,
                response -> response
        );
    }

    public <T, R, E extends Exception> R execute(
            String endpoint,
            HttpMethod method,
            HttpEntity<?> requestEntity,
            Class<T> responseType,
            String operationName,
            OutboundPolicy policy,
            OutboundFailureClassifier<E> classifier,
            OutboundResponseHandler<T, R> responseHandler
    ) throws E {
        return executeAttempts(endpoint, operationName, policy, classifier,
                () -> performExchange(endpoint, method, requestEntity, responseType, policy), responseHandler);
    }

    /** Reads a response inside RestTemplate's connection lifetime, before buffering it. */
    public <T, E extends Exception> ResponseEntity<T> exchangeExtracted(
            String endpoint,
            HttpMethod method,
            HttpEntity<?> requestEntity,
            ResponseExtractor<ResponseEntity<T>> extractor,
            long maxResponseBytes,
            String operationName,
            OutboundPolicy policy,
            OutboundFailureClassifier<E> classifier
    ) throws E {
        // Share the configured request factory (timeouts, host guard, redirects) without
        // changing the shared template's error handler during concurrent requests.
        RestTemplate boundedTemplate = new RestTemplate(restTemplate.getRequestFactory());
        ResponseErrorHandler delegate = restTemplate.getErrorHandler();
        boundedTemplate.setErrorHandler(new ResponseErrorHandler() {
            @Override
            public boolean hasError(ClientHttpResponse response) throws IOException {
                return delegate.hasError(response);
            }

            @Override
            public void handleError(URI url, HttpMethod httpMethod, ClientHttpResponse response) throws IOException {
                delegate.handleError(url, httpMethod, boundedResponse(response, maxResponseBytes));
            }
        });
        return executeAttempts(endpoint, operationName, policy, classifier,
                () -> performExchange(endpoint, method, policy,
                        uri -> boundedTemplate.execute(uri, method,
                                restTemplate.httpEntityCallback(requestEntity), extractor)), response -> response);
    }

    private ClientHttpResponse boundedResponse(ClientHttpResponse response, long maxBytes) throws IOException {
        if (response.getHeaders().getContentLength() > maxBytes) {
            throw new IOException("HTTP response exceeds max allowed size");
        }
        InputStream body = new FilterInputStream(response.getBody()) {
            private long count;

            @Override
            public int read() throws IOException {
                int value = super.read();
                if (value != -1 && ++count > maxBytes) {
                    throw new IOException("HTTP response exceeds max allowed size");
                }
                return value;
            }

            @Override
            public int read(byte[] bytes, int offset, int length) throws IOException {
                int allowed = (int) Math.min(length, Math.max(1L, maxBytes - count + 1L));
                int read = in.read(bytes, offset, allowed);
                if (read > 0 && (count += read) > maxBytes) {
                    throw new IOException("HTTP response exceeds max allowed size");
                }
                return read;
            }
        };
        return new ClientHttpResponse() {
            @Override
            public HttpStatusCode getStatusCode() throws IOException { return response.getStatusCode(); }
            @Override
            public String getStatusText() throws IOException { return response.getStatusText(); }
            @Override
            public HttpHeaders getHeaders() { return response.getHeaders(); }
            @Override
            public InputStream getBody() { return body; }
            @Override
            public void close() { response.close(); }
        };
    }

    private <T, R, E extends Exception> R executeAttempts(
            String endpoint,
            String operationName,
            OutboundPolicy policy,
            OutboundFailureClassifier<E> classifier,
            Supplier<ResponseEntity<T>> request,
            OutboundResponseHandler<T, R> responseHandler
    ) throws E {
        int attempts = Math.max(1, policy.maxRetries());
        for (int attempt = 1; attempt <= attempts; attempt++) {
            try {
                ResponseEntity<T> response = request.get();
                return responseHandler.handle(response);
            } catch (Exception error) {
                OutboundFailureContext context = new OutboundFailureContext(
                        endpoint,
                        operationName,
                        policy,
                        error,
                        attempt,
                        attempts
                );
                OutboundFailureDecision<E> decision = classifier.classify(context);
                boolean lastAttempt = attempt >= attempts;
                if (!decision.retryable() || lastAttempt) {
                    E terminalException = decision.terminalException();
                    logTerminal(context, terminalException);
                    throw terminalException;
                }
                long delayMs = decision.retryDelayMs() != null
                        ? Math.max(0L, decision.retryDelayMs())
                        : computeBackoffDelayMs(policy, attempt);
                LOG.warn(
                        "Outbound HTTP retry provider={} operation={} attempt={}/{} status={} delayMs={} endpoint={}",
                        policy.providerKey(),
                        operationName,
                        attempt,
                        attempts,
                        describeStatus(context),
                        delayMs,
                        LogUtil.safe(endpoint)
                );
                sleep(delayMs, policy.providerKey(), operationName);
            }
        }
        throw new IllegalStateException("Outbound retry loop exhausted without terminal exception");
    }

    private <T> ResponseEntity<T> performExchange(
            String endpoint,
            HttpMethod method,
            HttpEntity<?> requestEntity,
            Class<T> responseType,
            OutboundPolicy policy
    ) {
        return performExchange(endpoint, method, policy,
                uri -> restTemplate.exchange(uri, method, requestEntity, responseType));
    }

    private <T> ResponseEntity<T> performExchange(
            String endpoint,
            HttpMethod method,
            OutboundPolicy policy,
            java.util.function.Function<URI, ResponseEntity<T>> request
    ) {
        ProviderPacingState state = pacingByProvider.computeIfAbsent(policy.providerKey(), ignored -> new ProviderPacingState());
        state.lock.lock();
        try {
            long waitMs = waitTimeMs(state.hasCompletedRequest, state.lastRequestCompletedAtMs, policy.minRequestIntervalMs());
            sleep(waitMs, policy.providerKey(), "request pacing");
            try {
                URI uri = URI.create(endpoint);
                hostPolicy.validate(policy.providerKey(), uri);
                return request.apply(uri);
            } finally {
                state.lastRequestCompletedAtMs = currentTimeMillis.getAsLong();
                state.hasCompletedRequest = true;
            }
        } finally {
            state.lock.unlock();
        }
    }

    private long waitTimeMs(boolean hasCompletedRequest, long lastRequestCompletedAtMs, long minRequestIntervalMs) {
        if (minRequestIntervalMs <= 0L) {
            return 0L;
        }
        if (!hasCompletedRequest) {
            return 0L;
        }
        long now = currentTimeMillis.getAsLong();
        long elapsed = now - lastRequestCompletedAtMs;
        return Math.max(0L, minRequestIntervalMs - elapsed);
    }

    private long computeBackoffDelayMs(OutboundPolicy policy, int attempt) {
        long base = Math.max(0L, policy.retryBaseBackoffMs());
        if (base == 0L) {
            return 0L;
        }
        long exponent = 1L << Math.min(6, Math.max(0, attempt - 1));
        long candidate = Math.multiplyExact(base, exponent);
        long jitterUpperBound = Math.max(25L, Math.min(1000L, base));
        long jitter = jitterUpperBound <= 0L ? 0L : java.util.concurrent.ThreadLocalRandom.current().nextLong(jitterUpperBound + 1L);
        long bounded = Math.min(Long.MAX_VALUE - jitter, candidate) + jitter;
        return Math.min(policy.maxBackoffMs(), bounded);
    }

    private void logTerminal(OutboundFailureContext context, Exception terminalException) {
        LOG.warn(
                "Outbound HTTP terminal failure provider={} operation={} attempt={}/{} status={} endpoint={}",
                context.policy().providerKey(),
                context.operationName(),
                context.attempt(),
                context.maxAttempts(),
                describeStatus(context),
                LogUtil.safe(context.endpoint()),
                terminalException
        );
    }

    private String describeStatus(OutboundFailureContext context) {
        Integer status = context.statusCodeValue();
        if (status != null) {
            return Integer.toString(status);
        }
        return context.isNetworkAccessError() ? "NETWORK" : "CLIENT_EXCEPTION";
    }

    private void sleep(long millis, String providerKey, String operationName) {
        if (millis <= 0L) {
            return;
        }
        try {
            sleepStrategy.sleep(millis);
        } catch (InterruptedException interruptedException) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(
                    "Interrupted while waiting for outbound HTTP " + operationName + " (" + providerKey + ")",
                    interruptedException
            );
        }
    }

    @FunctionalInterface
    interface SleepStrategy {
        void sleep(long millis) throws InterruptedException;
    }

    private static final class ProviderPacingState {
        private final ReentrantLock lock = new ReentrantLock();
        private volatile boolean hasCompletedRequest = false;
        private volatile long lastRequestCompletedAtMs = 0L;
    }
}
