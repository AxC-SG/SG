package com.prototype.vulnwatch.service.sbomingestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;

import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

class SbomEndpointFetchServiceTest {
    private static final int LIMIT = 64;
    private static final String URL = "https://example.test/bom.json";
    private MockRestServiceServer server;
    private SbomEndpointFetchService service;

    @BeforeEach
    void setUp() {
        RestTemplate template = new RestTemplate();
        server = MockRestServiceServer.bindTo(template).build();
        OutboundHostPolicy hosts = OutboundHostPolicy.forTests();
        service = new SbomEndpointFetchService(new OutboundHttpClient(template, hosts),
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0, 3, 0, 0, true, true)),
                new SbomFetchGuardService(LIMIT, false, hosts), mock(SbomUploadSupportService.class));
    }

    @Test
    void acceptsExactlyConfiguredCeilingWithChunkedResponse() throws Exception {
        CountingBody body = respond(LIMIT, -1, HttpStatus.OK);
        assertEquals(LIMIT, service.fetch(request()).content().length);
        assertEquals(LIMIT, body.readBytes);
        assertTrue(body.closed);
        server.verify();
    }

    @ParameterizedTest
    @ValueSource(longs = {-1, 1})
    void rejectsDuringReadWithMissingOrFalseContentLength(long declared) {
        CountingBody body = respond(1_000_000_000L, declared, HttpStatus.OK);
        assertThrows(IOException.class, () -> service.fetch(request()));
        assertEquals(LIMIT + 1, body.readBytes);
        assertTrue(body.closed);
        // Only one expectation: a deterministic oversize rejection must not retry.
        server.verify();
    }

    @Test
    void rejectsDeclaredOversizeBeforeReadingTheBody() {
        CountingBody body = respond(1_000_000_000L, LIMIT + 1, HttpStatus.OK);
        assertThrows(IOException.class, () -> service.fetch(request()));
        assertEquals(0, body.readBytes);
        assertTrue(body.closed);
        server.verify();
    }

    @Test
    void boundsErrorBodiesBeforeTheDefaultErrorHandlerBuffersThem() {
        // Non-retryable status also proves the error handler, before extraction, is bounded.
        CountingBody body = respond(1_000_000_000L, -1, HttpStatus.BAD_REQUEST);
        assertThrows(IOException.class, () -> service.fetch(request()));
        assertTrue(body.readBytes <= LIMIT + 1);
        assertTrue(body.closed);
        server.verify();
    }

    @Test
    void preservesRetryPolicyForTransientHttpFailures() throws Exception {
        respond(3, -1, HttpStatus.SERVICE_UNAVAILABLE);
        respond(4, -1, HttpStatus.OK);
        assertEquals(4, service.fetch(request()).content().length);
        server.verify();
    }

    @Test
    void oversizedTransientErrorBodiesRemainBoundedOnEveryConfiguredRetry() {
        CountingBody first = respond(1_000_000_000L, -1, HttpStatus.SERVICE_UNAVAILABLE);
        CountingBody second = respond(1_000_000_000L, -1, HttpStatus.SERVICE_UNAVAILABLE);
        CountingBody third = respond(1_000_000_000L, -1, HttpStatus.SERVICE_UNAVAILABLE);
        assertThrows(IOException.class, () -> service.fetch(request()));
        for (CountingBody body : java.util.List.of(first, second, third)) {
            assertTrue(body.readBytes <= LIMIT + 1);
            assertTrue(body.closed);
        }
        server.verify();
    }

    private CountingBody respond(long actualLength, long declaredLength, HttpStatus status) {
        CountingBody body = new CountingBody(actualLength);
        server.expect(requestTo(URL)).andRespond(request -> {
            MockClientHttpResponse response = new MockClientHttpResponse(body, status);
            if (declaredLength >= 0) {
                response.getHeaders().setContentLength(declaredLength);
            } else {
                response.getHeaders().set("Transfer-Encoding", "chunked");
            }
            return response;
        });
        return body;
    }

    private SbomEndpointIngestionRequest request() {
        return new SbomEndpointIngestionRequest(AssetType.APPLICATION, "app", "app", URL, null, null);
    }

    private static final class CountingBody extends InputStream {
        private final long length;
        private long readBytes;
        private boolean closed;

        private CountingBody(long length) {
            this.length = length;
        }

        @Override
        public int read() {
            if (readBytes == length) {
                return -1;
            }
            readBytes++;
            return 'a';
        }

        @Override
        public int read(byte[] bytes, int offset, int count) {
            if (readBytes == length) {
                return -1;
            }
            int read = (int) Math.min(count, length - readBytes);
            Arrays.fill(bytes, offset, offset + read, (byte) 'a');
            readBytes += read;
            return read;
        }

        @Override
        public void close() {
            closed = true;
        }
    }
}
