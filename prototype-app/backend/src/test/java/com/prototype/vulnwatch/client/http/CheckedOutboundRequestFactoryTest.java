package com.prototype.vulnwatch.client.http;

import static org.junit.jupiter.api.Assertions.*;
import java.net.InetAddress;
import java.net.URI;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.mock.http.client.MockClientHttpResponse;

class CheckedOutboundRequestFactoryTest {
    @Test
    void dnsChangeBetweenAdmissionAndSocketIsRejectedWithoutConnecting() throws Exception {
        AtomicInteger resolutions = new AtomicInteger();
        var policy = new OutboundHostPolicy("provider=approved.example", host -> {
            try {
                return new InetAddress[]{InetAddress.getByName(resolutions.incrementAndGet() == 1 ? "93.184.216.34" : "169.254.169.254")};
            } catch (Exception failure) { throw new IllegalStateException(failure); }
        });
        try (var factory = new CheckedOutboundRequestFactory(policy, 100, 100)) {
            var request = factory.createRequest(URI.create("https://approved.example/data"), HttpMethod.GET);
            assertThrows(java.io.IOException.class, request::execute);
            assertEquals(2, resolutions.get());
        }
    }

    @Test
    void rejectsOversizeStreamingAndExpiredBodiesBeforeBuffering() throws Exception {
        try (var response = CheckedOutboundRequestFactory.bounded(new MockClientHttpResponse(new byte[9], HttpStatus.OK), 8, Long.MAX_VALUE)) {
            assertThrows(java.io.IOException.class, () -> response.getBody().readAllBytes());
        }
        try (var response = CheckedOutboundRequestFactory.bounded(new MockClientHttpResponse(new byte[1], HttpStatus.OK), 8, 0)) {
            assertThrows(java.io.IOException.class, () -> response.getBody().read());
        }
    }
}
