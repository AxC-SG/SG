package com.prototype.vulnwatch.client.http;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

/** Azure management response consumption stays in the shared transport package. */
@Component
public class AzureManagementTransport {

    private final RestTemplate http;

    public AzureManagementTransport() {
        this(new RestTemplate(new CheckedOutboundRequestFactory(new OutboundHostPolicy(""), 15_000, 30_000)));
    }

    @Autowired
    public AzureManagementTransport(RestTemplate http) {
        this.http = http;
    }

    public byte[] get(URI uri, String bearerToken, int maxBytes, long durationMs) throws IOException {
        long deadline = System.nanoTime() + java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(durationMs);
        return http.execute(uri, HttpMethod.GET, request -> {
            request.getHeaders().setBearerAuth(bearerToken);
            request.getHeaders().setAccept(List.of(MediaType.APPLICATION_JSON));
        }, response -> {
            try (var bounded = CheckedOutboundRequestFactory.bounded(response, maxBytes, deadline)) {
                if (!bounded.getStatusCode().is2xxSuccessful()) {
                    throw new IOException("Azure management request failed");
                }
                return bounded.getBody().readAllBytes();
            }
        });
    }
}
