package com.prototype.vulnwatch.service.sbomingestion;

import java.io.IOException;
import java.net.URI;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import org.springframework.beans.factory.annotation.Value;

@Service
public class SbomFetchGuardService {

    private final long maxPayloadBytes;
    private final boolean allowUserAuthHeader;
    private final OutboundHostPolicy outboundHostPolicy;

    public SbomFetchGuardService(
            @Value("${app.sbom-fetch.max-payload-bytes:5242880}") long maxPayloadBytes,
            @Value("${app.sbom-fetch.allow-user-auth-header:false}") boolean allowUserAuthHeader,
            OutboundHostPolicy outboundHostPolicy
    ) {
        this.maxPayloadBytes = maxPayloadBytes;
        this.allowUserAuthHeader = allowUserAuthHeader;
        this.outboundHostPolicy = outboundHostPolicy;
    }

    public HttpHeaders buildEndpointHeaders(String authorizationHeader) throws IOException {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(List.of(MediaType.APPLICATION_JSON, MediaType.TEXT_PLAIN, MediaType.ALL));
        if (authorizationHeader != null && !authorizationHeader.isBlank()) {
            if (!allowUserAuthHeader) {
                throw new IOException("Custom authorization headers are disabled for remote SBOM fetch");
            }
            headers.set(HttpHeaders.AUTHORIZATION, authorizationHeader.trim());
        }
        return headers;
    }

    public void validateRemoteSourceUrl(String value) throws IOException {
        URI uri;
        try {
            uri = URI.create(value);
        } catch (Exception e) {
            throw new IOException("Invalid source URL");
        }

        if (uri.getUserInfo() != null && !uri.getUserInfo().isBlank()) {
            throw new IOException("URL user info is not allowed");
        }
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IOException("Source URL host is required");
        }

        try {
            outboundHostPolicy.validate("sbom-endpoint", uri);
        } catch (IllegalArgumentException ex) {
            throw new IOException("Source URL is not an approved public HTTPS endpoint", ex);
        }
    }

    public long maxPayloadBytes() {
        // Both are existing bounds. A larger remote configuration cannot bypass the
        // common BOM byte ceiling applied to fetched and uploaded documents.
        return Math.min(maxPayloadBytes, com.prototype.vulnwatch.util.BomInputLimits.MAX_BOM_BYTES);
    }

    public void ensurePayloadWithinLimit(long bytes) throws IOException {
        if (bytes > maxPayloadBytes()) {
            throw new IOException("SBOM payload exceeds max allowed size");
        }
    }

}
