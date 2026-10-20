package com.prototype.vulnwatch.service.sbomingestion;

import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import com.prototype.vulnwatch.dto.SbomEndpointIngestionRequest;
import java.io.IOException;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
public class SbomEndpointFetchService {

    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final SbomFetchGuardService sbomFetchGuardService;
    private final SbomUploadSupportService sbomUploadSupportService;

    public SbomEndpointFetchService(
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            SbomFetchGuardService sbomFetchGuardService,
            SbomUploadSupportService sbomUploadSupportService
    ) {
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.sbomFetchGuardService = sbomFetchGuardService;
        this.sbomUploadSupportService = sbomUploadSupportService;
    }

    public SbomEndpointFetchResult fetch(SbomEndpointIngestionRequest request) throws IOException {
        String url = request.sourceUrl().trim();
        sbomFetchGuardService.validateRemoteSourceUrl(url);

        ResponseEntity<byte[]> response;
        try {
            response = outboundHttpClient.exchangeExtracted(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(sbomFetchGuardService.buildEndpointHeaders(request.authorizationHeader())),
                    this::readBoundedResponse,
                    sbomFetchGuardService.maxPayloadBytes(),
                    "Remote SBOM fetch",
                    outboundPolicy(),
                    context -> new OutboundFailureDecision<>(
                            !isPayloadLimitFailure(context.error()) && context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof IOException ioException
                                    ? ioException
                                    : new IOException(context.error())
                    )
            );
        } catch (IOException ioException) {
            throw ioException;
        } catch (Exception checkedException) {
            throw new IOException(checkedException);
        }

        long declaredLength = response.getHeaders().getContentLength();
        if (declaredLength > 0) {
            sbomFetchGuardService.ensurePayloadWithinLimit(declaredLength);
        }
        byte[] content = response.getBody();
        if (content == null || content.length == 0) {
            throw new IOException("Remote endpoint returned empty SBOM payload");
        }
        sbomFetchGuardService.ensurePayloadWithinLimit(content.length);

        Map<String, Object> evidence = new LinkedHashMap<>();
        evidence.put("ingestionMode", "remote-endpoint");
        evidence.put("sourceUrl", url);
        evidence.put("statusCode", response.getStatusCode().value());
        evidence.put("responseContentType", response.getHeaders().getFirst("Content-Type"));
        evidence.put("fetchedAt", Instant.now());

        SbomIngestionSourceMetadata metadata = new SbomIngestionSourceMetadata(
                "REMOTE_ENDPOINT",
                "api",
                request.sourceLabel() == null || request.sourceLabel().isBlank() ? url : request.sourceLabel().trim(),
                url,
                response.getStatusCode().value(),
                response.getHeaders().getFirst("Content-Type"),
                response.getHeaders().getContentLength() >= 0
                        ? response.getHeaders().getContentLength()
                        : (long) content.length,
                sbomUploadSupportService.toJson(evidence)
        );
        return new SbomEndpointFetchResult(content, metadata);
    }

    private ResponseEntity<byte[]> readBoundedResponse(
            org.springframework.http.client.ClientHttpResponse response) throws IOException {
        long limit = sbomFetchGuardService.maxPayloadBytes();
        if (response.getHeaders().getContentLength() > limit) {
            throw new PayloadLimitException();
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        InputStream input = response.getBody();
        byte[] buffer = new byte[8192];
        long total = 0;
        while (true) {
            // Read at most one byte beyond the ceiling, including absent or false headers.
            int length = (int) Math.min(buffer.length, Math.max(1L, limit - total + 1L));
            int read = input.read(buffer, 0, length);
            if (read == -1) {
                break;
            }
            total += read;
            if (total > limit) {
                throw new PayloadLimitException();
            }
            output.write(buffer, 0, read);
        }
        return new ResponseEntity<>(output.toByteArray(), response.getHeaders(), response.getStatusCode());
    }

    private boolean isPayloadLimitFailure(Throwable error) {
        for (Throwable cause = error; cause != null; cause = cause.getCause()) {
            if (cause instanceof PayloadLimitException) {
                return true;
            }
        }
        return false;
    }

    private static final class PayloadLimitException extends IOException {
        private PayloadLimitException() {
            super("SBOM payload exceeds max allowed size");
        }
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("sbom-endpoint", 0L, null, null);
    }
}
