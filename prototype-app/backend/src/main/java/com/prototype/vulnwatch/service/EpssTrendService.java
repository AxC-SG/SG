package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.OutboundFailureDecision;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicy;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

@Service
public class EpssTrendService {

    private static final Logger LOG = LoggerFactory.getLogger(EpssTrendService.class);

    @Value("${app.epss.base-url:https://api.first.org/data/v1/epss}")
    private String epssBaseUrl;

    private final OutboundHttpClient outboundHttpClient;
    private final OutboundPolicyFactory outboundPolicyFactory;
    private final ObjectMapper objectMapper;

    public EpssTrendService(
            OutboundHttpClient outboundHttpClient,
            OutboundPolicyFactory outboundPolicyFactory,
            ObjectMapper objectMapper
    ) {
        this.outboundHttpClient = outboundHttpClient;
        this.outboundPolicyFactory = outboundPolicyFactory;
        this.objectMapper = objectMapper;
    }

    public Double fetchSevenDayDelta(String cveId, Double currentScore, Instant scoreUpdatedAt) {
        if (currentScore == null || cveId == null || cveId.isBlank()) {
            return null;
        }
        LocalDate currentScoreDate = scoreUpdatedAt == null
                ? LocalDate.now(ZoneOffset.UTC)
                : LocalDate.ofInstant(scoreUpdatedAt, ZoneOffset.UTC);
        Double historicalScore = fetchScoreForDate(cveId, currentScoreDate.minusDays(7));
        if (historicalScore == null) {
            return null;
        }
        return currentScore - historicalScore;
    }

    private Double fetchScoreForDate(String cveId, LocalDate date) {
        String normalizedCveId = cveId.trim().toUpperCase(Locale.ROOT);
        String url = UriComponentsBuilder.fromUriString(epssBaseUrl)
                .queryParam("cve", normalizedCveId)
                .queryParam("date", date)
                .build()
                .toUriString();
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setAccept(List.of(MediaType.APPLICATION_JSON));
            headers.set("User-Agent", "vulnwatch-backend/1.0");
            ResponseEntity<String> response = outboundHttpClient.exchange(
                    url,
                    HttpMethod.GET,
                    new HttpEntity<>(headers),
                    String.class,
                    "EPSS history API",
                    outboundPolicy(),
                    context -> new OutboundFailureDecision<>(
                            context.isRetryableByDefault(),
                            context.retryAfterDelayMs(),
                            context.error() instanceof RuntimeException runtimeException
                                    ? runtimeException
                                    : new RuntimeException(context.error())
                    )
            );
            return parseScore(response.getBody(), normalizedCveId);
        } catch (Exception e) {
            LOG.debug("Unable to fetch EPSS history for {} on {}: {}", normalizedCveId, date, e.getMessage());
            return null;
        }
    }

    private Double parseScore(String payload, String cveId) {
        if (payload == null || payload.isBlank()) {
            return null;
        }
        try {
            JsonNode data = objectMapper.readTree(payload).path("data");
            if (!data.isArray()) {
                return null;
            }
            for (JsonNode entry : data) {
                if (!cveId.equals(entry.path("cve").asText("").toUpperCase(Locale.ROOT))) {
                    continue;
                }
                String value = entry.path("epss").asText("");
                if (value.isBlank()) {
                    return null;
                }
                return Double.parseDouble(value);
            }
        } catch (Exception e) {
            LOG.debug("Unable to parse EPSS history payload for {}: {}", cveId, e.getMessage());
        }
        return null;
    }

    private OutboundPolicy outboundPolicy() {
        return outboundPolicyFactory.forProvider("epss", 0L, null, null);
    }
}
