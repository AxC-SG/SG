package com.prototype.vulnwatch.client.http;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.GenerativeAssistancePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.List;
import java.util.Map;

@Component
public class OpenAiClient {

    public record AiCallOptions(String model, double temperature, int maxTokens, boolean jsonMode) {
        public static AiCallOptions defaults(int maxTokens) {
            return new AiCallOptions(null, 0.3, maxTokens, false);
        }

        public static AiCallOptions json(int maxTokens) {
            return new AiCallOptions(null, 0.3, maxTokens, true);
        }
    }

    private static final Logger log = LoggerFactory.getLogger(OpenAiClient.class);

    @Value("${app.openai.base-url:https://api.openai.com/v1}")
    private String baseUrl;

    @Value("${app.openai.model:gpt-4o-mini}")
    private String model;

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final GenerativeAssistancePolicy generativeAssistancePolicy;

    public OpenAiClient(RestTemplate restTemplate, ObjectMapper objectMapper, GenerativeAssistancePolicy generativeAssistancePolicy) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
        this.generativeAssistancePolicy = generativeAssistancePolicy;
    }

    public boolean isAvailable() {
        return generativeAssistancePolicy.configuredApiKey() != null;
    }

    public String chatCompletion(String systemPrompt, String userPrompt) {
        return chatCompletion(systemPrompt, userPrompt, 300);
    }

    public String chatCompletion(String systemPrompt, String userPrompt, int maxTokens) {
        return chat(systemPrompt, userPrompt, AiCallOptions.defaults(maxTokens));
    }

    /** Calls the chat completions API with response_format=json_object. */
    public String chatCompletionJson(String systemPrompt, String userPrompt, int maxTokens) {
        return chat(systemPrompt, userPrompt, AiCallOptions.json(maxTokens));
    }

    public String chat(String systemPrompt, String userPrompt, AiCallOptions options) {
        String apiKey = generativeAssistancePolicy.configuredApiKey();
        if (apiKey == null) return null;
        try {
            String url = baseUrl.stripTrailing() + "/chat/completions";

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.setBearerAuth(apiKey);

            java.util.LinkedHashMap<String, Object> body = new java.util.LinkedHashMap<>();
            body.put("model", options.model() != null && !options.model().isBlank() ? options.model() : model);
            body.put("messages", List.of(
                Map.of("role", "system", "content", systemPrompt),
                Map.of("role", "user", "content", userPrompt)
            ));
            body.put("max_tokens", options.maxTokens());
            body.put("temperature", options.temperature());
            if (options.jsonMode()) {
                body.put("response_format", Map.of("type", "json_object"));
            }

            HttpEntity<java.util.LinkedHashMap<String, Object>> request = new HttpEntity<>(body, headers);
            ResponseEntity<JsonNode> response = restTemplate.exchange(url, HttpMethod.POST, request, JsonNode.class);

            JsonNode responseBody = response.getBody();
            if (responseBody == null) return null;
            return responseBody.path("choices").get(0).path("message").path("content").asText(null);
        } catch (Exception e) {
            log.warn("OpenAI API call failed: {}", e.getMessage());
            return null;
        }
    }
}
