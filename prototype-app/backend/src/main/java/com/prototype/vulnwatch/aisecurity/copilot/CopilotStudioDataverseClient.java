package com.prototype.vulnwatch.aisecurity.copilot;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityDigestService;
import com.prototype.vulnwatch.aisecurity.service.AiGridProviderCallCounter;
import com.prototype.vulnwatch.domain.Tenant;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

/** Read-only Dataverse client. It requests only explicitly selected definition metadata. */
@Component
public class CopilotStudioDataverseClient {
    private static final int MAX_BODY_CHARS = 4_000_000;
    private final ObjectMapper json;
    private final AiSecurityDigestService digests;
    private final AiGridProviderCallCounter providerCalls;
    private final int maxPages;
    private final int maxAttempts;
    private final long retryBackoffMs;
    private final com.prototype.vulnwatch.client.http.CheckedHttpTransport http = new com.prototype.vulnwatch.client.http.CheckedHttpTransport();

    public CopilotStudioDataverseClient(ObjectMapper json, AiSecurityDigestService digests,
                                        AiGridProviderCallCounter providerCalls,
                                        @Value("${app.ai-security.runtime.max-api-calls-per-run:100}") int maxPages,
                                        @Value("${app.ai-security.copilot.max-attempts:3}") int maxAttempts,
                                        @Value("${app.ai-security.copilot.retry-backoff-ms:250}") long retryBackoffMs) {
        this.json = json; this.digests = digests; this.providerCalls = providerCalls;
        this.maxPages = Math.max(1, maxPages); this.maxAttempts = Math.max(1, maxAttempts);
        this.retryBackoffMs = Math.max(0, retryBackoffMs);
    }

    public Discovery discover(Tenant tenant, TokenCredential credential, String organizationUrl) {
        URI base = organization(organizationUrl);
        List<Bot> bots = new ArrayList<>();
        List<Component> components = new ArrayList<>();
        List<CoverageGap> gaps = new ArrayList<>();
        try {
            for (JsonNode node : list(credential, base.resolve("api/data/v9.2/bots?$select=botid,name,componentstate,versionnumber&$filter=componentstate%20eq%200"))) {
                String id = text(node, "botid");
                if (id != null) bots.add(new Bot(id, text(node, "name"), text(node, "componentstate"), text(node, "versionnumber")));
            }
        } catch (DataverseException error) { gaps.add(new CoverageGap("BOTS", error.status(), error.getMessage())); }
        try {
            // Content is hashed immediately and never leaves this parsing boundary.
            for (JsonNode node : list(credential, base.resolve("api/data/v9.2/botcomponents?$select=botcomponentid,name,componenttype,versionnumber,_parentbotid_value,content&$filter=componentstate%20eq%200"))) {
                String id = text(node, "botcomponentid");
                if (id == null) continue;
                String typeCode = text(node, "componenttype");
                String kind = componentType(typeCode);
                String content = text(node, "content");
                ComponentCategory category = category(typeCode);
                AiSecurityDigestService.Digest digest = content == null || category == ComponentCategory.COMPONENT
                        ? null
                        : digests.digest(tenant,
                                category == ComponentCategory.TOOL ? "tool-definition" : "prompt-definition",
                                content);
                components.add(new Component(id, text(node, "name"), kind, text(node, "versionnumber"),
                        text(node, "_parentbotid_value"), known(typeCode), category, digest));
                if (!known(typeCode)) gaps.add(new CoverageGap("COMPONENT:" + id, 200, "Unknown Copilot component retained as AI_COMPONENT"));
            }
        } catch (DataverseException error) { gaps.add(new CoverageGap("COMPONENTS", error.status(), error.getMessage())); }
        return new Discovery(List.copyOf(bots), List.copyOf(components), List.copyOf(gaps));
    }

    /** Transcript rows are used only as execution metadata; transcript content is never selected. */
    public List<Execution> executions(TokenCredential credential, String organizationUrl, Instant after) {
        com.prototype.vulnwatch.aisecurity.service.AiRuntimeScope.requireInScope();
        URI base = organization(organizationUrl); List<Execution> result = new ArrayList<>();
        String filter = "conversationtranscripts?$select=conversationtranscriptid,conversationstarttime,createdon,_bot_conversationtranscriptid_value"
                + "&$filter=createdon%20ge%20" + java.net.URLEncoder.encode(after.toString(), java.nio.charset.StandardCharsets.UTF_8);
        for (JsonNode node : list(credential, base.resolve("api/data/v9.2/" + filter))) {
            String id = text(node, "conversationtranscriptid");
            if (id != null) {
                Instant occurredAt = instant(node, "conversationstarttime");
                if (occurredAt == null) occurredAt = instant(node, "createdon");
                result.add(new Execution(id, text(node, "_bot_conversationtranscriptid_value"),
                        occurredAt, "RECORDED"));
            }
        }
        return List.copyOf(result);
    }

    public PermissionTest testPermissions(TokenCredential credential, String organizationUrl) {
        URI base = organization(organizationUrl);
        Probe discovery = probe(credential, base.resolve("api/data/v9.2/bots?$select=botid&$top=1"));
        Probe components = probe(credential, base.resolve("api/data/v9.2/botcomponents?$select=botcomponentid&$top=1"));
        Probe executions = new Probe(false, 410, "RUNTIME_OUT_OF_SCOPE");
        return new PermissionTest(discovery, components, executions);
    }

    private Probe probe(TokenCredential credential, URI uri) {
        try { list(credential, uri); return new Probe(true, 200, "READY"); }
        catch (DataverseException error) { return new Probe(false, error.status(), "UNAVAILABLE"); }
    }

    private List<JsonNode> list(TokenCredential credential, URI initial) {
        List<JsonNode> values = new ArrayList<>(); Set<URI> visited = new LinkedHashSet<>(); URI next = initial;
        for (int page = 0; next != null; page++) {
            if (page >= maxPages || !visited.add(next)) throw new DataverseException(429, "Dataverse page budget exceeded");
            validate(next, initial);
            JsonNode response = get(credential, next);
            if (response.path("value").isArray()) response.path("value").forEach(values::add);
            String link = text(response, "@odata.nextLink"); next = link == null ? null : URI.create(link);
        }
        return values;
    }

    private JsonNode get(TokenCredential credential, URI uri) {
        DataverseException lastFailure = null;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                AccessToken token = credential.getToken(new TokenRequestContext().addScopes(uri.getScheme() + "://" + uri.getHost() + "/.default")).block(Duration.ofSeconds(20));
                if (token == null || token.getToken() == null || token.getToken().isBlank()) throw new DataverseException(401, "Dataverse token unavailable");
                providerCalls.increment();
                var response = http.sendString(HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(30))
                        .header("Authorization", "Bearer " + token.getToken()).header("Accept", "application/json").GET().build(), MAX_BODY_CHARS);
                if (response.statusCode() < 200 || response.statusCode() >= 300) throw new DataverseException(response.statusCode(), "Dataverse metadata request failed");
                if (response.body().length() > MAX_BODY_CHARS) throw new DataverseException(413, "Dataverse response budget exceeded");
                return json.readTree(response.body());
            } catch (DataverseException error) {
                lastFailure = error;
            } catch (Exception error) {
                lastFailure = new DataverseException(502, "Dataverse metadata request failed");
            }
            if (lastFailure == null || !retryable(lastFailure.status()) || attempt == maxAttempts) break;
            delay(attempt);
        }
        throw lastFailure == null ? new DataverseException(502, "Dataverse metadata request failed") : lastFailure;
    }
    private static boolean retryable(int status) { return status == 429 || status >= 500; }
    private void delay(int attempt) {
        try { Thread.sleep(Math.min(5_000L, retryBackoffMs * (1L << Math.min(10, attempt - 1)))); }
        catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); throw new DataverseException(502, "Dataverse retry was interrupted"); }
    }
    private static URI organization(String value) {
        URI uri = URI.create(value); String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null
                || !(host.endsWith(".dynamics.com") || host.endsWith(".crm.dynamics.com"))) throw new DataverseException(400, "Dataverse URL is not allowlisted");
        return uri.resolve("/");
    }
    private static void validate(URI uri, URI base) {
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase();
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null || !host.equals(base.getHost())
                || !(host.endsWith(".dynamics.com") || host.endsWith(".crm.dynamics.com")) || !uri.getPath().startsWith("/api/data/v9.2/"))
            throw new DataverseException(400, "Dataverse URL is not allowlisted");
    }
    private static String text(JsonNode node, String field) { JsonNode value = node.path(field); return value.isTextual() || value.isNumber() ? value.asText() : null; }
    private static Instant instant(JsonNode node, String field) { try { String value = text(node, field); return value == null ? null : Instant.parse(value); } catch (RuntimeException ignored) { return null; } }
    private static boolean known(String kind) { try { int value = Integer.parseInt(kind); return value >= 0 && value <= 19; } catch (RuntimeException ignored) { return false; } }
    private static String componentType(String code) {
        return switch (code == null ? "" : code) {
            case "0" -> "TOPIC"; case "1" -> "SKILL"; case "2" -> "BOT_VARIABLE";
            case "3" -> "BOT_ENTITY"; case "4" -> "DIALOG"; case "5" -> "TRIGGER";
            case "6" -> "LANGUAGE_UNDERSTANDING"; case "7" -> "LANGUAGE_GENERATION";
            case "8" -> "DIALOG_SCHEMA"; case "9" -> "TOPIC_V2"; case "10" -> "BOT_TRANSLATIONS_V2";
            case "11" -> "BOT_ENTITY_V2"; case "12" -> "BOT_VARIABLE_V2"; case "13" -> "SKILL_V2";
            case "14" -> "BOT_FILE_ATTACHMENT"; case "15" -> "CUSTOM_GPT"; case "16" -> "KNOWLEDGE_SOURCE";
            case "17" -> "EXTERNAL_TRIGGER"; case "18" -> "COPILOT_SETTINGS"; case "19" -> "TEST_CASE";
            default -> "UNKNOWN";
        };
    }
    private static ComponentCategory category(String code) {
        if (Set.of("0", "7", "9", "15").contains(code)) return ComponentCategory.PROMPT;
        if (Set.of("1", "5", "13", "17").contains(code)) return ComponentCategory.TOOL;
        return ComponentCategory.COMPONENT;
    }
    public record Bot(String id, String name, String state, String version) { }
    public record Component(String id, String name, String kind, String version, String botId, boolean recognized,
                            ComponentCategory category, AiSecurityDigestService.Digest digest) { }
    public enum ComponentCategory { PROMPT, TOOL, COMPONENT }
    public record CoverageGap(String scope, int status, String message) { }
    public record Discovery(List<Bot> bots, List<Component> components, List<CoverageGap> coverageGaps) { }
    public record Execution(String id, String botId, Instant occurredAt, String status) { }
    public record Probe(boolean ready, int status, String state) { }
    public record PermissionTest(Probe bots, Probe components, Probe executions) { }
    private static final class DataverseException extends RuntimeException { private final int status; DataverseException(int status, String message) { super(message); this.status = status; } int status() { return status; } }
}
