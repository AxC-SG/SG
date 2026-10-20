package com.prototype.vulnwatch.aisecurity.azure;

import com.azure.core.credential.AccessToken;
import com.azure.core.credential.TokenCredential;
import com.azure.core.credential.TokenRequestContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiGridProviderCallCounter;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityDigestService;
import com.prototype.vulnwatch.domain.Tenant;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ThreadLocalRandom;
import org.springframework.stereotype.Component;

@Component
public class AzureAiManagementClient {

    private static final String MANAGEMENT_HOST = "management.azure.com";
    private static final String GRAPH_HOST = "graph.microsoft.com";
    private static final String MANAGEMENT_SCOPE = "https://management.azure.com/.default";
    private static final String GRAPH_SCOPE = "https://graph.microsoft.com/.default";
    private static final String SEARCH_SCOPE = "https://search.azure.com/.default";
    private static final String FOUNDRY_SCOPE = "https://ai.azure.com/.default";
    private static final int MAX_PAGES = 100;
    private static final int MAX_BODY_CHARS = 4_000_000;
    private static final int MAX_ATTEMPTS = 3;
    private static final Duration MAX_RETRY_DELAY = Duration.ofSeconds(5);

    private final com.prototype.vulnwatch.client.http.CheckedHttpTransport http;
    private final ObjectMapper objectMapper;
    private final AzurePolicyPermissionMatrix permissionMatrix;
    private final AiGridProviderCallCounter providerCalls;
    private final AiSecurityDigestService digests;

    @org.springframework.beans.factory.annotation.Autowired
    public AzureAiManagementClient(
            ObjectMapper objectMapper,
            AzurePolicyPermissionMatrix permissionMatrix,
            AiGridProviderCallCounter providerCalls,
            AiSecurityDigestService digests
    ) {
        this.objectMapper = objectMapper;
        this.permissionMatrix = permissionMatrix;
        this.providerCalls = providerCalls;
        this.digests = digests;
        this.http = new com.prototype.vulnwatch.client.http.CheckedHttpTransport();
    }

    AzureAiManagementClient(ObjectMapper objectMapper, AzurePolicyPermissionMatrix permissionMatrix) {
        this(objectMapper, permissionMatrix, new AiGridProviderCallCounter(), new AiSecurityDigestService("0123456789abcdef0123456789abcdef", "test", "", ""));
    }

    public DiscoverySnapshot discover(TokenCredential credential, String subscriptionId) {
        return discover(credential, subscriptionId, AiSecurityAzureConnectorService.RESOURCE_FAMILIES, false);
    }

    public DiscoverySnapshot discover(
            TokenCredential credential,
            String subscriptionId,
            Set<String> requestedFamilies,
            boolean previewAgentsEnabled
    ) {
        return discover(credential, subscriptionId, requestedFamilies, previewAgentsEnabled, null);
    }

    public DiscoverySnapshot discover(TokenCredential credential, String subscriptionId, Set<String> requestedFamilies,
                                      boolean previewAgentsEnabled, Tenant tenant) {
        Set<String> requested = requestedFamilies == null ? Set.of() : requestedFamilies.stream()
                .filter(family -> !Set.of("AZURE_ML_JOBS", "AZURE_ML_PIPELINES").contains(family))
                .collect(java.util.stream.Collectors.toUnmodifiableSet());
        Map<String, List<AzureResource>> resources = new LinkedHashMap<>();
        Map<String, AzureApiFailure> failures = new LinkedHashMap<>();
        for (String family : AiSecurityAzureConnectorService.RESOURCE_FAMILIES) {
            resources.put(family, new ArrayList<>());
        }

        List<AzureResource> subscriptionResources;
        try {
            String url = "https://" + MANAGEMENT_HOST + "/subscriptions/"
                    + encode(subscriptionId) + "/resources?api-version=2021-04-01";
            subscriptionResources = list(credential, url).stream()
                    .map(node -> resource(node, subscriptionId))
                    .filter(resource -> resource.id() != null && resource.type() != null)
                    .toList();
        } catch (AzureApiException exception) {
            AzureApiFailure failure = exception.failure();
            AiSecurityAzureConnectorService.RESOURCE_FAMILIES.forEach(family -> failures.put(family, failure));
            return new DiscoverySnapshot(resources, failures);
        }

        for (AzureResource resource : subscriptionResources) {
            String family = family(resource.type());
            if (family != null && neededBaseFamily(family, requested)) {
                resources.get(family).add(enrich(credential, resource, failures, family));
            }
        }

        collectRequestedChild(credential, requested, resources.get("AZURE_AI_ACCOUNTS"),
                "projects", "AZURE_FOUNDRY_PROJECTS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_FOUNDRY_PROJECTS"),
                "connections", "AZURE_FOUNDRY_CONNECTIONS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_AI_ACCOUNTS"),
                "deployments", "AZURE_FOUNDRY_DEPLOYMENTS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_AI_ACCOUNTS"),
                "raiPolicies", "AZURE_RAI_POLICIES", resources, failures);
        if (previewAgentsEnabled && requested.contains("AZURE_FOUNDRY_AGENT_ROUTES")) {
            collectChildren(credential, resources.get("AZURE_FOUNDRY_PROJECTS"), "applications",
                    "AZURE_FOUNDRY_AGENT_APPLICATIONS", resources, failures);
            collectChildren(credential, resources.get("AZURE_FOUNDRY_AGENT_APPLICATIONS"), "agentdeployments",
                    "AZURE_FOUNDRY_AGENT_DEPLOYMENTS", resources, failures);
            if (failures.containsKey("AZURE_FOUNDRY_AGENT_APPLICATIONS")) {
                failures.putIfAbsent("AZURE_FOUNDRY_AGENT_DEPLOYMENTS", failures.get("AZURE_FOUNDRY_AGENT_APPLICATIONS"));
            }
        }
        if (previewAgentsEnabled && requested.stream().anyMatch(family -> family.startsWith("AZURE_FOUNDRY_AGENT"))) {
            collectFoundryAgents(credential, resources.get("AZURE_FOUNDRY_PROJECTS"), resources, failures, tenant);
        }
        if (requested.stream().anyMatch(family -> family.startsWith("AZURE_CLASSIC_FOUNDRY_AGENT"))) {
            collectClassicFoundryAgents(credential, resources.get("AZURE_FOUNDRY_PROJECTS"), resources, failures, tenant);
        }
        collectRequestedChild(credential, requested, resources.get("AZURE_ML_WORKSPACES"),
                "models", "AZURE_ML_MODELS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_ML_WORKSPACES"),
                "onlineEndpoints", "AZURE_ML_ENDPOINTS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_ML_ENDPOINTS"),
                "deployments", "AZURE_ML_DEPLOYMENTS", resources, failures);
        collectRequestedChild(credential, requested, resources.get("AZURE_ML_WORKSPACES"),
                "computes", "AZURE_ML_COMPUTE", resources, failures);

        if (requested.stream().anyMatch(AzureAiManagementClient::isSearchDefinitionFamily)) {
            collectSearchDefinitions(credential, requested, resources.get("AZURE_SEARCH_SERVICES"), resources, failures);
        }
        collectRequestedChild(credential, requested, resources.get("AZURE_BOT_SERVICES"),
                "channels", "AZURE_BOT_CHANNELS", resources, failures);

        if (requested.contains("AZURE_DIAGNOSTIC_SETTINGS")) {
            collectDiagnostics(credential, subscriptionResources, resources, failures);
        }
        if (requested.contains("AZURE_RBAC_GLOBAL")) {
            collectSubscriptionRbac(credential, subscriptionId, resources, failures);
        }
        if (requested.contains("AZURE_BOT_IDENTITIES")) {
            collectAgentIdentities(credential, subscriptionId, resources, failures);
        }
        return new DiscoverySnapshot(resources, failures);
    }

    private void collectAgentIdentities(
            TokenCredential credential,
            String subscriptionId,
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
        try {
            for (JsonNode node : list(credential,
                    "https://" + GRAPH_HOST + "/v1.0/servicePrincipals/microsoft.graph.agentIdentity")) {
                String principalId = text(node.path("id"));
                if (principalId == null) continue;
                String id = "azure-identity:" + principalId.toLowerCase(Locale.ROOT);
                resources.get("AZURE_BOT_IDENTITIES").add(new AzureResource(
                        id, id, text(node.path("displayName")), "Microsoft.Entra/agentIdentities",
                        "AgentIdentity", "GLOBAL", subscriptionId, null,
                        objectMapper.createObjectNode(), node, objectMapper.createObjectNode(), Map.of(), null));
            }
        } catch (AzureApiException exception) {
            failures.putIfAbsent("AZURE_BOT_IDENTITIES", exception.failure());
        }
    }

    /**
     * Azure AI Search definitions are read through the service data plane.  This deliberately
     * uses only collection GET endpoints: it never calls documents, query, key, or index
     * mutation endpoints.
     */
    private void collectSearchDefinitions(
            TokenCredential credential,
            Set<String> requested,
            List<AzureResource> services,
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
        if (services == null) return;
        Map<String, String> paths = Map.of(
                "AZURE_SEARCH_INDEXES", "indexes",
                "AZURE_SEARCH_SKILLSETS", "skillsets",
                "AZURE_SEARCH_INDEXERS", "indexers",
                "AZURE_SEARCH_DATA_SOURCES", "datasources",
                "AZURE_SEARCH_KNOWLEDGE_BASES", "knowledgebases",
                "AZURE_SEARCH_KNOWLEDGE_SOURCES", "knowledgesources");
        for (AzureResource service : services) {
            String endpoint = text(service.properties().path("endpoint"));
            if (endpoint == null) endpoint = text(service.properties().path("hostName"));
            if (endpoint == null) endpoint = service.name() == null ? null : service.name() + ".search.windows.net";
            if (endpoint == null) continue;
            String base = endpoint.startsWith("https://") ? endpoint : "https://" + endpoint;
            for (Map.Entry<String, String> entry : paths.entrySet()) {
                String family = entry.getKey();
                if (!requested.contains(family) || failures.containsKey(family)) continue;
                try {
                    String apiVersion = family.startsWith("AZURE_SEARCH_KNOWLEDGE_") ? "2026-04-01" : "2024-07-01";
                    for (JsonNode node : searchList(credential, base + "/" + entry.getValue() + "?api-version=" + apiVersion)) {
                        AzureResource definition = searchResource(node, service, family).withParentId(service.id());
                        resources.get(family).add(definition);
                    }
                } catch (AzureApiException exception) {
                    failures.put(family, exception.failure());
                }
            }
        }
    }

    private static boolean isSearchDefinitionFamily(String family) {
        return "AZURE_SEARCH_INDEXES".equals(family) || "AZURE_SEARCH_SKILLSETS".equals(family)
                || "AZURE_SEARCH_INDEXERS".equals(family) || "AZURE_SEARCH_DATA_SOURCES".equals(family)
                || "AZURE_SEARCH_KNOWLEDGE_BASES".equals(family) || "AZURE_SEARCH_KNOWLEDGE_SOURCES".equals(family);
    }

    /** Uses only GET /agents and published definitions; it never invokes agents, models, or tools. */
    private void collectFoundryAgents(
            TokenCredential credential, List<AzureResource> projects,
            Map<String, List<AzureResource>> resources, Map<String, AzureApiFailure> failures, Tenant tenant
    ) {
        if (projects == null || failures.containsKey("AZURE_FOUNDRY_AGENTS")) return;
        for (AzureResource project : projects) {
            String endpoint = foundryProjectEndpoint(project);
            if (endpoint == null) continue;
            try {
                for (JsonNode agent : foundryList(credential, endpoint + "/agents?api-version=v1")) {
                    AzureResource agentResource = foundryAgentResource(agent, project, tenant);
                    resources.get("AZURE_FOUNDRY_AGENTS").add(agentResource);
                    AzureResource route = agent.path("agent_endpoint").isObject()
                            ? foundryRouteResource(agent, agentResource)
                            : legacyFoundryRouteResource(agentResource, resources.get("AZURE_FOUNDRY_AGENT_APPLICATIONS"),
                                    resources.get("AZURE_FOUNDRY_AGENT_DEPLOYMENTS"), failures);
                    resources.get("AZURE_FOUNDRY_AGENT_ROUTES").add(route);
                    String name = text(agent.path("name"));
                    if (name == null) continue;
                    try {
                        for (JsonNode version : foundryList(credential,
                                endpoint + "/agents/" + encode(name) + "/versions?api-version=v1")) {
                            resources.get("AZURE_FOUNDRY_AGENT_VERSIONS").add(
                                    foundryVersionResource(version, agentResource, tenant));
                        }
                    } catch (AzureApiException exception) {
                        // A single agent can be unavailable or use an unsupported version API;
                        // retain all other agents and make the enclosing inventory scope partial.
                        failures.putIfAbsent("AZURE_FOUNDRY_AGENT_VERSIONS", exception.failure());
                        failures.putIfAbsent("AZURE_FOUNDRY_AGENT_ROUTES", exception.failure());
                    }
                }
            } catch (AzureApiException exception) {
                failures.putIfAbsent("AZURE_FOUNDRY_AGENTS", exception.failure());
                failures.putIfAbsent("AZURE_FOUNDRY_AGENT_ROUTES", exception.failure());
            }
        }
    }

    /**
     * Classic Foundry exposes Assistants API definitions but no immutable definition-version
     * history. We retain its current definition as a version node and report that limitation as
     * an explicit coverage gap instead of inventing history.
     */
    private void collectClassicFoundryAgents(
            TokenCredential credential, List<AzureResource> projects,
            Map<String, List<AzureResource>> resources, Map<String, AzureApiFailure> failures, Tenant tenant
    ) {
        if (projects == null || failures.containsKey("AZURE_CLASSIC_FOUNDRY_AGENTS")) return;
        boolean observed = false;
        for (AzureResource project : projects) {
            String endpoint = foundryProjectEndpoint(project);
            if (endpoint == null) continue;
            try {
                for (JsonNode assistant : foundryList(credential, endpoint + "/assistants?api-version=v1")) {
                    AzureResource agent = classicAssistantResource(assistant, project, tenant);
                    resources.get("AZURE_CLASSIC_FOUNDRY_AGENTS").add(agent);
                    resources.get("AZURE_CLASSIC_FOUNDRY_AGENT_VERSIONS").add(
                            classicAssistantVersionResource(assistant, agent, tenant));
                    observed = true;
                }
            } catch (AzureApiException exception) {
                failures.putIfAbsent("AZURE_CLASSIC_FOUNDRY_AGENTS", exception.failure());
            }
        }
        if (observed) {
            failures.putIfAbsent("AZURE_CLASSIC_FOUNDRY_AGENTS", new AzureApiFailure(
                    "COVERAGE_GAP",
                    "Classic Foundry exposes only the current assistant definition, and its runs API is thread-scoped without project-wide thread enumeration; historical versions and exhaustive runtime collection require external snapshots or log export",
                    false,
                    200));
        }
    }

    private AzureResource classicAssistantResource(JsonNode assistant, AzureResource project, Tenant tenant) {
        String providerId = text(assistant.path("id"));
        if (providerId == null) providerId = text(assistant.path("name"));
        if (providerId == null) providerId = "unnamed";
        String name = text(assistant.path("name"));
        String id = project.id() + "/assistants/" + encode(providerId);
        var properties = safeClassicDefinition(assistant, tenant);
        properties.put("agentVersion", classicVersion(assistant));
        return new AzureResource(id.toLowerCase(Locale.ROOT), id, name,
                "Microsoft.Foundry/projects/assistants", "ClassicFoundryAssistant", project.location(),
                project.subscriptionId(), project.resourceGroup(), objectMapper.createObjectNode(), properties,
                objectMapper.createObjectNode(), Map.of(), project.id());
    }

    private AzureResource classicAssistantVersionResource(JsonNode assistant, AzureResource agent, Tenant tenant) {
        String version = classicVersion(assistant);
        String id = agent.id() + "/versions/" + encode(version);
        var properties = safeClassicDefinition(assistant, tenant);
        properties.put("agentVersion", version);
        return new AzureResource(id.toLowerCase(Locale.ROOT), id, agent.name() + " current",
                "Microsoft.Foundry/projects/assistants/versions", "ClassicFoundryAssistantVersion", agent.location(),
                agent.subscriptionId(), agent.resourceGroup(), objectMapper.createObjectNode(), properties,
                objectMapper.createObjectNode(), Map.of(), agent.id());
    }

    private com.fasterxml.jackson.databind.node.ObjectNode safeClassicDefinition(JsonNode assistant, Tenant tenant) {
        var properties = objectMapper.createObjectNode();
        String model = text(assistant.path("model"));
        if (model != null) properties.put("modelDeploymentName", model);
        addPromptDigest(properties, assistant, tenant);
        properties.set("tools", safeTools(assistant.path("tools"), tenant));
        return properties;
    }

    private static String classicVersion(JsonNode assistant) {
        JsonNode updated = assistant.path("updated_at");
        if (updated.isIntegralNumber()) return Long.toString(updated.asLong());
        JsonNode created = assistant.path("created_at");
        return created.isIntegralNumber() ? Long.toString(created.asLong()) : "current";
    }

    private String foundryProjectEndpoint(AzureResource project) {
        if (project.id() == null) return null;
        String lowered = project.id().toLowerCase(Locale.ROOT);
        int accountStart = lowered.indexOf("/accounts/");
        int projectStart = lowered.indexOf("/projects/");
        if (accountStart < 0 || projectStart <= accountStart) return null;
        String account = project.id().substring(accountStart + "/accounts/".length(), projectStart);
        String projectName = project.id().substring(projectStart + "/projects/".length());
        if (account.isBlank() || projectName.isBlank() || projectName.contains("/")) return null;
        return "https://" + account + ".services.ai.azure.com/api/projects/" + encode(projectName);
    }

    private List<JsonNode> foundryList(TokenCredential credential, String url) {
        List<JsonNode> values = new ArrayList<>();
        Set<String> visited = new LinkedHashSet<>();
        String next = url;
        for (int page = 0; next != null; page++) {
            if (page >= MAX_PAGES || !visited.add(next)) {
                throw new AzureApiException(new AzureApiFailure(
                        "PAGE_BUDGET_EXCEEDED", "Azure Foundry pagination limit was exceeded", false, 0));
            }
            JsonNode response = get(credential, next);
            JsonNode data = response.path("data");
            if (data.isArray()) data.forEach(values::add);
            else throw new AzureApiException(new AzureApiFailure("INVALID_PROVIDER_RESPONSE",
                    "Azure Foundry collection response did not contain an agent list", false, 0));
            next = nextFoundryPageUrl(url, response);
            if (next != null) validateFoundryUri(URI.create(next));
        }
        return values;
    }

    String nextFoundryPageUrl(String initialUrl, JsonNode response) {
        if (!response.path("has_more").asBoolean(false)) return null;
        String cursor = text(response.path("last_id"));
        if (cursor == null) {
            throw new AzureApiException(new AzureApiFailure(
                    "INVALID_CONFIGURATION", "Azure Foundry pagination cursor was missing", false, 0));
        }
        return initialUrl + (initialUrl.contains("?") ? "&" : "?") + "after=" + encode(cursor);
    }

    private AzureResource foundryAgentResource(JsonNode agent, AzureResource project, Tenant tenant) {
        String name = text(agent.path("name"));
        String id = project.id() + "/agents/" + (name == null ? "unnamed" : name);
        com.fasterxml.jackson.databind.node.ObjectNode properties = objectMapper.createObjectNode();
        JsonNode definition = agent.path("versions").path("latest").path("definition");
        // Do not carry the provider definition forward. It may contain instructions, tool schemas,
        // headers, or other content. Keep only fields needed for inventory relationships.
        String model = text(definition.path("model"));
        if (model != null) properties.put("modelDeploymentName", model);
        String version = text(agent.path("versions").path("latest").path("version"));
        if (version != null) properties.put("agentVersion", version);
        addPromptDigest(properties, definition, tenant);
        properties.set("tools", safeTools(definition.path("tools"), tenant));
        return new AzureResource(id.toLowerCase(Locale.ROOT), id, name,
                "Microsoft.Foundry/projects/agents", "FoundryPromptAgent", project.location(),
                project.subscriptionId(), project.resourceGroup(), objectMapper.createObjectNode(), properties,
                objectMapper.createObjectNode(), Map.of(), project.id());
    }

    AzureResource foundryRouteResource(JsonNode agent, AzureResource parent) {
        var properties = objectMapper.createObjectNode();
        var versions = objectMapper.createArrayNode();
        JsonNode endpoint = agent.path("agent_endpoint");
        String gap = null;
        String status = "READY";
        if (!endpoint.isObject()) gap = "UNSUPPORTED_API";
        else if (!endpoint.path("protocol_configuration").isObject()
                || endpoint.path("protocol_configuration").isEmpty()) gap = "AMBIGUOUS_ROUTE_STATE";
        JsonNode rules = endpoint.path("version_selector").path("version_selection_rules");
        if (gap == null && endpoint.hasNonNull("version_selector") && (!rules.isArray() || rules.isEmpty())) {
            gap = "AMBIGUOUS_ROUTE_STATE";
        }
        if (gap == null && rules.isArray() && !rules.isEmpty()) {
            double total = 0;
            for (JsonNode rule : rules) {
                if (!"FixedRatio".equals(rule.path("type").asText())
                        || !rule.path("traffic_percentage").isNumber()) { gap = "AMBIGUOUS_ROUTE_STATE"; break; }
                double traffic = rule.path("traffic_percentage").asDouble();
                if (traffic < 0 || traffic > 100) { gap = "AMBIGUOUS_ROUTE_STATE"; break; }
                total += traffic;
                if (traffic > 0) {
                    String version = text(rule.path("agent_version"));
                    if (version == null) { gap = "UNRESOLVED_VERSION"; break; }
                    versions.add(version);
                }
            }
            if (gap == null && total == 0) status = "ZERO_TRAFFIC_ALLOCATION";
            else if (gap == null && Math.abs(total - 100) > 0.0001) gap = "AMBIGUOUS_ROUTE_STATE";
        } else if (gap == null) {
            // Provider default routes latest, but an exact observed target is still required.
            String version = text(agent.path("versions").path("latest").path("version"));
            if (version == null) gap = "UNRESOLVED_VERSION";
            else versions.add(version);
        }
        JsonNode definition = agent.path("versions").path("latest").path("definition");
        String definitionType = definition.path("kind").asText(definition.path("type").asText());
        if (gap == null && !definitionType.isEmpty() && !definitionType.equals("prompt")) {
            gap = "AMBIGUOUS_ROUTE_STATE";
        }
        properties.put("status", gap == null ? status : "UNKNOWN");
        properties.put("deploymentEvidenceReason", gap == null ? "" : gap);
        properties.set("routedVersions", versions);
        String id = parent.id() + "/endpoint";
        return new AzureResource(id, id, parent.name() + " endpoint", "Microsoft.Foundry/projects/agents/endpoint",
                "FoundryAgentEndpoint", parent.location(), parent.subscriptionId(), parent.resourceGroup(),
                objectMapper.createObjectNode(), properties, objectMapper.createObjectNode(), Map.of(), parent.id());
    }

    AzureResource legacyFoundryRouteResource(AzureResource agent, List<AzureResource> applications,
                                             List<AzureResource> deployments, Map<String, AzureApiFailure> failures) {
        Set<String> gaps = new java.util.TreeSet<>();
        for (String family : List.of("AZURE_FOUNDRY_AGENT_APPLICATIONS", "AZURE_FOUNDRY_AGENT_DEPLOYMENTS")) {
            AzureApiFailure failure = failures.get(family);
            if (failure != null) gaps.add(failure.statusCode() == 403 ? "PERMISSION_DENIED"
                    : failure.code().contains("BUDGET") ? "BUDGET_EXHAUSTED"
                    : failure.statusCode() == 404 ? "UNSUPPORTED_API" : "PROVIDER_ERROR");
        }
        var versions = objectMapper.createArrayNode();
        boolean zeroTraffic = false;
        int routingMechanisms = 0;
        for (AzureResource app : applications == null ? List.<AzureResource>of() : applications) {
            if (!java.util.Objects.equals(app.parentId(), agent.parentId())) continue;
            boolean related = false;
            for (JsonNode reference : app.properties().path("agents")) {
                related |= agent.name().equals(reference.path("agentName").asText()) || agent.id().equals(reference.path("agentId").asText());
            }
            List<AzureResource> children = (deployments == null ? List.<AzureResource>of() : deployments).stream()
                    .filter(d -> app.id().equals(d.parentId())).toList();
            for (AzureResource deployment : children) {
                for (JsonNode reference : deployment.properties().path("agents")) {
                    related |= agent.name().equals(reference.path("agentName").asText()) || agent.id().equals(reference.path("agentId").asText());
                }
            }
            if (!related) continue;
            routingMechanisms++;
            JsonNode rules = app.properties().path("trafficRoutingPolicy").path("rules");
            if (rules.isArray()) {
                if (!app.properties().path("trafficRoutingPolicy").path("protocol").asText().equals("FixedRatio")) {
                    gaps.add("AMBIGUOUS_ROUTE_STATE"); continue;
                }
                double allocation = 0;
                for (JsonNode rule : rules) {
                    if (!rule.path("trafficPercentage").isNumber() || rule.path("trafficPercentage").asDouble() < 0
                            || rule.path("trafficPercentage").asDouble() > 100) { gaps.add("AMBIGUOUS_ROUTE_STATE"); continue; }
                    allocation += rule.path("trafficPercentage").asDouble();
                    String target = rule.path("deploymentId").asText();
                    AzureResource deployment = children.stream().filter(d -> d.id().equalsIgnoreCase(target)
                            || d.properties().path("deploymentId").asText().equals(target)).findFirst().orElse(null);
                    if (deployment == null) { gaps.add("UNRESOLVED_IDENTITY"); continue; }
                    if (rule.path("trafficPercentage").asDouble() == 0) { zeroTraffic = true; continue; }
                    appendLegacyServingVersions(agent, deployment, versions, gaps);
                }
                if (allocation == 0) zeroTraffic = true;
                else if (Math.abs(allocation - 100) > 0.0001) gaps.add("AMBIGUOUS_ROUTE_STATE");
            } else if (children.size() == 1) {
                // The documented default directs all traffic to the first deployment. With one
                // completely enumerated child, that target is unambiguous.
                appendLegacyServingVersions(agent, children.get(0), versions, gaps);
            } else if (!children.isEmpty()) gaps.add("AMBIGUOUS_ROUTE_STATE");
        }
        String gap = gaps.size() > 1 ? "INCOMPLETE_SCOPE" : gaps.stream().findFirst().orElse("");
        var properties = objectMapper.createObjectNode();
        properties.put("status", !gap.isEmpty() ? "UNKNOWN" : !versions.isEmpty() ? "READY"
                : routingMechanisms > 1 ? "NO_SERVING_ROUTE" : zeroTraffic ? "ZERO_TRAFFIC_ALLOCATION" : "NO_ACTIVE_DEPLOYMENT");
        properties.put("deploymentEvidenceReason", gap);
        properties.set("routedVersions", versions);
        String id = agent.id() + "/legacy-routing";
        return new AzureResource(id,id,agent.name() + " application routing", "Microsoft.Foundry/projects/agents/endpoint",
                "LegacyFoundryApplicationRouting", agent.location(), agent.subscriptionId(), agent.resourceGroup(),
                objectMapper.createObjectNode(), properties, objectMapper.createObjectNode(), Map.of(), agent.id());
    }

    private void appendLegacyServingVersions(AzureResource agent, AzureResource deployment,
            com.fasterxml.jackson.databind.node.ArrayNode versions, Set<String> gaps) {
        String state = deployment.properties().path("state").asText();
        if (Set.of("Stopped", "Deleted", "Failed").contains(state)) return;
        if (!state.equals("Running")) { gaps.add("AMBIGUOUS_ROUTE_STATE"); return; }
        if (!deployment.properties().path("protocols").isArray() || deployment.properties().path("protocols").isEmpty()) {
            gaps.add("AMBIGUOUS_ROUTE_STATE"); return;
        }
        for (JsonNode reference : deployment.properties().path("agents")) {
            if (!agent.name().equals(reference.path("agentName").asText()) && !agent.id().equals(reference.path("agentId").asText())) continue;
            String version = text(reference.path("agentVersion"));
            if (version == null) gaps.add("UNRESOLVED_VERSION"); else versions.add(version);
        }
    }

    private com.fasterxml.jackson.databind.node.ArrayNode safeTools(JsonNode definitions, Tenant tenant) {
        com.fasterxml.jackson.databind.node.ArrayNode tools = objectMapper.createArrayNode();
        if (definitions.isArray()) {
            for (JsonNode tool : definitions) {
                String type = text(tool.path("type"));
                if (type == null) continue;
                var summary = objectMapper.createObjectNode();
                summary.put("type", type);
                // MCP identity is metadata; schemas, headers, arguments, and definitions are omitted.
                copyText(tool, summary, "server_url");
                copyText(tool, summary, "serverUrl");
                copyText(tool, summary, "url");
                copyText(tool, summary, "project_connection_id");
                copyText(tool, summary, "projectConnectionId");
                if (tenant != null) {
                    var digest = digests.digest(tenant, "tool-definition", tool.toString());
                    summary.put("toolDefinitionDigest", digest.value()); summary.put("digestAlgorithm", digest.algorithm()); summary.put("digestKeyVersion", digest.keyVersion());
                }
                tools.add(summary);
            }
        }
        return tools;
    }

    private AzureResource foundryVersionResource(JsonNode version, AzureResource agent, Tenant tenant) {
        String number = text(version.path("version"));
        if (number == null) number = text(version.path("id"));
        if (number == null) number = "unknown";
        String id = agent.id() + "/versions/" + encode(number);
        var properties = objectMapper.createObjectNode();
        JsonNode definition = version.path("definition");
        String model = text(definition.path("model"));
        if (model != null) properties.put("modelDeploymentName", model);
        properties.put("agentVersion", number);
        addPromptDigest(properties, definition, tenant);
        properties.set("tools", safeTools(definition.path("tools"), tenant));
        return new AzureResource(id.toLowerCase(Locale.ROOT), id, agent.name() + " v" + number,
                "Microsoft.Foundry/projects/agents/versions", "FoundryPromptAgentVersion", agent.location(),
                agent.subscriptionId(), agent.resourceGroup(), objectMapper.createObjectNode(), properties,
                objectMapper.createObjectNode(), Map.of(), agent.id());
    }

    private void addPromptDigest(com.fasterxml.jackson.databind.node.ObjectNode properties, JsonNode definition, Tenant tenant) {
        if (tenant == null) return;
        String prompt = text(definition.path("instructions")); if (prompt == null) prompt = text(definition.path("prompt"));
        if (prompt == null) return;
        var digest = digests.digest(tenant, "prompt-definition", prompt);
        properties.put("promptDigest", digest.value()); properties.put("digestAlgorithm", digest.algorithm()); properties.put("digestKeyVersion", digest.keyVersion());
    }

    private void copyText(JsonNode source, com.fasterxml.jackson.databind.node.ObjectNode target, String field) {
        String value = text(source.path(field));
        if (value != null) target.put(field, value);
    }

    private List<JsonNode> searchList(TokenCredential credential, String initialUrl) {
        List<JsonNode> values = new ArrayList<>();
        String next = initialUrl;
        for (int page = 0; next != null; page++) {
            if (page >= MAX_PAGES) throw new AzureApiException(new AzureApiFailure(
                    "PAGE_BUDGET_EXCEEDED", "Azure Search pagination limit was exceeded", false, 0));
            JsonNode response = get(credential, next);
            JsonNode pageValues = response.path("value");
            if (pageValues.isArray()) pageValues.forEach(values::add);
            next = text(response.path("@odata.nextLink"));
            if (next != null) validateSearchUri(URI.create(next));
        }
        return values;
    }

    private AzureResource searchResource(JsonNode node, AzureResource service, String family) {
        String name = text(node.path("name"));
        String id = service.id() + "/" + family.toLowerCase(Locale.ROOT) + "/" + (name == null ? "unnamed" : name);
        return new AzureResource(id.toLowerCase(Locale.ROOT), id, name, family, null, service.location(),
                service.subscriptionId(), service.resourceGroup(), objectMapper.createObjectNode(), node,
                objectMapper.createObjectNode(), Map.of(), null);
    }

    private void collectSubscriptionRbac(
            TokenCredential credential,
            String subscriptionId,
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
        try {
            String path = "/subscriptions/" + encode(subscriptionId)
                    + "/providers/Microsoft.Authorization/roleAssignments";
            for (JsonNode node : list(credential, managementUrl(
                    path, permissionMatrix.family("AZURE_RBAC_GLOBAL").apiVersion()))) {
                resources.get("AZURE_RBAC_GLOBAL").add(resource(node, subscriptionId)
                        .withLocation("GLOBAL"));
            }
        } catch (AzureApiException exception) {
            failures.put("AZURE_RBAC_GLOBAL", exception.failure());
        }
    }

    private boolean neededBaseFamily(String family, Set<String> requested) {
        if (requested.contains(family)) return true;
        if ("AZURE_AI_ACCOUNTS".equals(family)) {
            return requested.stream().anyMatch(value -> value.startsWith("AZURE_FOUNDRY")
                    || value.startsWith("AZURE_CLASSIC_FOUNDRY") || value.startsWith("AZURE_RAI"));
        }
        if ("AZURE_ML_WORKSPACES".equals(family)) {
            return requested.stream().anyMatch(value -> value.startsWith("AZURE_ML"));
        }
        if ("AZURE_BOT_SERVICES".equals(family)) {
            return requested.stream().anyMatch(value -> value.startsWith("AZURE_BOT"));
        }
        return false;
    }

    private void collectRequestedChild(
            TokenCredential credential,
            Set<String> requested,
            List<AzureResource> parents,
            String childPath,
            String family,
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
        if (requested.contains(family)
                || ("AZURE_FOUNDRY_PROJECTS".equals(family)
                        && requested.stream().anyMatch(value -> value.startsWith("AZURE_FOUNDRY_AGENT")
                                || value.startsWith("AZURE_CLASSIC_FOUNDRY_AGENT")))) {
            collectChildren(credential, parents, childPath, family, resources, failures);
        }
    }

    private void collectChildren(
            TokenCredential credential,
            List<AzureResource> parents,
            String childPath,
            String family,
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
        if (parents == null || failures.containsKey(family)) {
            return;
        }
        List<AzureResource> collected = resources.get(family);
        for (AzureResource parent : parents) {
            String childType = parent.type() + "/" + childPath.toLowerCase(Locale.ROOT);
            String version = apiVersion(childType);
            try {
                for (JsonNode node : list(credential, managementUrl(parent.id() + "/" + childPath, version))) {
                    AzureResource child = resource(node, parent.subscriptionId());
                    if (child.location() == null || "GLOBAL".equalsIgnoreCase(child.location())) {
                        child = child.withLocation(parent.location());
                    }
                    collected.add(child.withParentId(parent.id()));
                }
            } catch (AzureApiException exception) {
                failures.put(family, exception.failure());
                return;
            }
        }
    }

    private void partitionPipelineJobs(Map<String, List<AzureResource>> resources) {
        List<AzureResource> jobs = resources.get("AZURE_ML_JOBS");
        List<AzureResource> pipelines = resources.get("AZURE_ML_PIPELINES");
        if (jobs == null || pipelines == null) {
            return;
        }
        List<AzureResource> pipelineJobs = jobs.stream().filter(this::isPipelineJob).toList();
        pipelines.addAll(pipelineJobs);
        jobs.removeAll(pipelineJobs);
    }

    boolean isPipelineJob(AzureResource resource) {
        String jobType = text(resource.properties().path("jobType"));
        String componentId = text(resource.properties().path("componentId"));
        return "PIPELINE".equalsIgnoreCase(jobType)
                || (componentId != null && componentId.toLowerCase(Locale.ROOT).contains("/components/"));
    }

    private void collectDiagnostics(
            TokenCredential credential,
            List<AzureResource> resourcesToInspect,
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
        List<AzureResource> diagnostics = resources.get("AZURE_DIAGNOSTIC_SETTINGS");
        for (AzureResource resource : resourcesToInspect) {
            if (family(resource.type()) == null) {
                continue;
            }
            try {
                String path = resource.id() + "/providers/Microsoft.Insights/diagnosticSettings";
                for (JsonNode node : list(credential, managementUrl(
                        path, permissionMatrix.family("AZURE_DIAGNOSTIC_SETTINGS").apiVersion()))) {
                    AzureResource diagnostic = resource(node, resource.subscriptionId())
                            .withLocation(resource.location())
                            .withParentId(resource.id());
                    diagnostics.add(diagnostic);
                }
            } catch (AzureApiException exception) {
                failures.putIfAbsent("AZURE_DIAGNOSTIC_SETTINGS", exception.failure());
            }
        }
    }

    private AzureResource enrich(
            TokenCredential credential,
            AzureResource resource,
            Map<String, AzureApiFailure> failures,
            String family
    ) {
        try {
            JsonNode node = get(credential, managementUrl(resource.id(), apiVersion(resource.type())));
            return resource(node, resource.subscriptionId());
        } catch (AzureApiException exception) {
            failures.putIfAbsent(family, exception.failure());
            return resource;
        }
    }

    private List<JsonNode> list(TokenCredential credential, String initialUrl) {
        List<JsonNode> values = new ArrayList<>();
        Set<String> visited = new LinkedHashSet<>();
        String next = initialUrl;
        for (int page = 0; next != null; page++) {
            if (page >= MAX_PAGES || !visited.add(next)) {
                throw new AzureApiException(new AzureApiFailure(
                        "PAGE_BUDGET_EXCEEDED", "Azure pagination limit was exceeded", false, 0));
            }
            JsonNode response = get(credential, next);
            JsonNode pageValues = response.path("value");
            if (pageValues.isArray()) {
                pageValues.forEach(values::add);
            } else if (!response.isMissingNode() && !response.isNull()) {
                values.add(response);
            }
            String candidate = text(response.path("nextLink"));
            if (candidate == null) candidate = text(response.path("@odata.nextLink"));
            if (candidate != null) {
                validateAllowedUri(URI.create(candidate));
            }
            next = candidate;
        }
        return values;
    }

    private JsonNode get(TokenCredential credential, String url) {
        URI uri = URI.create(url);
        validateAllowedUri(uri);
        AzureApiException terminal = null;
        for (int attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            HttpHeaders responseHeaders = HttpHeaders.of(Map.of(), (name, value) -> true);
            try {
                HttpRequest request = HttpRequest.newBuilder(uri)
                        .timeout(Duration.ofSeconds(30))
                        .header("Authorization", "Bearer " + bearerToken(credential, uri.getHost()))
                        .header("Accept", "application/json")
                        .GET()
                        .build();
                providerCalls.increment();
                var response = http.sendString(request, MAX_BODY_CHARS);
                responseHeaders = response.headers();
                String body = response.body() == null ? "" : response.body();
                if (body.length() > MAX_BODY_CHARS) {
                    throw new AzureApiException(new AzureApiFailure(
                            "INVALID_CONFIGURATION", "Azure response exceeded the allowed size",
                            false, response.statusCode()));
                }
                if (response.statusCode() < 200 || response.statusCode() >= 300) {
                    throw new AzureApiException(failure(response.statusCode(), body));
                }
                return body.isBlank() ? objectMapper.createObjectNode() : objectMapper.readTree(body);
            } catch (AiGridProviderCallCounter.ProviderCallBudgetExceededException exception) {
                throw new AzureApiException(new AzureApiFailure("PROVIDER_CALL_BUDGET_EXHAUSTED",
                        "Azure metadata collection exhausted its provider call budget", false, 0));
            } catch (AzureApiException exception) {
                terminal = exception;
            } catch (java.net.http.HttpTimeoutException exception) {
                terminal = new AzureApiException(
                        new AzureApiFailure("TIMEOUT", "Azure request timed out", true, 0));
            } catch (InterruptedException exception) {
                Thread.currentThread().interrupt();
                throw new AzureApiException(new AzureApiFailure(
                        "PROVIDER_UNAVAILABLE", "Azure request was interrupted", true, 0));
            } catch (Exception exception) {
                terminal = new AzureApiException(new AzureApiFailure(
                        "PROVIDER_UNAVAILABLE", "Azure request could not be completed", true, 0));
            }
            if (terminal == null || !terminal.failure().retryable() || attempt == MAX_ATTEMPTS) {
                throw terminal;
            }
            sleep(retryDelay(responseHeaders, attempt));
        }
        throw terminal;
    }

    Duration retryDelay(HttpHeaders headers, int attempt) {
        long requestedMillis = headers.firstValue("x-ms-retry-after-ms")
                .map(this::positiveLong)
                .orElseGet(() -> headers.firstValue("Retry-After")
                        .map(this::positiveLong)
                        .map(seconds -> seconds * 1_000L)
                        .orElse(0L));
        long fallbackMillis = 250L * (1L << Math.max(0, attempt - 1))
                + ThreadLocalRandom.current().nextLong(0, 251);
        long delayMillis = requestedMillis > 0 ? requestedMillis : fallbackMillis;
        return Duration.ofMillis(Math.min(delayMillis, MAX_RETRY_DELAY.toMillis()));
    }

    private long positiveLong(String value) {
        try {
            return Math.max(0L, Long.parseLong(value.trim()));
        } catch (RuntimeException exception) {
            return 0L;
        }
    }

    private void sleep(Duration delay) {
        try {
            Thread.sleep(delay.toMillis());
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new AzureApiException(new AzureApiFailure(
                    "PROVIDER_UNAVAILABLE", "Azure retry was interrupted", true, 0));
        }
    }

    private AzureApiFailure failure(int status, String body) {
        String providerCode = null;
        try {
            providerCode = text(objectMapper.readTree(body).path("error").path("code"));
        } catch (Exception ignored) {
            // The sanitized status-based code remains authoritative.
        }
        if (status == 401) {
            return new AzureApiFailure("AZURE_AUTHENTICATION_FAILED", "Azure authentication failed", false, status);
        }
        if (status == 403) {
            return new AzureApiFailure("ACCESS_DENIED", "Azure permission is missing", false, status);
        }
        if (status == 404 && "MissingSubscriptionRegistration".equalsIgnoreCase(providerCode)) {
            return new AzureApiFailure(
                    "RESOURCE_PROVIDER_NOT_REGISTERED", "Azure resource provider is not registered", false, status);
        }
        if (status == 429) {
            return new AzureApiFailure("THROTTLED", "Azure temporarily throttled discovery", true, status);
        }
        return new AzureApiFailure("PROVIDER_UNAVAILABLE", "Azure API request failed", status >= 500, status);
    }

    private AzureResource resource(JsonNode node, String subscriptionId) {
        String id = text(node.path("id"));
        String type = text(node.path("type"));
        String location = text(node.path("location"));
        return new AzureResource(
                canonicalArmId(id),
                id,
                text(node.path("name")),
                type,
                text(node.path("kind")),
                location == null ? "GLOBAL" : location.toLowerCase(Locale.ROOT),
                subscriptionId,
                resourceGroup(id),
                node.path("identity"),
                node.path("properties"),
                node.path("sku"),
                stringMap(node.path("tags")),
                null);
    }

    String family(String type) {
        if (type == null) return null;
        String normalized = type.toLowerCase(Locale.ROOT);
        if (normalized.equals("microsoft.cognitiveservices/accounts")) return "AZURE_AI_ACCOUNTS";
        if (normalized.equals("microsoft.cognitiveservices/accounts/projects")) return "AZURE_FOUNDRY_PROJECTS";
        if (normalized.equals("microsoft.cognitiveservices/accounts/deployments")) return "AZURE_FOUNDRY_DEPLOYMENTS";
        if (normalized.equals("microsoft.cognitiveservices/accounts/raipolicies")) return "AZURE_RAI_POLICIES";
        if (normalized.equals("microsoft.cognitiveservices/accounts/projects/connections")) return "AZURE_FOUNDRY_CONNECTIONS";
        if (normalized.equals("microsoft.storage/storageaccounts")) return "AZURE_STORAGE_ACCOUNTS";
        if (normalized.equals("microsoft.fabric/capacities")) return "AZURE_FABRIC_CAPACITIES";
        if (normalized.contains("/agentdeployments")) return "AZURE_FOUNDRY_AGENT_DEPLOYMENTS";
        if (normalized.equals("microsoft.cognitiveservices/accounts/projects/applications")) return "AZURE_FOUNDRY_AGENT_APPLICATIONS";
        if (normalized.equals("microsoft.foundry/projects/agents")) return "AZURE_FOUNDRY_AGENTS";
        if (normalized.equals("microsoft.machinelearningservices/workspaces")) return "AZURE_ML_WORKSPACES";
        if (normalized.contains("/models")) return "AZURE_ML_MODELS";
        if (normalized.contains("/onlineendpoints/") && normalized.endsWith("/deployments")) {
            return "AZURE_ML_DEPLOYMENTS";
        }
        if (normalized.contains("/onlineendpoints")) return "AZURE_ML_ENDPOINTS";
        if (normalized.contains("/computes")) return "AZURE_ML_COMPUTE";
        if (normalized.contains("/jobs")) return "AZURE_ML_JOBS";
        if (normalized.equals("microsoft.search/searchservices")) return "AZURE_SEARCH_SERVICES";
        if (normalized.equals("microsoft.botservice/botservices")) return "AZURE_BOT_SERVICES";
        if (normalized.endsWith("/channels")) return "AZURE_BOT_CHANNELS";
        if (normalized.equals("microsoft.authorization/roleassignments")) return "AZURE_RBAC_GLOBAL";
        return null;
    }

    private String apiVersion(String type) {
        String resourceFamily = family(type);
        return resourceFamily == null
                ? "2021-04-01"
                : permissionMatrix.family(resourceFamily).apiVersion();
    }

    private String managementUrl(String path, String apiVersion) {
        return "https://" + MANAGEMENT_HOST + path + "?api-version=" + encode(apiVersion);
    }

    void validateManagementUri(URI uri) {
        if (!"https".equalsIgnoreCase(uri.getScheme())
                || uri.getHost() == null
                || !MANAGEMENT_HOST.equalsIgnoreCase(uri.getHost())
                || uri.getUserInfo() != null) {
            throw new AzureApiException(new AzureApiFailure(
                    "INVALID_CONFIGURATION", "Azure continuation host is not allowed", false, 0));
        }
    }

    private void validateAllowedUri(URI uri) {
        if (MANAGEMENT_HOST.equalsIgnoreCase(uri.getHost())) {
            validateManagementUri(uri);
        } else if (GRAPH_HOST.equalsIgnoreCase(uri.getHost())) {
            validateGraphUri(uri);
        } else if (isFoundryHost(uri.getHost())) {
            validateFoundryUri(uri);
        } else {
            validateSearchUri(uri);
        }
    }

    void validateGraphUri(URI uri) {
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null
                || !GRAPH_HOST.equalsIgnoreCase(uri.getHost())
                || !"/v1.0/servicePrincipals/microsoft.graph.agentIdentity".equals(uri.getPath())) {
            throw new AzureApiException(new AzureApiFailure(
                    "INVALID_CONFIGURATION", "Microsoft Graph continuation URL is not allowed", false, 0));
        }
    }

    void validateSearchUri(URI uri) {
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null
                || !(host.endsWith(".search.windows.net") || host.endsWith(".search.azure.com"))) {
            throw new AzureApiException(new AzureApiFailure(
                    "INVALID_CONFIGURATION", "Azure Search endpoint is not allowed", false, 0));
        }
    }

    void validateFoundryUri(URI uri) {
        if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getUserInfo() != null || !isFoundryHost(uri.getHost())) {
            throw new AzureApiException(new AzureApiFailure(
                    "INVALID_CONFIGURATION", "Azure Foundry endpoint is not allowed", false, 0));
        }
    }

    private boolean isFoundryHost(String host) {
        return host != null && host.toLowerCase(Locale.ROOT).endsWith(".services.ai.azure.com");
    }

    private String bearerToken(TokenCredential credential, String host) {
        String scope = GRAPH_HOST.equalsIgnoreCase(host) ? GRAPH_SCOPE
                : host != null && (host.endsWith(".search.windows.net") || host.endsWith(".search.azure.com"))
                ? SEARCH_SCOPE : isFoundryHost(host) ? FOUNDRY_SCOPE : MANAGEMENT_SCOPE;
        AccessToken token = credential.getToken(new TokenRequestContext().addScopes(scope))
                .block(Duration.ofSeconds(30));
        if (token == null || token.getToken() == null || token.getToken().isBlank()) {
            throw new AzureApiException(new AzureApiFailure(
                    "AZURE_AUTHENTICATION_FAILED", "Unable to acquire Azure token", false, 0));
        }
        return token.getToken();
    }

    private Map<String, String> stringMap(JsonNode node) {
        Map<String, String> values = new LinkedHashMap<>();
        if (node != null && node.isObject()) {
            node.fields().forEachRemaining(entry -> values.put(entry.getKey(), entry.getValue().asText()));
        }
        return values;
    }

    private String resourceGroup(String id) {
        if (id == null) return null;
        String lower = id.toLowerCase(Locale.ROOT);
        String marker = "/resourcegroups/";
        int start = lower.indexOf(marker);
        if (start < 0) return null;
        String remainder = id.substring(start + marker.length());
        int end = remainder.indexOf('/');
        return end < 0 ? remainder : remainder.substring(0, end);
    }

    private String canonicalArmId(String id) {
        return id == null ? null : id.trim().toLowerCase(Locale.ROOT);
    }

    private String text(JsonNode node) {
        return node == null || node.isMissingNode() || node.isNull() || node.asText().isBlank()
                ? null : node.asText();
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    public record DiscoverySnapshot(
            Map<String, List<AzureResource>> resources,
            Map<String, AzureApiFailure> failures
    ) {
    }

    public record AzureResource(
            String id,
            String originalId,
            String name,
            String type,
            String kind,
            String location,
            String subscriptionId,
            String resourceGroup,
            JsonNode identity,
            JsonNode properties,
            JsonNode sku,
            Map<String, String> tags,
            String parentId
    ) {
        AzureResource withLocation(String replacement) {
            return new AzureResource(id, originalId, name, type, kind, replacement, subscriptionId,
                    resourceGroup, identity, properties, sku, tags, parentId);
        }

        AzureResource withParentId(String replacement) {
            return new AzureResource(id, originalId, name, type, kind, location, subscriptionId,
                    resourceGroup, identity, properties, sku, tags, replacement);
        }
    }

    public record AzureApiFailure(String code, String message, boolean retryable, int statusCode) {
    }

    public static final class AzureApiException extends RuntimeException {
        private final AzureApiFailure failure;

        AzureApiException(AzureApiFailure failure) {
            super(failure.message());
            this.failure = failure;
        }

        public AzureApiFailure failure() {
            return failure;
        }
    }
}
