package com.prototype.vulnwatch.devseed;

import com.prototype.vulnwatch.VulnWatchApplication;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.RelationshipObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.aisecurity.service.AiGridAssessmentWorker;
import com.prototype.vulnwatch.aisecurity.service.AiGridCapabilityService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityObservationService;
import com.prototype.vulnwatch.aisecurity.service.AiSecuritySyncRunFacade;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

/**
 * Local-only demo seed for AI Grid. It is not part of the product and lives in test sources, so it is never packaged
 * into the application jar. Boots the backend context against the
 * local database without the web server or schedulers and feeds observation envelopes through the same ingest path
 * the AWS and Azure connectors use, so the product's own fact producers, assessment worker and published AI policies
 * decide which AI_POSTURE findings open. Usage: java ... AiGridDemoSeed [tenant-slug]
 */
public final class AiGridDemoSeed {

    private static final String AWS_ACCOUNT = "418273650912";
    private static final String AWS_REGION = "us-east-1";
    private static final String AZ_TENANT = "6b1f4c2e-9a3d-4e57-8c21-5d9e0a3b7f14";
    private static final String AZ_SUB = "3f2a9c41-7d6e-4b18-9a5c-2e8f0b7d4a61";
    private static final String AZ_REGION = "eastus";
    private static final List<String> AZ_FAMILIES = List.of("AZURE_AI_ACCOUNTS", "AZURE_RAI_POLICIES", "AZURE_SEARCH_KNOWLEDGE_BASES",
            "AZURE_FOUNDRY_AGENTS", "AZURE_FOUNDRY_AGENT_TOOLS", "AZURE_FOUNDRY_DEPLOYMENTS", "AZURE_ML_ENDPOINTS", "AZURE_BOT_SERVICES", "AZURE_DIAGNOSTIC_SETTINGS", "AZURE_BOT_IDENTITIES");

    private record Scope(String family, List<ArtifactObservation> artifacts, List<RelationshipObservation> relationships, String region) {
        Scope(String family, List<ArtifactObservation> artifacts, List<RelationshipObservation> relationships) {
            this(family, artifacts, relationships, null);
        }
    }

    private AiGridDemoSeed() { }

    public static void main(String[] args) throws Exception {
        String slug = args.length > 0 ? args[0] : "demo-workspace";
        try (ConfigurableApplicationContext ctx = new SpringApplicationBuilder(VulnWatchApplication.class)
                .web(WebApplicationType.SERVLET)
                .profiles("local", "postgres")
                .properties("app.scheduling.enabled=false", "spring.main.banner-mode=off", "server.port=0")
                .run()) {
            Tenant tenant = ctx.getBean(TenantRepository.class).findBySlugIgnoreCase(slug)
                    .orElseThrow(() -> new IllegalArgumentException("No tenant " + slug));
            AiSecurityObservationService observations = ctx.getBean(AiSecurityObservationService.class);
            AiSecuritySyncRunFacade runs = ctx.getBean(AiSecuritySyncRunFacade.class);
            AiGridCapabilityService capabilities = ctx.getBean(AiGridCapabilityService.class);
            TenantSchemaExecutionService tenantExecution = ctx.getBean(TenantSchemaExecutionService.class);
            NamedParameterJdbcTemplate jdbc = ctx.getBean(NamedParameterJdbcTemplate.class);

            UUID awsConnector = ctx.getBean(AiSecurityAwsConnectorService.class).save(tenant,
                    new AiSecurityAwsConnectorService.ConnectorConfigRequest(AWS_ACCOUNT,
                            "arn:aws:iam::" + AWS_ACCOUNT + ":role/ScoutgridAiReadOnly", null, List.of(AWS_REGION), true)).id();
            UUID azureConnector = azureConnector(tenant, tenantExecution, jdbc);

            // As the connectors do: declare the scanned families first, so their capabilities count as observed.
            List<Scope> aws = awsScopes();
            List<Scope> azure = azureScopes();
            UUID awsRun = runs.start(tenant, AiSecuritySyncRunFacade.AWS_SYNC_TYPE).getId();
            capabilities.registerRun(tenant, awsRun, "AWS", awsConnector, AWS_ACCOUNT, List.of(AWS_REGION),
                    aws.stream().map(Scope::family).distinct().toList());
            int awsArtifacts = ingest(observations, tenant, awsRun, awsConnector, "AWS", AWS_ACCOUNT, AWS_ACCOUNT, AWS_REGION, aws);
            capabilities.finalizeRun(tenant, awsRun);
            runs.complete(tenant.getId(), awsRun, awsArtifacts, 0,
                    "{\"provider\":\"AWS\",\"accountId\":\"" + AWS_ACCOUNT + "\",\"regions\":[\"" + AWS_REGION + "\"],\"seed\":\"ai-grid-demo\"}");

            UUID azureRun = runs.start(tenant, AiSecuritySyncRunFacade.AZURE_SYNC_TYPE).getId();
            capabilities.registerRun(tenant, azureRun, "AZURE", azureConnector, AZ_SUB, List.of(AZ_REGION),
                    azure.stream().map(Scope::family).distinct().toList());
            int azureArtifacts = ingest(observations, tenant, azureRun, azureConnector, "AZURE", AZ_TENANT, AZ_SUB, AZ_REGION, azure);
            capabilities.finalizeRun(tenant, azureRun);
            runs.complete(tenant.getId(), azureRun, azureArtifacts, 0,
                    "{\"provider\":\"AZURE\",\"subscriptionId\":\"" + AZ_SUB + "\",\"seed\":\"ai-grid-demo\"}");

            // Re-assess each finalized run (all capabilities now observed) through the product's assessment worker.
            Set<String> policies = Set.copyOf(jdbc.getJdbcTemplate().queryForList("""
                    select policy_id from platform.ai_grid_policy_distribution
                     where available and default_selection in ('REQUIRED','ENABLED','PREVIEW')""", String.class));
            AiGridAssessmentWorker worker = ctx.getBean(AiGridAssessmentWorker.class);
            worker.enqueue(tenant, awsRun, policies);
            worker.enqueue(tenant, azureRun, policies);
            waitForAssessments(tenant, tenantExecution, jdbc);
            System.out.println("SEED_RESULT aws_run=" + awsRun + " aws_artifacts=" + awsArtifacts
                    + " azure_run=" + azureRun + " azure_artifacts=" + azureArtifacts);
        }
    }

    private static int ingest(AiSecurityObservationService observations, Tenant tenant, UUID runId, UUID connectorId, String provider,
                              String providerTenantId, String account, String region, List<Scope> scopes) {
        int count = 0;
        for (Scope scope : scopes) {
            String scopeRegion = scope.region() == null ? region : scope.region();
            String scopeKey = provider + ":" + account + ":" + scopeRegion + ":" + scope.family();
            observations.ingest(tenant, new ObservationEnvelopeV1("1.0", runId, connectorId, tenant.getId(), provider, providerTenantId,
                    account, scopeRegion, scope.family(), scopeKey, 0, 1, runId + ":" + scope.family() + ":0",
                    "seed-" + scope.family() + "-" + scope.artifacts().size(), Instant.now(), ScopeStatus.COMPLETE,
                    scope.artifacts(), scope.relationships(), List.of()));
            count += scope.artifacts().size();
        }
        return count;
    }

    // ---- AWS: Bedrock agents, guardrails, knowledge bases, models, Lambda action groups, AgentCore MCP ----

    private static List<Scope> awsScopes() {
        String agentArn = "arn:aws:bedrock:" + AWS_REGION + ":" + AWS_ACCOUNT + ":agent/";
        String guardrailArn = "arn:aws:bedrock:" + AWS_REGION + ":" + AWS_ACCOUNT + ":guardrail/";
        String kbArn = "arn:aws:bedrock:" + AWS_REGION + ":" + AWS_ACCOUNT + ":knowledge-base/";
        String role = "arn:aws:iam::" + AWS_ACCOUNT + ":role/";
        List<Scope> scopes = new ArrayList<>();
        // Supporting control-plane scans the connector runs beside the AI families (IAM, Lambda URLs, S3 exposure).
        scopes.add(new Scope("IAM_GLOBAL", List.of(), List.of(), "GLOBAL"));
        scopes.add(new Scope("LAMBDA_URLS", List.of(), List.of()));
        scopes.add(new Scope("S3_EXPOSURE", List.of(), List.of()));

        ArtifactObservation strongGuardrail = artifact(guardrailArn + "gr-kanra-default", "AI_GUARDRAIL", "AWS_BEDROCK_GUARDRAIL",
                "kanra-default-guardrail", attrs("status", "READY", "minimumStrength", "HIGH", "contentFilterCount", 6,
                        "piiEntityCount", 5, "deniedTopicCount", 3, "tags", tags("platform-ai", "production", "high")));
        ArtifactObservation liteGuardrail = artifact(guardrailArn + "gr-claims-lite", "AI_GUARDRAIL", "AWS_BEDROCK_GUARDRAIL",
                "claims-guardrail-lite", attrs("status", "READY", "minimumStrength", "LOW", "contentFilterCount", 0,
                        "piiEntityCount", 0, "deniedTopicCount", 0, "tags", tags("claims", "production", "high")));
        ArtifactObservation draftGuardrail = artifact(guardrailArn + "gr-marketing-draft", "AI_GUARDRAIL", "AWS_BEDROCK_GUARDRAIL",
                "marketing-copy-guardrail", attrs("status", "FAILED", "minimumStrength", "MEDIUM", "contentFilterCount", 2,
                        "piiEntityCount", 1, "tags", tags("marketing", "staging", "low")));
        scopes.add(new Scope("BEDROCK_GUARDRAILS", List.of(strongGuardrail, liteGuardrail, draftGuardrail), List.of()));

        ArtifactObservation checkoutAgent = artifact(agentArn + "AGCHKOUT01", "AI_AGENT", "AWS_BEDROCK_AGENT", "checkout-support-agent",
                attrs("status", "PREPARED", "guardrailAttached", false, "executionRoleArn", role + "checkout-support-agent", "iamWildcardActions", true,
                        "foundationModel", "anthropic.claude-3-5-sonnet", "tags", tags("payments", "production", "high")));
        ArtifactObservation claimsAgent = artifact(agentArn + "AGCLAIMS02", "AI_AGENT", "AWS_BEDROCK_AGENT", "claims-triage-agent",
                attrs("status", "PREPARED", "guardrailAttached", true, "guardrailMinimumStrength", "LOW", "executionRoleArn", "",
                        "foundationModel", "anthropic.claude-3-haiku", "tags", tags("claims", "production", "high")));
        ArtifactObservation orderAgent = artifact(agentArn + "AGORDERS03", "AI_AGENT", "AWS_BEDROCK_AGENT", "order-status-agent",
                attrs("status", "PREPARED", "guardrailAttached", true, "guardrailMinimumStrength", "HIGH",
                        "executionRoleArn", role + "order-status-agent", "foundationModel", "amazon.nova-pro",
                        "tags", tags("fulfilment", "production", "medium")));
        ArtifactObservation fraudAgent = artifact(agentArn + "AGFRAUD04", "AI_AGENT", "AWS_BEDROCK_AGENT", "fraud-review-agent",
                attrs("status", "PREPARE_FAILED", "guardrailAttached", true, "guardrailMinimumStrength", "MEDIUM",
                        "executionRoleArn", role + "fraud-review-agent", "foundationModel", "anthropic.claude-3-5-sonnet",
                        "tags", tags("risk", "staging", "high")));
        ArtifactObservation refundTool = artifact("arn:aws:lambda:" + AWS_REGION + ":" + AWS_ACCOUNT + ":function:refund-action-group",
                "OTHER_AI_ARTIFACT", "AWS_LAMBDA_FUNCTION", "refund-action-group",
                attrs("status", "ACTIVE", "functionUrlAuthType", "NONE", "iamWildcardActions", true, "tags", tags("payments", "production", "high")));
        ArtifactObservation lookupTool = artifact("arn:aws:lambda:" + AWS_REGION + ":" + AWS_ACCOUNT + ":function:order-lookup-action",
                "OTHER_AI_ARTIFACT", "AWS_LAMBDA_FUNCTION", "order-lookup-action",
                attrs("status", "ACTIVE", "functionUrlAuthType", "AWS_IAM", "iamWildcardActions", false, "tags", tags("fulfilment", "production", "medium")));
        scopes.add(new Scope("BEDROCK_AGENTS", List.of(checkoutAgent, claimsAgent, orderAgent, fraudAgent, strongGuardrail, liteGuardrail,
                refundTool, lookupTool), List.of(
                rel(claimsAgent, liteGuardrail, "USES_GUARDRAIL"), rel(orderAgent, strongGuardrail, "USES_GUARDRAIL"),
                rel(fraudAgent, strongGuardrail, "USES_GUARDRAIL"), rel(checkoutAgent, refundTool, "USES_TOOL"),
                rel(orderAgent, lookupTool, "USES_TOOL"))));

        ArtifactObservation productKb = artifact(kbArn + "KBPRODDOCS", "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "product-docs-kb",
                attrs("status", "ACTIVE", "s3Public", true, "dataSourceCount", 2, "tags", tags("digital-experience", "production", "medium")));
        ArtifactObservation hrKb = artifact(kbArn + "KBHRPOLICY", "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "hr-policies-kb",
                attrs("status", "ACTIVE", "s3Public", false, "dataSourceCount", 0, "tags", tags("people-ops", "production", "high")));
        ArtifactObservation claimsKb = artifact(kbArn + "KBCLAIMHST", "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "claims-history-kb",
                attrs("status", "FAILED", "s3Public", false, "dataSourceCount", 1, "tags", tags("claims", "production", "high")));
        ArtifactObservation supportKb = artifact(kbArn + "KBSUPPORT1", "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "support-playbooks-kb",
                attrs("status", "ACTIVE", "s3Public", false, "dataSourceCount", 3, "tags", tags("payments", "production", "medium")));
        scopes.add(new Scope("BEDROCK_KNOWLEDGE_BASES", List.of(productKb, hrKb, claimsKb, supportKb), List.of(
                rel(checkoutAgent, supportKb, "USES_KNOWLEDGE_BASE"), rel(claimsAgent, claimsKb, "USES_KNOWLEDGE_BASE"))));

        String modelArn = "arn:aws:bedrock:" + AWS_REGION + ":" + AWS_ACCOUNT + ":custom-model/";
        ArtifactObservation fraudModel = artifact(modelArn + "fraud-scoring-v3", "AI_MODEL", "AWS_BEDROCK_CUSTOM_MODEL", "fraud-scoring-v3",
                attrs("status", "ACTIVE", "invocationLoggingEnabled", false, "providerName", "Kanra", "tags", tags("risk", "production", "high")));
        ArtifactObservation summarizer = artifact(modelArn + "claims-summarizer-v1", "AI_MODEL", "AWS_BEDROCK_CUSTOM_MODEL", "claims-summarizer-v1",
                attrs("status", "LEGACY", "invocationLoggingEnabled", true, "providerName", "Kanra", "tags", tags("claims", "production", "medium")));
        ArtifactObservation recommender = artifact(modelArn + "product-recommender-v2", "AI_MODEL", "AWS_BEDROCK_IMPORTED_MODEL",
                "product-recommender-v2", attrs("status", "ACTIVE", "invocationLoggingEnabled", true, "providerName", "Kanra",
                        "tags", tags("digital-experience", "production", "medium")));
        scopes.add(new Scope("BEDROCK_DEPLOYABLE_MODELS", List.of(fraudModel, summarizer, recommender), List.of(
                rel(fraudAgent, fraudModel, "USES_MODEL"))));

        ArtifactObservation dsDomain = artifact("arn:aws:sagemaker:" + AWS_REGION + ":" + AWS_ACCOUNT + ":domain/d-datasci01",
                "AI_MODEL", "AWS_SAGEMAKER_DOMAIN", "data-science-studio", attrs("status", "InService", "vpcId", "", "invocationLoggingEnabled", true,
                        "tags", tags("data-platform", "production", "medium")));
        ArtifactObservation mlDomain = artifact("arn:aws:sagemaker:" + AWS_REGION + ":" + AWS_ACCOUNT + ":domain/d-mlplatfm2",
                "AI_MODEL", "AWS_SAGEMAKER_DOMAIN", "ml-platform-studio", attrs("status", "InService", "vpcId", "vpc-0a7f3c91e2b4d5f60", "invocationLoggingEnabled", true,
                        "tags", tags("data-platform", "production", "high")));
        scopes.add(new Scope("SAGEMAKER_DOMAINS", List.of(dsDomain, mlDomain), List.of()));

        String gwArn = "arn:aws:bedrock-agentcore:" + AWS_REGION + ":" + AWS_ACCOUNT + ":gateway/";
        ArtifactObservation opsGateway = artifact(gwArn + "ops-tools-gw", "MCP_GATEWAY", "AWS_AGENTCORE_GATEWAY", "ops-tools-gateway",
                attrs("status", "READY", "inboundAuthType", "NONE", "endpointExposure", "PUBLIC_NETWORK_REACHABLE",
                        "tags", tags("platform", "production", "high")));
        ArtifactObservation partnerGateway = artifact(gwArn + "partner-mcp-gw", "MCP_GATEWAY", "AWS_AGENTCORE_GATEWAY", "partner-mcp-gateway",
                attrs("status", "READY", "inboundAuthType", "CUSTOM_JWT", "tags", tags("platform", "production", "medium")));
        scopes.add(new Scope("AWS_AGENTCORE_GATEWAYS", List.of(opsGateway, partnerGateway), List.of()));

        ArtifactObservation ticketTarget = artifact(gwArn + "ops-tools-gw/target/servicenow-tickets", "MCP_TARGET",
                "AWS_AGENTCORE_GATEWAY_TARGET", "servicenow-ticket-tools", attrs("status", "FAILED", "outboundAuthType", "NONE",
                        "tags", tags("platform", "production", "high")));
        ArtifactObservation inventoryTarget = artifact(gwArn + "partner-mcp-gw/target/inventory-api", "MCP_TARGET",
                "AWS_AGENTCORE_GATEWAY_TARGET", "inventory-api-tools", attrs("status", "READY", "outboundAuthType", "OAUTH",
                        "tags", tags("fulfilment", "production", "medium")));
        scopes.add(new Scope("AWS_AGENTCORE_GATEWAY_TARGETS", List.of(ticketTarget, inventoryTarget), List.of(
                rel(opsGateway, ticketTarget, "ROUTES_TO_TARGET"), rel(partnerGateway, inventoryTarget, "ROUTES_TO_TARGET"))));
        return scopes;
    }

    // ---- Azure: OpenAI accounts, RAI policies, AI Search knowledge bases, Foundry agents/MCP, ML, bots ----

    private static List<Scope> azureScopes() {
        String rg = "/subscriptions/" + AZ_SUB + "/resourceGroups/";
        String cs = "/providers/Microsoft.CognitiveServices/accounts/";
        List<Scope> scopes = new ArrayList<>();
        scopes.add(new Scope("AZURE_DIAGNOSTIC_SETTINGS", List.of(), List.of()));
        scopes.add(new Scope("AZURE_BOT_IDENTITIES", List.of(), List.of()));

        ArtifactObservation prodOpenAi = artifact(rg + "rg-ai-prod" + cs + "kanra-openai-prod", "OTHER_AI_ARTIFACT", "AZURE_AI_ACCOUNTS",
                "kanra-openai-prod", attrs("provisioningState", "Succeeded", "localAuthEnabled", true, "diagnosticLoggingEnabled", false,
                        "hasDestination", false, "publicNetworkUnrestricted", true, "customerManagedKey", false, "privateEndpointCount", 0,
                        "tags", Map.of("environment", "production", "criticality", "high")));
        ArtifactObservation devOpenAi = artifact(rg + "rg-ai-dev" + cs + "kanra-openai-dev", "OTHER_AI_ARTIFACT", "AZURE_AI_ACCOUNTS",
                "kanra-openai-dev", attrs("provisioningState", "Succeeded", "localAuthEnabled", false, "diagnosticLoggingEnabled", true,
                        "hasDestination", true, "publicNetworkUnrestricted", false, "customerManagedKey", true, "privateEndpointCount", 1,
                        "tags", Map.of("owner", "data-platform", "environment", "development", "criticality", "medium")));
        ArtifactObservation euOpenAi = artifact(rg + "rg-ai-eu" + cs + "kanra-openai-weu", "OTHER_AI_ARTIFACT", "AZURE_AI_ACCOUNTS",
                "kanra-openai-weu", attrs("provisioningState", "Failed", "localAuthEnabled", false, "diagnosticLoggingEnabled", true,
                        "hasDestination", true, "publicNetworkUnrestricted", false,
                        "tags", Map.of("owner", "digital-experience", "environment", "staging", "criticality", "medium")));
        scopes.add(new Scope("AZURE_AI_ACCOUNTS", List.of(prodOpenAi, devOpenAi, euOpenAi), List.of()));

        ArtifactObservation prodFilter = artifact(rg + "rg-ai-prod" + cs + "kanra-openai-prod/raiPolicies/prod-content-filter", "AI_GUARDRAIL",
                "AZURE_RAI_POLICIES", "prod-content-filter", attrs("raiFilterEvidenceComplete", true, "raiNonBlockingFilterObserved", true,
                        "raiFilterCount", 0, "raiPolicyMode", "Asynchronous_filter", "raiBasePolicyName", "Microsoft.Default"));
        ArtifactObservation devFilter = artifact(rg + "rg-ai-dev" + cs + "kanra-openai-dev/raiPolicies/strict-filter", "AI_GUARDRAIL",
                "AZURE_RAI_POLICIES", "strict-filter", attrs("raiFilterEvidenceComplete", true, "raiNonBlockingFilterObserved", false,
                        "raiFilterCount", 8, "raiPolicyMode", "Blocking", "raiBasePolicyName", "Microsoft.DefaultV2",
                        "raiPolicyName", "strict-filter"));
        scopes.add(new Scope("AZURE_RAI_POLICIES", List.of(prodFilter, devFilter), List.of(rel(prodOpenAi, prodFilter, "USES_GUARDRAIL"),
                rel(devOpenAi, devFilter, "USES_GUARDRAIL"))));

        String search = "/providers/Microsoft.Search/searchServices/kanra-search/knowledgebases/";
        ArtifactObservation policyKb = artifact(rg + "rg-search" + search + "customer-policies", "KNOWLEDGE_BASE",
                "AZURE_SEARCH_KNOWLEDGE_BASES", "customer-policies-kb", attrs("publicNetworkUnrestricted", true,
                        "searchLocalAuthEnabled", true, "retrievalMode", "HYBRID"));
        ArtifactObservation engKb = artifact(rg + "rg-search" + search + "engineering-runbooks", "KNOWLEDGE_BASE",
                "AZURE_SEARCH_KNOWLEDGE_BASES", "engineering-runbooks-kb", attrs("publicNetworkUnrestricted", false,
                        "searchLocalAuthEnabled", false, "retrievalMode", "SEMANTIC"));
        scopes.add(new Scope("AZURE_SEARCH_KNOWLEDGE_BASES", List.of(policyKb, engKb), List.of()));

        String foundry = rg + "rg-ai-prod/providers/Microsoft.CognitiveServices/accounts/kanra-foundry/projects/customer-care/";
        ArtifactObservation careAgent = artifact(foundry + "agents/care-concierge", "AI_AGENT", "AZURE_FOUNDRY_AGENTS", "care-concierge-agent",
                attrs("status", "Active", "codeInterpreterEnabled", true, "modelDeployment", "gpt-4o-prod"));
        ArtifactObservation billingAgent = artifact(foundry + "agents/billing-helper", "AI_AGENT", "AZURE_FOUNDRY_AGENTS", "billing-helper-agent",
                attrs("status", "Active", "codeInterpreterEnabled", false, "modelDeployment", "gpt-4o-mini-prod"));
        scopes.add(new Scope("AZURE_FOUNDRY_AGENTS", List.of(careAgent, billingAgent), List.of(rel(careAgent, policyKb, "USES_KNOWLEDGE_BASE"))));

        ArtifactObservation crmMcp = artifact(foundry + "tools/crm-mcp", "MCP_SERVER", "AZURE_FOUNDRY_MCP_SERVER", "crm-lookup-mcp",
                attrs("endpointHost", "crm-mcp.kanra.example", "configuredAuthType", "NONE", "toolType", "mcp"));
        ArtifactObservation docsMcp = artifact(foundry + "tools/docs-mcp", "MCP_SERVER", "AZURE_FOUNDRY_MCP_SERVER", "docs-search-mcp",
                attrs("endpointHost", "docs-mcp.kanra.example", "configuredAuthType", "OAUTH2", "toolType", "mcp"));
        scopes.add(new Scope("AZURE_FOUNDRY_AGENT_TOOLS", List.of(crmMcp, docsMcp), List.of(rel(careAgent, crmMcp, "USES_TOOL"),
                rel(billingAgent, docsMcp, "USES_TOOL"))));

        ArtifactObservation gpt4o = artifact(rg + "rg-ai-prod" + cs + "kanra-openai-prod/deployments/gpt-4o-prod", "AI_MODEL",
                "AZURE_FOUNDRY_DEPLOYMENTS", "gpt-4o-prod", attrs("modelName", "gpt-4o", "modelPublisher", "OpenAI", "modelVersion", "2024-08-06",
                        "versionUpgradeOption", "NoAutoUpgrade", "raiPolicyName", "prod-content-filter"));
        ArtifactObservation gpt4oMini = artifact(rg + "rg-ai-prod" + cs + "kanra-openai-prod/deployments/gpt-4o-mini-prod", "AI_MODEL",
                "AZURE_FOUNDRY_DEPLOYMENTS", "gpt-4o-mini-prod", attrs("modelName", "gpt-4o-mini", "modelPublisher", "OpenAI",
                        "modelVersion", "2024-07-18", "versionUpgradeOption", "OnceNewDefaultVersionAvailable"));
        scopes.add(new Scope("AZURE_FOUNDRY_DEPLOYMENTS", List.of(gpt4o, gpt4oMini), List.of(rel(prodOpenAi, gpt4o, "DEPLOYS_MODEL"),
                rel(prodOpenAi, gpt4oMini, "DEPLOYS_MODEL"), rel(careAgent, gpt4o, "USES_MODEL"), rel(billingAgent, gpt4oMini, "USES_MODEL"))));

        ArtifactObservation churnEndpoint = artifact(rg + "rg-ml/providers/Microsoft.MachineLearningServices/workspaces/kanra-ml/onlineEndpoints/churn-score",
                "OTHER_AI_ARTIFACT", "AZURE_ML_ENDPOINTS", "churn-score-endpoint", attrs("provisioningState", "Succeeded",
                        "mlLocalAuthEnabled", true, "traffic", Map.of("blue", 100), "tags", Map.of("owner", "data-platform")));
        scopes.add(new Scope("AZURE_ML_ENDPOINTS", List.of(churnEndpoint), List.of()));

        ArtifactObservation supportBot = artifact(rg + "rg-bots/providers/Microsoft.BotService/botServices/kanra-support-bot", "AI_AGENT",
                "AZURE_BOT_SERVICES", "kanra-support-bot", attrs("provisioningState", "Succeeded", "botPasswordAuthWithoutManagedIdentity", true,
                        "managedIdentityAssigned", false));
        scopes.add(new Scope("AZURE_BOT_SERVICES", List.of(supportBot), List.of()));
        return scopes;
    }

    // ---- helpers ----

    private static UUID azureConnector(Tenant tenant, TenantSchemaExecutionService tenantExecution, NamedParameterJdbcTemplate jdbc) {
        return tenantExecution.run(tenant, () -> {
            List<UUID> existing = jdbc.queryForList("select id from ai_security_connector_configs where provider = 'AZURE' and account_id = :sub",
                    Map.of("sub", AZ_SUB), UUID.class);
            if (!existing.isEmpty()) return existing.get(0);
            UUID id = UUID.randomUUID();
            jdbc.update("""
                    insert into ai_security_connector_configs
                        (id, tenant_id, provider, account_id, provider_tenant_id, regions_json, resource_families_json, enabled)
                    values (:id, :tenantId, 'AZURE', :sub, :azTenant, cast(:regions as jsonb), cast(:families as jsonb), true)
                    """, Map.of("id", id, "tenantId", tenant.getId(), "sub", AZ_SUB, "azTenant", AZ_TENANT,
                    "regions", "[\"" + AZ_REGION + "\"]", "families", "[\"" + String.join("\",\"", AZ_FAMILIES) + "\"]"));
            return id;
        });
    }

    private static void waitForAssessments(Tenant tenant, TenantSchemaExecutionService tenantExecution, NamedParameterJdbcTemplate jdbc)
            throws InterruptedException {
        for (int i = 0; i < 60; i++) {
            Integer pending = tenantExecution.run(tenant, () -> jdbc.queryForObject(
                    "select count(*) from ai_grid_outbox where event_type = 'STATIC_ASSESSMENT_REQUESTED' and status in ('PENDING','PROCESSING')", Map.of(), Integer.class));
            if (pending == null || pending == 0) return;
            Thread.sleep(1000);
        }
        System.out.println("SEED_WARNING assessment outbox still has pending events; the running server's poller will finish them");
    }

    private static ArtifactObservation artifact(String id, String type, String nativeKind, String name, Map<String, Object> attributes) {
        return new ArtifactObservation(id, type, nativeKind, name, attributes);
    }

    private static RelationshipObservation rel(ArtifactObservation source, ArtifactObservation target, String type) {
        return new RelationshipObservation(source.providerResourceId(), target.providerResourceId(), type, Map.of());
    }

    private static Map<String, Object> attrs(Object... pairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) map.put((String) pairs[i], pairs[i + 1]);
        return map;
    }

    private static Map<String, String> tags(String owner, String environment, String criticality) {
        return Map.of("owner", owner, "environment", environment, "criticality", criticality);
    }
}
