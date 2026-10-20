package com.prototype.vulnwatch.aisecurity.aws;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.Diagnostic;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.RelationshipObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.ConnectorSecret;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService.CredentialsHandle;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityObservationService;
import com.prototype.vulnwatch.aisecurity.service.AiSecuritySyncRunFacade;
import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService;
import com.prototype.vulnwatch.aisecurity.service.AiGridCapabilityService;
import com.prototype.vulnwatch.aisecurity.service.AiGridProviderCallCounter;
import com.prototype.vulnwatch.aisecurity.service.AiGridRelationshipSemantics;
import com.prototype.vulnwatch.aisecurity.service.AiGridRunMetricsService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityDigestService;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.domain.Tenant;
import java.net.URLDecoder;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.core.interceptor.Context;
import software.amazon.awssdk.core.interceptor.ExecutionAttributes;
import software.amazon.awssdk.core.interceptor.ExecutionInterceptor;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.bedrock.BedrockClient;
import software.amazon.awssdk.services.bedrock.model.GetCustomModelRequest;
import software.amazon.awssdk.services.bedrock.model.GetCustomModelResponse;
import software.amazon.awssdk.services.bedrock.model.GetFoundationModelRequest;
import software.amazon.awssdk.services.bedrock.model.GetFoundationModelResponse;
import software.amazon.awssdk.services.bedrock.model.GetGuardrailRequest;
import software.amazon.awssdk.services.bedrock.model.GetGuardrailResponse;
import software.amazon.awssdk.services.bedrock.model.GetImportedModelRequest;
import software.amazon.awssdk.services.bedrock.model.GetImportedModelResponse;
import software.amazon.awssdk.services.bedrock.model.GetModelInvocationLoggingConfigurationRequest;
import software.amazon.awssdk.services.bedrock.model.GuardrailContentFilter;
import software.amazon.awssdk.services.bedrock.model.GuardrailContextualGroundingFilter;
import software.amazon.awssdk.services.bedrock.model.GuardrailManagedWords;
import software.amazon.awssdk.services.bedrock.model.GuardrailPiiEntity;
import software.amazon.awssdk.services.bedrock.model.GuardrailRegex;
import software.amazon.awssdk.services.bedrock.model.GuardrailTopic;
import software.amazon.awssdk.services.bedrock.model.GuardrailWord;
import software.amazon.awssdk.services.bedrock.model.ListGuardrailsRequest;
import software.amazon.awssdk.services.bedrock.model.ListCustomModelsRequest;
import software.amazon.awssdk.services.bedrock.model.ListImportedModelsRequest;
import software.amazon.awssdk.services.bedrock.model.ListInferenceProfilesRequest;
import software.amazon.awssdk.services.bedrock.model.ListModelCustomizationJobsRequest;
import software.amazon.awssdk.services.bedrock.model.ListProvisionedModelThroughputsRequest;
import software.amazon.awssdk.services.bedrockagent.BedrockAgentClient;
import software.amazon.awssdk.services.bedrockagent.model.GetAgentActionGroupRequest;
import software.amazon.awssdk.services.bedrockagent.model.GetAgentRequest;
import software.amazon.awssdk.services.bedrockagent.model.GetAgentVersionRequest;
import software.amazon.awssdk.services.bedrockagent.model.GetDataSourceRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListAgentActionGroupsRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListAgentAliasesRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListAgentKnowledgeBasesRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListAgentsRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListAgentVersionsRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListDataSourcesRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListKnowledgeBasesRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListFlowsRequest;
import software.amazon.awssdk.services.bedrockagent.model.ListPromptsRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.BedrockAgentCoreControlClient;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.GetGatewayRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.GetGatewayTargetRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.GetAgentRuntimeRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListAgentRuntimeEndpointsRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListAgentRuntimeVersionsRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListAgentRuntimesRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListBrowsersRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListCodeInterpretersRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListGatewayTargetsRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListGatewaysRequest;
import software.amazon.awssdk.services.bedrockagentcorecontrol.model.ListMemoriesRequest;
import software.amazon.awssdk.services.iam.IamClient;
import software.amazon.awssdk.services.iam.model.GetPolicyRequest;
import software.amazon.awssdk.services.iam.model.GetPolicyVersionRequest;
import software.amazon.awssdk.services.iam.model.GetRolePolicyRequest;
import software.amazon.awssdk.services.iam.model.GetRoleRequest;
import software.amazon.awssdk.services.iam.model.ListAttachedRolePoliciesRequest;
import software.amazon.awssdk.services.iam.model.ListRolePoliciesRequest;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.GetFunctionUrlConfigRequest;
import software.amazon.awssdk.services.lambda.model.ResourceNotFoundException;
import software.amazon.awssdk.services.macie2.Macie2Client;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetBucketPolicyStatusRequest;
import software.amazon.awssdk.services.sagemaker.SageMakerClient;
import software.amazon.awssdk.services.sagemaker.model.DescribeDomainRequest;
import software.amazon.awssdk.services.sagemaker.model.DescribeEndpointConfigRequest;
import software.amazon.awssdk.services.sagemaker.model.DescribeEndpointRequest;
import software.amazon.awssdk.services.sagemaker.model.DescribeModelPackageGroupRequest;
import software.amazon.awssdk.services.sagemaker.model.DescribeNotebookInstanceRequest;
import software.amazon.awssdk.services.sagemaker.model.DescribeSpaceRequest;
import software.amazon.awssdk.services.sagemaker.model.ListDomainsRequest;
import software.amazon.awssdk.services.sagemaker.model.ListEndpointConfigsRequest;
import software.amazon.awssdk.services.sagemaker.model.ListEndpointsRequest;
import software.amazon.awssdk.services.sagemaker.model.ListModelPackageGroupsRequest;
import software.amazon.awssdk.services.sagemaker.model.ListModelPackagesRequest;
import software.amazon.awssdk.services.sagemaker.model.ListNotebookInstancesRequest;
import software.amazon.awssdk.services.sagemaker.model.ListPipelinesRequest;
import software.amazon.awssdk.services.sagemaker.model.ListProcessingJobsRequest;
import software.amazon.awssdk.services.sagemaker.model.ListSpacesRequest;
import software.amazon.awssdk.services.sagemaker.model.ListTrainingJobsRequest;
import software.amazon.awssdk.services.sagemaker.model.ListTransformJobsRequest;

@Service
public class AwsBedrockDiscoveryService {

    private static final Logger LOG = LoggerFactory.getLogger(AwsBedrockDiscoveryService.class);
    private static final List<String> COLLECTOR_FAMILIES = List.of(
            "BEDROCK_AGENTS", "BEDROCK_AGENT_VERSIONS", "BEDROCK_AGENT_ROUTES", "BEDROCK_AGENT_DEFINITIONS",
            "BEDROCK_DEPLOYABLE_MODELS", "BEDROCK_INFERENCE_PROFILES", "BEDROCK_MODEL_CUSTOMIZATION_JOBS",
            "BEDROCK_PROMPTS", "BEDROCK_FLOWS", "IAM_GLOBAL", "LAMBDA_URLS",
            "BEDROCK_KNOWLEDGE_BASES", "BEDROCK_DATA_SOURCES", "BEDROCK_DATA_STORES",
            "AWS_AGENTCORE_GATEWAYS", "AWS_AGENTCORE_GATEWAY_TARGETS", "AWS_AGENTCORE_RUNTIMES",
            "AWS_AGENTCORE_BROWSERS", "AWS_AGENTCORE_CODE_INTERPRETERS", "AWS_AGENTCORE_MEMORIES",
            "S3_EXPOSURE", "AWS_MACIE_PII", "BEDROCK_GUARDRAILS", "BEDROCK_INVOCATION_LOGGING",
            "SAGEMAKER_DOMAINS", "SAGEMAKER_SPACES", "SAGEMAKER_MODEL_REGISTRY", "SAGEMAKER_ENDPOINTS",
            "SAGEMAKER_ENDPOINT_CONFIGURATIONS", "SAGEMAKER_JOBS", "SAGEMAKER_PIPELINES",
            "SAGEMAKER_COMPUTE", "SAGEMAKER_EXECUTION_ROLES", "SAGEMAKER_NETWORKING");

    public static List<String> collectorFamilies() {
        return COLLECTOR_FAMILIES;
    }

    private final AiSecurityAwsConnectorService connectorService;
    private final AiSecurityObservationService observationService;
    private final AiSecuritySyncRunFacade syncRunFacade;
    private final ObjectMapper objectMapper;
    private final AiSecurityAwsAdmissionService admissionService;
    private final AiGridBudgetService budgets;
    private final AiGridProviderCallCounter providerCalls;
    private final AiGridRunMetricsService runMetrics;
    private final AiGridCapabilityService capabilities;
    private final AwsMaciePiiLookupService maciePiiLookupService;
    private final AiSecurityDigestService digestService;
    private final boolean maciePiiEnabled;
    private final long providerCallCeiling;
    private final ExecutionInterceptor providerCallInterceptor = new ExecutionInterceptor() {
        @Override
        public void beforeTransmission(Context.BeforeTransmission context, ExecutionAttributes executionAttributes) {
            providerCalls.increment();
        }
    };

    public AwsBedrockDiscoveryService(
            AiSecurityAwsConnectorService connectorService,
            AiSecurityObservationService observationService,
            AiSecuritySyncRunFacade syncRunFacade,
            ObjectMapper objectMapper,
            AiSecurityAwsAdmissionService admissionService,
            AiGridBudgetService budgets,
            AiGridProviderCallCounter providerCalls,
            AiGridRunMetricsService runMetrics,
            AiGridCapabilityService capabilities,
            AwsMaciePiiLookupService maciePiiLookupService,
            AiSecurityDigestService digestService,
            @Value("${app.ai-security.aws.macie-pii.enabled:false}") boolean maciePiiEnabled,
            @Value("${app.ai-security.provider-call-ceiling:10000}") long providerCallCeiling
    ) {
        this.connectorService = connectorService;
        this.observationService = observationService;
        this.syncRunFacade = syncRunFacade;
        this.objectMapper = objectMapper;
        this.admissionService = admissionService;
        this.budgets = budgets;
        this.providerCalls = providerCalls;
        this.runMetrics = runMetrics;
        this.capabilities = capabilities;
        this.maciePiiLookupService = maciePiiLookupService;
        this.digestService = digestService;
        this.maciePiiEnabled = maciePiiEnabled;
        this.providerCallCeiling = providerCallCeiling;
    }

    public DiscoveryResult discover(Tenant tenant, UUID connectorId) {
        ConnectorSecret config = connectorService.secret(tenant);
        if (!config.id().equals(connectorId) || !tenant.getId().equals(config.tenantId()) || !config.enabled()) {
            throw new IllegalArgumentException("AI Security connector does not match claimed job");
        }
        SyncRun run = syncRunFacade.start(tenant, AiSecuritySyncRunFacade.AWS_SYNC_TYPE, json(Map.of(
                "provider", "AWS",
                "connectorId", connectorId,
                "accountId", config.accountId(),
                "regions", config.regions())));
        int artifacts = 0;
        int failedScopes = 0;
        capabilities.registerRun(tenant, run.getId(), "AWS", connectorId, config.accountId(),
                config.regions(), COLLECTOR_FAMILIES);
        try (var measurement = providerCalls.begin(providerCallCeiling)) {
            try {
                budgets.admit(tenant, run.getId(), "AWS", COLLECTOR_FAMILIES, "*", "*");
                try (CredentialsHandle credentials = connectorService.credentials(config)) {
                    Set<String> ingestedScopeKeys = new java.util.HashSet<>();
                    for (String regionName : config.regions()) {
                        Region region = Region.of(regionName);
                        try (var permit = admissionService.acquire(config.accountId(), regionName)) {
                            RegionContext context = discoverRegion(tenant, config, credentials.provider(), region);
                            for (ScopePayload scope : context.scopes()) {
                                // Global scopes are collected during each regional pass, but
                                // the receipt contract permits one global scope per run.
                                String scopeKey = "AWS:" + config.accountId() + ":"
                                        + (scope.global() ? "GLOBAL" : regionName) + ":" + scope.family();
                                if (!ingestedScopeKeys.add(scopeKey)) {
                                    continue;
                                }
                                observationService.ingest(tenant, envelope(tenant, config, run.getId(), regionName, scope));
                                artifacts += scope.artifacts().size();
                                if (scope.status() != ScopeStatus.COMPLETE) {
                                    failedScopes++;
                                }
                            }
                        }
                    }
                }
                int persistedArtifacts = observationService.countPersistedArtifacts(tenant, run.getId());
                capabilities.finalizeRun(tenant, run.getId());
                capabilities.recordRuntimeCapabilities(tenant, "AWS", "AWS_CONTROL_PLANE",
                        config.accountId(), "GLOBAL", "UNSUPPORTED_API",
                        "AWS control-plane inventory does not establish observed runtime action or decision evidence",
                        List.of("RUNTIME_EXECUTION_METADATA", "RUNTIME_VERSION_CORRELATION",
                                "RUNTIME_EVENT_DECISIONS", "RUNTIME_ACTION_OUTCOMES",
                                "RUNTIME_TOOL_CORRELATION", "RUNTIME_DATA_CLASSIFICATION"));
                runMetrics.recordProviderCalls(tenant, run.getId(), "AWS", measurement.count());
                budgets.reconcile(tenant, run.getId(), "AWS");
                syncRunFacade.complete(
                        tenant.getId(), run.getId(), persistedArtifacts, failedScopes,
                        json(Map.of(
                                "provider", "AWS",
                                "connectorId", connectorId,
                                "accountId", config.accountId(),
                                "regions", config.regions(),
                                "providerApiCalls", measurement.count())));
                return new DiscoveryResult(run.getId(), persistedArtifacts, failedScopes);
            } catch (Exception ex) {
                capabilities.finalizeRun(tenant, run.getId());
                runMetrics.recordProviderCalls(tenant, run.getId(), "AWS", measurement.count());
                budgets.reconcile(tenant, run.getId(), "AWS");
                syncRunFacade.fail(tenant.getId(), run.getId(), "AWS Bedrock discovery failed");
                throw ex;
            }
        }
    }

    private RegionContext discoverRegion(
            Tenant tenant, ConnectorSecret config, AwsCredentialsProvider credentials, Region region) {
        List<ScopePayload> scopes = new ArrayList<>();
        AgentContext agents = collectAgents(config, credentials, region, scopes);
        Map<String, List<String>> securityCorrelationVersions = collectAgentVersionsAndAliases(
                tenant, config, credentials, region, true, scopes);
        collectAgentRoutes(config, credentials, region, scopes);
        scopes.add(complete("BEDROCK_AGENT_DEFINITIONS", List.of(), List.of()));
        collectIam(config, credentials, region, agents, securityCorrelationVersions, true, scopes);
        collectLambdaUrls(config, credentials, region, agents, securityCorrelationVersions, scopes);
        collectKnowledgeBases(config, credentials, region, agents, securityCorrelationVersions, scopes);
        collectAgentCoreGateways(config, credentials, region, scopes);
        collectAgentCoreUtilities(config, credentials, region, scopes);
        collectGuardrails(config, credentials, region, agents, scopes);
        collectInvocationLogging(config, credentials, region, scopes);
        collectDeployableBedrockResources(config, credentials, region, scopes);
        collectSageMaker(config, credentials, region, scopes);
        return new RegionContext(scopes);
    }

    /** Lists Bedrock resource metadata only; prompt bodies, flow definitions, and model data are never read. */
    private void collectDeployableBedrockResources(
            ConnectorSecret config, AwsCredentialsProvider credentials, Region region, List<ScopePayload> scopes) {
        List<ArtifactObservation> models = new ArrayList<>(), profiles = new ArrayList<>(), jobs = new ArrayList<>(),
                prompts = new ArrayList<>(), flows = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        Map<String, GetFoundationModelResponse> foundationModelCache = new HashMap<>();
        try (BedrockClient bedrock = BedrockClient.builder().region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build();
             BedrockAgentClient agent = BedrockAgentClient.builder().region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            String token = null;
            do {
                var page = bedrock.listCustomModels(ListCustomModelsRequest.builder().nextToken(token).build());
                for (var model : page.modelSummaries()) {
                    Map<String, Object> attributes = new LinkedHashMap<>();
                    attributes.put("status", model.modelStatusAsString());
                    attributes.put("baseModelArn", safeValue(model.baseModelArn()));
                    attributes.put("customizationType", safeValue(model.customizationTypeAsString()));
                    attributes.put("ownerAccountId", safeValue(model.ownerAccountId()));
                    try {
                        GetCustomModelResponse detail = bedrock.getCustomModel(
                                GetCustomModelRequest.builder().modelIdentifier(model.modelArn()).build());
                        attributes.put("modelKmsKeyArn", safeValue(detail.modelKmsKeyArn()));
                        attributes.put("trainingDataS3Uri", detail.trainingDataConfig() == null
                                ? "" : safeValue(detail.trainingDataConfig().s3Uri()));
                        attributes.put("validationDataS3Uris", detail.validationDataConfig() == null
                                || !detail.validationDataConfig().hasValidators() ? List.of()
                                : detail.validationDataConfig().validators().stream()
                                        .map(v -> v.s3Uri()).toList());
                        attributes.put("failureMessage", safeValue(detail.failureMessage()));
                    } catch (Exception ex) {
                        LOG.warn("bedrock:GetCustomModel enrichment unavailable for {}: {}: {}",
                                model.modelArn(), ex.getClass().getName(), ex.getMessage());
                    }
                    models.add(new ArtifactObservation(
                            model.modelArn(), "AI_MODEL", "AWS_BEDROCK_CUSTOM_MODEL", model.modelName(), attributes));
                    if (hasText(model.baseModelArn())) {
                        String baseModelArn = model.baseModelArn();
                        String baseModelName = baseModelArn.contains("/")
                                ? baseModelArn.substring(baseModelArn.lastIndexOf('/') + 1) : baseModelArn;
                        models.add(foundationModelArtifact(bedrock, foundationModelCache,
                                baseModelArn, baseModelArn, baseModelName, "referencedByCustomModel"));
                        relationships.add(new RelationshipObservation(
                                model.modelArn(), baseModelArn, "USES_MODEL", Map.of()));
                    }
                }
                token = page.nextToken();
            } while (hasText(token));
            token = null;
            do {
                var page = bedrock.listImportedModels(ListImportedModelsRequest.builder().nextToken(token).build());
                for (var model : page.modelSummaries()) {
                    Map<String, Object> attributes = new LinkedHashMap<>();
                    attributes.put("architecture", safeValue(model.modelArchitecture()));
                    attributes.put("instructSupported", model.instructSupported());
                    try {
                        GetImportedModelResponse detail = bedrock.getImportedModel(
                                GetImportedModelRequest.builder().modelIdentifier(model.modelArn()).build());
                        attributes.put("modelKmsKeyArn", safeValue(detail.modelKmsKeyArn()));
                        attributes.put("modelDataS3Uri", detail.modelDataSource() == null
                                || detail.modelDataSource().s3DataSource() == null ? ""
                                : safeValue(detail.modelDataSource().s3DataSource().s3Uri()));
                    } catch (Exception ex) {
                        LOG.warn("bedrock:GetImportedModel enrichment unavailable for {}: {}: {}",
                                model.modelArn(), ex.getClass().getName(), ex.getMessage());
                    }
                    models.add(new ArtifactObservation(
                            model.modelArn(), "AI_MODEL", "AWS_BEDROCK_IMPORTED_MODEL", model.modelName(), attributes));
                }
                token = page.nextToken();
            } while (hasText(token));
            token = null;
            do {
                var page = bedrock.listProvisionedModelThroughputs(ListProvisionedModelThroughputsRequest.builder().nextToken(token).build());
                for (var throughput : page.provisionedModelSummaries()) {
                    Map<String, Object> attributes = new LinkedHashMap<>();
                    attributes.put("status", throughput.statusAsString());
                    attributes.put("modelArn", safeValue(throughput.modelArn()));
                    attributes.put("commitmentDuration", safeValue(throughput.commitmentDurationAsString()));
                    attributes.put("commitmentExpirationTime", throughput.commitmentExpirationTime() == null
                            ? "" : throughput.commitmentExpirationTime().toString());
                    models.add(new ArtifactObservation(throughput.provisionedModelArn(), "AI_MODEL",
                            "AWS_BEDROCK_PROVISIONED_MODEL", throughput.provisionedModelName(), attributes));
                    if (hasText(throughput.modelArn())) relationships.add(new RelationshipObservation(throughput.provisionedModelArn(), throughput.modelArn(), "USES_MODEL", Map.of()));
                }
                token = page.nextToken();
            } while (hasText(token));
            scopes.add(complete("BEDROCK_DEPLOYABLE_MODELS", models, relationships));

            token = null;
            do {
                var page = bedrock.listInferenceProfiles(ListInferenceProfilesRequest.builder().nextToken(token).build());
                for (var profile : page.inferenceProfileSummaries()) profiles.add(new ArtifactObservation(profile.inferenceProfileArn(), "OTHER_AI_ARTIFACT", "AWS_BEDROCK_INFERENCE_PROFILE", profile.inferenceProfileName(), Map.of("status", profile.statusAsString(), "type", profile.typeAsString())));
                token = page.nextToken();
            } while (hasText(token));
            scopes.add(complete("BEDROCK_INFERENCE_PROFILES", profiles, List.of()));

            token = null;
            do {
                var page = bedrock.listModelCustomizationJobs(ListModelCustomizationJobsRequest.builder().nextToken(token).build());
                for (var job : page.modelCustomizationJobSummaries()) {
                    jobs.add(new ArtifactObservation(job.jobArn(), "OTHER_AI_ARTIFACT", "AWS_BEDROCK_MODEL_CUSTOMIZATION_JOB", job.jobName(), Map.of("status", job.statusAsString(), "baseModelArn", safeValue(job.baseModelArn()), "customModelArn", safeValue(job.customModelArn()))));
                    if (hasText(job.customModelArn())) relationships.add(new RelationshipObservation(job.jobArn(), job.customModelArn(), "PRODUCES_MODEL", Map.of()));
                }
                token = page.nextToken();
            } while (hasText(token));
            scopes.add(complete("BEDROCK_MODEL_CUSTOMIZATION_JOBS", jobs, relationships));

            token = null;
            do {
                var page = agent.listPrompts(ListPromptsRequest.builder().nextToken(token).build());
                for (var prompt : page.promptSummaries()) prompts.add(new ArtifactObservation(prompt.arn(), "AI_PROMPT", "AWS_BEDROCK_PROMPT", prompt.name(), Map.of("providerNativeId", prompt.id(), "version", safeValue(prompt.version()))));
                token = page.nextToken();
            } while (hasText(token));
            scopes.add(complete("BEDROCK_PROMPTS", prompts, List.of()));
            token = null;
            do {
                var page = agent.listFlows(ListFlowsRequest.builder().nextToken(token).build());
                for (var flow : page.flowSummaries()) flows.add(new ArtifactObservation(flow.arn(), "OTHER_AI_ARTIFACT", "AWS_BEDROCK_FLOW", flow.name(), Map.of("id", flow.id(), "version", safeValue(flow.version()), "status", safeValue(flow.statusAsString()))));
                token = page.nextToken();
            } while (hasText(token));
            scopes.add(complete("BEDROCK_FLOWS", flows, List.of()));
        } catch (Exception ex) {
            List<String> permissions = List.of("bedrock:ListCustomModels", "bedrock:ListImportedModels", "bedrock:ListProvisionedModelThroughputs", "bedrock:ListInferenceProfiles", "bedrock:ListModelCustomizationJobs", "bedrock:ListPrompts", "bedrock:ListFlows", "bedrock:GetFoundationModel", "bedrock:GetCustomModel", "bedrock:GetImportedModel");
            for (String family : List.of("BEDROCK_DEPLOYABLE_MODELS", "BEDROCK_INFERENCE_PROFILES", "BEDROCK_MODEL_CUSTOMIZATION_JOBS", "BEDROCK_PROMPTS", "BEDROCK_FLOWS")) scopes.add(failed(family, ex, permissions));
        }
    }

    /** Read-only SageMaker inventory.  It intentionally lists/describes configuration metadata only. */
    private void collectSageMaker(
            ConnectorSecret config, AwsCredentialsProvider credentials, Region region, List<ScopePayload> scopes) {
        List<ArtifactObservation> domains = new ArrayList<>(), spaces = new ArrayList<>(), registry = new ArrayList<>(),
                endpoints = new ArrayList<>(), endpointConfigs = new ArrayList<>(), jobs = new ArrayList<>(),
                pipelines = new ArrayList<>(), compute = new ArrayList<>(), roles = new ArrayList<>(), networking = new ArrayList<>();
        List<RelationshipObservation> domainRelations = new ArrayList<>(), registryRelations = new ArrayList<>(),
                endpointConfigRelations = new ArrayList<>(), endpointRelations = new ArrayList<>();
        try (SageMakerClient client = SageMakerClient.builder().region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            String token = null;
            do {
                var page = client.listDomains(ListDomainsRequest.builder().nextToken(token).build());
                for (var summary : page.domains()) {
                    var detail = client.describeDomain(DescribeDomainRequest.builder().domainId(summary.domainId()).build());
                    String domainArn = detail.domainArn();
                    domains.add(new ArtifactObservation(domainArn, "OTHER_AI_ARTIFACT", "AWS_SAGEMAKER_DOMAIN", detail.domainName(),
                            Map.of("domainId", detail.domainId(), "authMode", detail.authModeAsString(), "vpcId", safeValue(detail.vpcId()))));
                    if (hasText(detail.defaultUserSettings() == null ? null : detail.defaultUserSettings().executionRole())) {
                        String roleArn = detail.defaultUserSettings().executionRole();
                        roles.add(new ArtifactObservation(roleArn, "OTHER_AI_ARTIFACT", "AWS_SAGEMAKER_EXECUTION_ROLE", roleArn,
                                Map.of("referencedBy", "domain")));
                        domainRelations.add(direct(domainArn, roleArn, "USES_EXECUTION_ROLE",
                                "sagemaker:DescribeDomain", "defaultUserSettings.executionRole"));
                    }
                    if (hasText(detail.vpcId())) {
                        String networkId = "arn:aws:sagemaker:" + region.id() + ":" + config.accountId() + ":network/" + detail.vpcId();
                        networking.add(new ArtifactObservation(networkId, "OTHER_AI_ARTIFACT", "AWS_SAGEMAKER_NETWORK", detail.vpcId(),
                                Map.of("vpcId", detail.vpcId(), "subnetIds", detail.subnetIds())));
                        domainRelations.add(direct(domainArn, networkId, "USES_NETWORK",
                                "sagemaker:DescribeDomain", "vpcId"));
                    }
                    String spaceToken = null;
                    do {
                        var spacePage = client.listSpaces(ListSpacesRequest.builder().domainIdEquals(detail.domainId()).nextToken(spaceToken).build());
                        for (var spaceSummary : spacePage.spaces()) {
                            var space = client.describeSpace(DescribeSpaceRequest.builder().domainId(detail.domainId()).spaceName(spaceSummary.spaceName()).build());
                            String spaceArn = space.spaceArn();
                            spaces.add(new ArtifactObservation(spaceArn, "OTHER_AI_ARTIFACT", "AWS_SAGEMAKER_SPACE", space.spaceName(),
                                    Map.of("domainId", detail.domainId(), "status", space.statusAsString())));
                            domainRelations.add(direct(domainArn, spaceArn, "CONTAINS",
                                    "sagemaker:ListSpaces", "domainId"));
                        }
                        spaceToken = spacePage.nextToken();
                    } while (hasText(spaceToken));
                }
                token = page.nextToken();
            } while (hasText(token));
            scopes.add(complete("SAGEMAKER_DOMAINS", domains, domainRelations));
            scopes.add(complete("SAGEMAKER_SPACES", spaces, domainRelations));
            scopes.add(completeGlobal("SAGEMAKER_EXECUTION_ROLES", roles));
            scopes.add(complete("SAGEMAKER_NETWORKING", networking, domainRelations));

            token = null;
            do {
                var page = client.listModelPackageGroups(ListModelPackageGroupsRequest.builder().nextToken(token).build());
                for (var group : page.modelPackageGroupSummaryList()) {
                    var detail = client.describeModelPackageGroup(DescribeModelPackageGroupRequest.builder().modelPackageGroupName(group.modelPackageGroupName()).build());
                    registry.add(new ArtifactObservation(detail.modelPackageGroupArn(), "AI_MODEL", "AWS_SAGEMAKER_MODEL_PACKAGE_GROUP", detail.modelPackageGroupName(), Map.of()));
                }
                token = page.nextToken();
            } while (hasText(token));
            token = null;
            do {
                var page = client.listModelPackages(ListModelPackagesRequest.builder().nextToken(token).build());
                for (var model : page.modelPackageSummaryList()) {
                    registry.add(new ArtifactObservation(model.modelPackageArn(), "AI_MODEL", "AWS_SAGEMAKER_MODEL_PACKAGE", model.modelPackageName(), Map.of("status", model.modelPackageStatusAsString())));
                    if (hasText(model.modelPackageGroupName())) {
                        String groupArn = "arn:aws:sagemaker:" + region.id() + ":" + config.accountId()
                                + ":model-package-group/" + model.modelPackageGroupName();
                        registryRelations.add(direct(model.modelPackageArn(), groupArn, "CONTAINS",
                                "sagemaker:ListModelPackages", "modelPackageGroupName"));
                    }
                }
                token = page.nextToken();
            } while (hasText(token));
            scopes.add(complete("SAGEMAKER_MODEL_REGISTRY", registry, registryRelations));

            token = null;
            do {
                var page = client.listEndpointConfigs(ListEndpointConfigsRequest.builder().nextToken(token).build());
                for (var summary : page.endpointConfigs()) {
                    var detail = client.describeEndpointConfig(DescribeEndpointConfigRequest.builder().endpointConfigName(summary.endpointConfigName()).build());
                    endpointConfigs.add(new ArtifactObservation(detail.endpointConfigArn(), "OTHER_AI_ARTIFACT", "AWS_SAGEMAKER_ENDPOINT_CONFIGURATION", detail.endpointConfigName(), Map.of("productionVariants", detail.productionVariants().size())));
                    for (var variant : detail.productionVariants()) {
                        if (!hasText(variant.modelName())) continue;
                        String modelArn = "arn:aws:sagemaker:" + region.id() + ":" + config.accountId()
                                + ":model/" + variant.modelName();
                        endpointConfigs.add(new ArtifactObservation(modelArn, "AI_MODEL", "AWS_SAGEMAKER_MODEL_REFERENCE",
                                variant.modelName(), Map.of("referenceOnly", true)));
                        endpointConfigRelations.add(direct(detail.endpointConfigArn(), modelArn, "USES_MODEL",
                                "sagemaker:DescribeEndpointConfig", "productionVariants[].modelName"));
                    }
                }
                token = page.nextToken();
            } while (hasText(token));
            scopes.add(complete("SAGEMAKER_ENDPOINT_CONFIGURATIONS", endpointConfigs, endpointConfigRelations));
            token = null;
            do {
                var page = client.listEndpoints(ListEndpointsRequest.builder().nextToken(token).build());
                for (var summary : page.endpoints()) {
                    var detail = client.describeEndpoint(DescribeEndpointRequest.builder().endpointName(summary.endpointName()).build());
                    endpoints.add(new ArtifactObservation(detail.endpointArn(), "OTHER_AI_ARTIFACT", "AWS_SAGEMAKER_ENDPOINT", detail.endpointName(), Map.of("status", detail.endpointStatusAsString(), "endpointConfigName", detail.endpointConfigName())));
                    String configArn = "arn:aws:sagemaker:" + region.id() + ":" + config.accountId() + ":endpoint-config/" + detail.endpointConfigName();
                    endpointRelations.add(direct(detail.endpointArn(), configArn, "USES_ENDPOINT_CONFIGURATION",
                            "sagemaker:DescribeEndpoint", "endpointConfigName"));
                }
                token = page.nextToken();
            } while (hasText(token));
            scopes.add(complete("SAGEMAKER_ENDPOINTS", endpoints, endpointRelations));

            client.listTrainingJobs(ListTrainingJobsRequest.builder().build()).trainingJobSummaries().forEach(job -> jobs.add(new ArtifactObservation(job.trainingJobArn(), "OTHER_AI_ARTIFACT", "AWS_SAGEMAKER_TRAINING_JOB", job.trainingJobName(), Map.of("status", job.trainingJobStatusAsString()))));
            client.listProcessingJobs(ListProcessingJobsRequest.builder().build()).processingJobSummaries().forEach(job -> jobs.add(new ArtifactObservation(job.processingJobArn(), "OTHER_AI_ARTIFACT", "AWS_SAGEMAKER_PROCESSING_JOB", job.processingJobName(), Map.of("status", job.processingJobStatusAsString()))));
            client.listTransformJobs(ListTransformJobsRequest.builder().build()).transformJobSummaries().forEach(job -> jobs.add(new ArtifactObservation(job.transformJobArn(), "OTHER_AI_ARTIFACT", "AWS_SAGEMAKER_TRANSFORM_JOB", job.transformJobName(), Map.of("status", job.transformJobStatusAsString()))));
            scopes.add(complete("SAGEMAKER_JOBS", jobs, List.of()));
            client.listPipelines(ListPipelinesRequest.builder().build()).pipelineSummaries().forEach(pipeline -> pipelines.add(new ArtifactObservation(pipeline.pipelineArn(), "OTHER_AI_ARTIFACT", "AWS_SAGEMAKER_PIPELINE", pipeline.pipelineName(), Map.of())));
            scopes.add(complete("SAGEMAKER_PIPELINES", pipelines, List.of()));
            token = null;
            do {
                var page = client.listNotebookInstances(ListNotebookInstancesRequest.builder().nextToken(token).build());
                for (var summary : page.notebookInstances()) {
                    var notebook = client.describeNotebookInstance(DescribeNotebookInstanceRequest.builder().notebookInstanceName(summary.notebookInstanceName()).build());
                    compute.add(new ArtifactObservation(notebook.notebookInstanceArn(), "OTHER_AI_ARTIFACT", "AWS_SAGEMAKER_NOTEBOOK_INSTANCE", notebook.notebookInstanceName(), Map.of("instanceType", notebook.instanceTypeAsString(), "status", notebook.notebookInstanceStatusAsString())));
                }
                token = page.nextToken();
            } while (hasText(token));
            scopes.add(complete("SAGEMAKER_COMPUTE", compute, List.of()));
        } catch (Exception ex) {
            Map<String, List<String>> required = Map.of(
                    "SAGEMAKER_DOMAINS", List.of("sagemaker:ListDomains", "sagemaker:DescribeDomain"),
                    "SAGEMAKER_SPACES", List.of("sagemaker:ListSpaces", "sagemaker:DescribeSpace"),
                    "SAGEMAKER_MODEL_REGISTRY", List.of("sagemaker:ListModelPackageGroups", "sagemaker:DescribeModelPackageGroup", "sagemaker:ListModelPackages"),
                    "SAGEMAKER_ENDPOINTS", List.of("sagemaker:ListEndpoints", "sagemaker:DescribeEndpoint"),
                    "SAGEMAKER_ENDPOINT_CONFIGURATIONS", List.of("sagemaker:ListEndpointConfigs", "sagemaker:DescribeEndpointConfig"),
                    "SAGEMAKER_JOBS", List.of("sagemaker:ListTrainingJobs", "sagemaker:ListProcessingJobs", "sagemaker:ListTransformJobs"),
                    "SAGEMAKER_PIPELINES", List.of("sagemaker:ListPipelines"),
                    "SAGEMAKER_COMPUTE", List.of("sagemaker:ListNotebookInstances", "sagemaker:DescribeNotebookInstance"),
                    "SAGEMAKER_EXECUTION_ROLES", List.of("sagemaker:DescribeDomain"),
                    "SAGEMAKER_NETWORKING", List.of("sagemaker:DescribeDomain"));
            required.forEach((family, permissions) -> scopes.add(failed(family, ex, permissions)));
        }
    }

    private AgentContext collectAgents(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            List<ScopePayload> scopes
    ) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        Map<String, AgentFact> facts = new LinkedHashMap<>();
        Map<String, GetFoundationModelResponse> foundationModelCache = new HashMap<>();
        try (BedrockAgentClient client = BedrockAgentClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build();
             BedrockClient bedrock = BedrockClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            String token = null;
            do {
                var response = client.listAgents(ListAgentsRequest.builder().nextToken(token).build());
                for (var summary : response.agentSummaries()) {
                    var agent = client.getAgent(GetAgentRequest.builder().agentId(summary.agentId()).build()).agent();
                    String agentArn = arn(config, region, "agent/" + summary.agentId());
                    Map<String, Object> attributes = new LinkedHashMap<>();
                    attributes.put("agentId", summary.agentId());
                    attributes.put("status", summary.agentStatusAsString());
                    attributes.put("executionRoleArn", agent.agentResourceRoleArn());
                    attributes.put("foundationModel", agent.foundationModel());
                    boolean guardrailAttached = agent.guardrailConfiguration() != null
                            && hasText(agent.guardrailConfiguration().guardrailIdentifier());
                    attributes.put("guardrailAttached", guardrailAttached);
                    if (guardrailAttached) {
                        attributes.put("guardrailId", agent.guardrailConfiguration().guardrailIdentifier());
                        attributes.put("guardrailVersion", safeValue(agent.guardrailConfiguration().guardrailVersion()));
                    }
                    artifacts.add(new ArtifactObservation(
                            agentArn, "AI_AGENT", "AWS_BEDROCK_AGENT", summary.agentName(), attributes));
                    facts.put(summary.agentId(), new AgentFact(
                            summary.agentId(), summary.agentName(), agentArn, agent.agentResourceRoleArn(),
                            agent.foundationModel(),
                            guardrailAttached ? agent.guardrailConfiguration().guardrailIdentifier() : null));

                    if (hasText(agent.foundationModel())) {
                        String modelId = agent.foundationModel();
                        String modelResourceId = modelId.startsWith("arn:")
                                ? modelId
                                : "bedrock:model:" + region.id() + ":" + modelId;
                        artifacts.add(foundationModelArtifact(bedrock, foundationModelCache,
                                modelResourceId, modelId, modelId, "referencedByAgent"));
                        relationships.add(new RelationshipObservation(
                                agentArn, modelResourceId, "USES_MODEL", Map.of()));
                    }
                }
                token = response.nextToken();
            } while (hasText(token));
            scopes.add(complete("BEDROCK_AGENTS", artifacts, relationships));
        } catch (Exception ex) {
            scopes.add(failed("BEDROCK_AGENTS", ex, List.of(
                    "bedrock:ListAgents", "bedrock:GetAgent")));
        }
        return new AgentContext(facts);
    }

    /** Retain DRAFT-inclusive versions for security correlation; only alias routes prove deployment. */
    private Map<String, List<String>> collectAgentVersionsAndAliases(
            Tenant tenant, ConnectorSecret config, AwsCredentialsProvider credentials, Region region,
            boolean includeDefinitions, List<ScopePayload> scopes) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        Map<String, List<String>> securityCorrelationVersions = new LinkedHashMap<>();
        try (BedrockAgentClient client = BedrockAgentClient.builder().region(region)
                .credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            String agentsToken = null;
            do {
                var agents = client.listAgents(ListAgentsRequest.builder().nextToken(agentsToken).build());
                for (var summary : agents.agentSummaries()) {
                    String agentArn = arn(config, region, "agent/" + summary.agentId());
                    artifacts.add(new ArtifactObservation(agentArn, "AI_AGENT", "AWS_BEDROCK_AGENT",
                            summary.agentName(), Map.of()));
                    boolean draftObserved = false;
                    String versionsToken = null;
                    do {
                        var versions = client.listAgentVersions(ListAgentVersionsRequest.builder()
                                .agentId(summary.agentId()).nextToken(versionsToken).build());
                        for (var version : versions.agentVersionSummaries()) {
                            if (!hasText(version.agentVersion())) continue;
                            String versionArn = agentArn + "/version/" + version.agentVersion();
                            var versionDetail = client.getAgentVersion(GetAgentVersionRequest.builder()
                                    .agentId(summary.agentId()).agentVersion(version.agentVersion()).build()).agentVersion();
                            Map<String, Object> attributes = new LinkedHashMap<>();
                            attributes.put("version", version.agentVersion());
                            attributes.put("status", version.agentStatusAsString());
                            attributes.put("deployedArtifact", false);
                            attributes.put("createdAt", version.createdAt() == null ? "" : version.createdAt().toString());
                            attributes.put("updatedAt", version.updatedAt() == null ? "" : version.updatedAt().toString());
                            artifacts.add(new ArtifactObservation(versionArn, "AI_AGENT_VERSION",
                                    "AWS_BEDROCK_AGENT_VERSION",
                                    summary.agentName() + " v" + version.agentVersion(), attributes));
                            draftObserved |= "DRAFT".equalsIgnoreCase(version.agentVersion());
                            relationships.add(new RelationshipObservation(versionArn, agentArn, "VERSION_OF",
                                    Map.of("confidence", "DIRECT", "sourceApi", "ListAgentVersions")));
                            if (includeDefinitions) {
                                addVersionModelAndGuardrailArtifacts(config, region, versionArn, versionDetail,
                                        artifacts, relationships);
                                addVersionPromptArtifacts(tenant, versionArn, versionDetail, artifacts, relationships);
                                addVersionToolArtifacts(client, summary.agentId(), version.agentVersion(), versionArn,
                                        artifacts, relationships);
                            }
                        }
                        versionsToken = versions.nextToken();
                    } while (hasText(versionsToken));

                    String aliasesToken = null;
                    do {
                        var aliases = client.listAgentAliases(ListAgentAliasesRequest.builder()
                                .agentId(summary.agentId()).nextToken(aliasesToken).build());
                        for (var alias : aliases.agentAliasSummaries()) {
                            String aliasArn = agentArn + "/alias/" + alias.agentAliasId();
                            List<String> routedVersions = alias.hasRoutingConfiguration()
                                    ? alias.routingConfiguration().stream().map(item -> item.agentVersion())
                                    .filter(this::hasText).toList() : List.of();
                            Map<String, Object> attributes = new LinkedHashMap<>();
                            attributes.put("aliasId", alias.agentAliasId());
                            attributes.put("aliasName", safeValue(alias.agentAliasName()));
                            attributes.put("status", alias.agentAliasStatusAsString());
                            attributes.put("invocationState", alias.aliasInvocationStateAsString());
                            attributes.put("routedVersions", routedVersions);
                            attributes.put("deployedArtifact", true);
                            artifacts.add(new ArtifactObservation(aliasArn, "AI_COMPONENT",
                                    "AWS_BEDROCK_AGENT_ALIAS", safeValue(alias.agentAliasName()), attributes));
                            relationships.add(new RelationshipObservation(agentArn, aliasArn, "HAS_COMPONENT",
                                    Map.of("confidence", "DIRECT", "evidence", Map.of(
                                            "sourceApi", "ListAgentAliases", "field", "agentId"))));
                            for (String version : routedVersions) {
                                securityCorrelationVersions.computeIfAbsent(summary.agentId(), ignored -> new ArrayList<>()).add(version);
                                relationships.add(new RelationshipObservation(aliasArn,
                                        agentArn + "/version/" + version, "SERVES_VERSION",
                                        Map.of("confidence", "DIRECT", "evidence", Map.of(
                                                "sourceApi", "ListAgentAliases",
                                                "field", "routingConfiguration.agentVersion"))));
                            }
                        }
                        aliasesToken = aliases.nextToken();
                    } while (hasText(aliasesToken));
                    if (securityCorrelationVersions.getOrDefault(summary.agentId(), List.of()).isEmpty() && draftObserved) {
                        securityCorrelationVersions.put(summary.agentId(), new ArrayList<>(List.of("DRAFT")));
                    }
                }
                agentsToken = agents.nextToken();
            } while (hasText(agentsToken));
            scopes.add(complete("BEDROCK_AGENT_VERSIONS", artifacts, relationships));
        } catch (Exception ex) {
            scopes.add(failed("BEDROCK_AGENT_VERSIONS", ex, List.of(
                    "bedrock:ListAgents", "bedrock:ListAgentVersions", "bedrock:ListAgentAliases",
                    "bedrock:GetAgentVersion", "bedrock:ListAgentActionGroups", "bedrock:GetAgentActionGroup")));
        }
        securityCorrelationVersions.replaceAll((agentId, versions) -> versions.stream().distinct().toList());
        return Map.copyOf(securityCorrelationVersions);
    }

    /** Routing has its own finalized scope: definition/IAM/tool failures cannot invalidate it. */
    BedrockAgentClient routingClient(AwsCredentialsProvider credentials, Region region) {
        return BedrockAgentClient.builder().region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build();
    }

    private void collectAgentRoutes(ConnectorSecret config, AwsCredentialsProvider credentials, Region region,
                                    List<ScopePayload> scopes) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        try (BedrockAgentClient client = routingClient(credentials, region)) {
            String agentsToken = null;
            do {
                var agents = client.listAgents(ListAgentsRequest.builder().nextToken(agentsToken).build());
                for (var summary : agents.agentSummaries()) {
                    String agentArn = arn(config, region, "agent/" + summary.agentId());
                    artifacts.add(new ArtifactObservation(agentArn, "AI_AGENT", "AWS_BEDROCK_AGENT",
                            summary.agentName(), Map.of()));
                    String versionsToken = null;
                    do {
                        var versions = client.listAgentVersions(ListAgentVersionsRequest.builder()
                                .agentId(summary.agentId()).nextToken(versionsToken).build());
                        for (var version : versions.agentVersionSummaries()) {
                            if (!hasText(version.agentVersion())) continue;
                            String versionArn = agentArn + "/version/" + version.agentVersion();
                            Map<String, Object> attributes = new LinkedHashMap<>();
                            attributes.put("version", version.agentVersion());
                            attributes.put("status", version.agentStatusAsString());
                            attributes.put("deployedArtifact", false);
                            attributes.put("createdAt", version.createdAt() == null ? "" : version.createdAt().toString());
                            attributes.put("updatedAt", version.updatedAt() == null ? "" : version.updatedAt().toString());
                            artifacts.add(new ArtifactObservation(versionArn, "AI_AGENT_VERSION",
                                    "AWS_BEDROCK_AGENT_VERSION",
                                    summary.agentName() + " v" + version.agentVersion(), attributes));
                            relationships.add(new RelationshipObservation(versionArn, agentArn, "VERSION_OF",
                                    Map.of("confidence", "DIRECT", "sourceApi", "ListAgentVersions")));
                        }
                        versionsToken = versions.nextToken();
                    } while (hasText(versionsToken));

                    String aliasesToken = null;
                    do {
                        var aliases = client.listAgentAliases(ListAgentAliasesRequest.builder()
                                .agentId(summary.agentId()).nextToken(aliasesToken).build());
                        for (var alias : aliases.agentAliasSummaries()) {
                            String aliasArn = agentArn + "/alias/" + alias.agentAliasId();
                            List<String> routedVersions = alias.hasRoutingConfiguration()
                                    ? alias.routingConfiguration().stream().map(item -> item.agentVersion())
                                    .filter(this::hasText).toList() : List.of();
                            Map<String, Object> attributes = new LinkedHashMap<>();
                            attributes.put("aliasId", alias.agentAliasId());
                            attributes.put("aliasName", safeValue(alias.agentAliasName()));
                            attributes.put("status", alias.agentAliasStatusAsString());
                            attributes.put("invocationState", alias.aliasInvocationStateAsString());
                            attributes.put("routedVersions", routedVersions);
                            attributes.put("deployedArtifact", true);
                            artifacts.add(new ArtifactObservation(aliasArn, "AI_COMPONENT",
                                    "AWS_BEDROCK_AGENT_ALIAS", safeValue(alias.agentAliasName()), attributes));
                            relationships.add(new RelationshipObservation(agentArn, aliasArn, "HAS_COMPONENT",
                                    Map.of("confidence", "DIRECT", "evidence", Map.of(
                                            "sourceApi", "ListAgentAliases", "field", "agentId"))));
                            for (String version : routedVersions) {
                                relationships.add(new RelationshipObservation(aliasArn,
                                        agentArn + "/version/" + version, "SERVES_VERSION",
                                        Map.of("confidence", "DIRECT", "evidence", Map.of(
                                                "sourceApi", "ListAgentAliases",
                                                "field", "routingConfiguration.agentVersion"))));
                            }
                        }
                        aliasesToken = aliases.nextToken();
                    } while (hasText(aliasesToken));
                }
                agentsToken = agents.nextToken();
            } while (hasText(agentsToken));
            scopes.add(complete("BEDROCK_AGENT_ROUTES", artifacts, relationships));
        } catch (Exception ex) {
            scopes.add(failed("BEDROCK_AGENT_ROUTES", ex, List.of(
                    "bedrock:ListAgents", "bedrock:ListAgentVersions", "bedrock:ListAgentAliases")));
        }
    }

    private void addVersionModelAndGuardrailArtifacts(
            ConnectorSecret config,
            Region region,
            String versionArn,
            software.amazon.awssdk.services.bedrockagent.model.AgentVersion version,
            List<ArtifactObservation> artifacts,
            List<RelationshipObservation> relationships) {
        if (version == null) return;
        if (hasText(version.foundationModel())) {
            String modelId = version.foundationModel();
            String modelResourceId = modelId.startsWith("arn:")
                    ? modelId : "bedrock:model:" + region.id() + ":" + modelId;
            artifacts.add(new ArtifactObservation(modelResourceId, "AI_MODEL", "AWS_BEDROCK_MODEL", modelId,
                    Map.of("referencedBy", "agentVersion")));
            relationships.add(new RelationshipObservation(versionArn, modelResourceId, "USES_MODEL",
                    Map.of("confidence", "DIRECT", "evidence", Map.of(
                            "sourceApi", "GetAgentVersion", "field", "foundationModel"))));
        }
        if (version.guardrailConfiguration() != null
                && hasText(version.guardrailConfiguration().guardrailIdentifier())) {
            String guardrailId = version.guardrailConfiguration().guardrailIdentifier();
            String guardrailArn = guardrailId.startsWith("arn:")
                    ? guardrailId : arn(config, region, "guardrail/" + guardrailId);
            Map<String, Object> guardrailAttributes = new LinkedHashMap<>();
            guardrailAttributes.put("version", safeValue(version.guardrailConfiguration().guardrailVersion()));
            artifacts.add(new ArtifactObservation(guardrailArn, "AI_GUARDRAIL", "AWS_BEDROCK_GUARDRAIL",
                    guardrailId, guardrailAttributes));
            relationships.add(new RelationshipObservation(versionArn, guardrailArn, "USES_GUARDRAIL",
                    Map.of("confidence", "DIRECT", "evidence", Map.of(
                            "sourceApi", "GetAgentVersion", "field", "guardrailConfiguration"),
                            "guardrailVersion", safeValue(version.guardrailConfiguration().guardrailVersion()))));
        }
    }

    private void addVersionToolArtifacts(
            BedrockAgentClient client, String agentId, String agentVersion, String versionArn,
            List<ArtifactObservation> artifacts, List<RelationshipObservation> relationships) {
        String token = null;
        do {
            var page = client.listAgentActionGroups(ListAgentActionGroupsRequest.builder()
                    .agentId(agentId).agentVersion(agentVersion).nextToken(token).build());
            for (var summary : page.actionGroupSummaries()) {
                var detail = client.getAgentActionGroup(GetAgentActionGroupRequest.builder()
                        .agentId(agentId).agentVersion(agentVersion)
                        .actionGroupId(summary.actionGroupId()).build()).agentActionGroup();
                String toolId = versionArn + "/tool/" + summary.actionGroupId();
                String lambdaArn = detail.actionGroupExecutor() == null
                        ? "" : safeValue(detail.actionGroupExecutor().lambda());
                Map<String, Object> attributes = new LinkedHashMap<>();
                attributes.put("actionGroupId", summary.actionGroupId());
                attributes.put("state", summary.actionGroupStateAsString());
                attributes.put("signature", safeValue(detail.parentActionSignatureAsString()));
                attributes.put("lambdaArn", lambdaArn);
                attributes.put("definitionBodyStored", false);
                artifacts.add(new ArtifactObservation(toolId, "AI_TOOL", "AWS_BEDROCK_ACTION_GROUP",
                        safeValue(summary.actionGroupName()), attributes));
                relationships.add(new RelationshipObservation(versionArn, toolId, "USES_TOOL",
                        Map.of("confidence", "DIRECT", "sourceApi", "GetAgentActionGroup")));
                if (hasText(lambdaArn)) {
                    artifacts.add(new ArtifactObservation(lambdaArn, "SUPPORTING_RESOURCE", "AWS_LAMBDA_FUNCTION",
                            functionName(lambdaArn), Map.of("lambdaArn", lambdaArn)));
                    relationships.add(new RelationshipObservation(toolId, lambdaArn, "IMPLEMENTED_BY",
                            Map.of("confidence", "DIRECT", "evidence", Map.of(
                                    "sourceApi", "GetAgentActionGroup",
                                    "field", "actionGroupExecutor.lambda"))));
                }
            }
            token = page.nextToken();
        } while (hasText(token));
    }

    /** Stores prompt structure and a digest only; prompt bodies are never persisted. */
    private void addVersionPromptArtifacts(
            Tenant tenant,
            String versionArn,
            software.amazon.awssdk.services.bedrockagent.model.AgentVersion version,
            List<ArtifactObservation> artifacts,
            List<RelationshipObservation> relationships) {
        if (version == null) return;
        if (hasText(version.instruction())) {
            String promptId = versionArn + "/prompt/instruction";
            AiSecurityDigestService.Digest digest = digestService.digest(
                    tenant, "AWS_AGENT_INSTRUCTION", version.instruction());
            artifacts.add(new ArtifactObservation(promptId, "AI_PROMPT", "AWS_BEDROCK_AGENT_INSTRUCTION",
                    "Agent instruction", Map.of("promptType", "INSTRUCTION",
                            "promptDigest", digest.value(), "digestAlgorithm", digest.algorithm(),
                            "digestKeyVersion", digest.keyVersion(), "promptLength", version.instruction().length(),
                            "bodyStored", false)));
            relationships.add(new RelationshipObservation(versionArn, promptId, "USES_PROMPT",
                    Map.of("confidence", "DIRECT", "sourceApi", "GetAgentVersion", "field", "instruction")));
        }
        var overrides = version.promptOverrideConfiguration();
        if (overrides == null || !overrides.hasPromptConfigurations()) return;
        for (var prompt : overrides.promptConfigurations()) {
            String type = safeValue(prompt.promptTypeAsString());
            String promptId = versionArn + "/prompt/" + type.toLowerCase(Locale.ROOT);
            Map<String, Object> attributes = new LinkedHashMap<>();
            attributes.put("promptType", type);
            attributes.put("creationMode", safeValue(prompt.promptCreationModeAsString()));
            attributes.put("state", safeValue(prompt.promptStateAsString()));
            attributes.put("foundationModel", safeValue(prompt.foundationModel()));
            attributes.put("bodyStored", false);
            if (hasText(prompt.basePromptTemplate())) {
                AiSecurityDigestService.Digest digest = digestService.digest(
                        tenant, "AWS_AGENT_PROMPT:" + type, prompt.basePromptTemplate());
                attributes.put("promptDigest", digest.value());
                attributes.put("digestAlgorithm", digest.algorithm());
                attributes.put("digestKeyVersion", digest.keyVersion());
                attributes.put("promptLength", prompt.basePromptTemplate().length());
            }
            artifacts.add(new ArtifactObservation(promptId, "AI_PROMPT", "AWS_BEDROCK_AGENT_PROMPT",
                    "Agent prompt " + type, attributes));
            relationships.add(new RelationshipObservation(versionArn, promptId, "USES_PROMPT",
                    Map.of("confidence", "DIRECT", "sourceApi", "GetAgentVersion",
                            "field", "promptOverrideConfiguration.promptConfigurations")));
        }
    }

    private void collectIam(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            AgentContext agents,
            Map<String, List<String>> securityCorrelationVersions,
            boolean identityGraphAllowed,
            List<ScopePayload> scopes
    ) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        List<Diagnostic> diagnostics = new ArrayList<>();
        try (IamClient iam = IamClient.builder().region(Region.AWS_GLOBAL).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            for (AgentFact agent : agents.facts().values()) {
                if (!hasText(agent.roleArn())) {
                    continue;
                }
                try {
                    Map<String, Object> roleFacts = rolePolicyFacts(iam, agent.roleArn(), config.accountId());
                    if (identityGraphAllowed) {
                        artifacts.add(new ArtifactObservation(agent.roleArn(), "SUPPORTING_RESOURCE", "AWS_IAM_ROLE",
                                roleName(agent.roleArn()), roleFacts));
                        for (String version : securityCorrelationVersions.getOrDefault(agent.id(), List.of())) {
                            relationships.add(new RelationshipObservation(
                                    agent.arn() + "/version/" + version, agent.roleArn(), "ASSUMES_ROLE",
                                    Map.of("confidence", "DIRECT", "evidence", Map.of(
                                            "sourceApi", "Bedrock GetAgentVersion",
                                            "field", "agentResourceRoleArn"),
                                            "deploymentStage", "DRAFT".equalsIgnoreCase(version)
                                                    ? "PRE_DEPLOYMENT" : "SERVED")));
                        }
                    }
                } catch (Exception ex) {
                    diagnostics.add(new Diagnostic("IAM_ROLE_EVIDENCE_PARTIAL",
                            "IAM evidence was unavailable for one execution role", false,
                            List.of("iam:GetRole", "iam:ListAttachedRolePolicies", "iam:GetPolicy",
                                    "iam:GetPolicyVersion", "iam:ListRolePolicies", "iam:GetRolePolicy"),
                            sha256(agent.roleArn()).substring(0, 16)));
                }
            }
            scopes.add(new ScopePayload("IAM_GLOBAL", true,
                    diagnostics.isEmpty() ? ScopeStatus.COMPLETE : ScopeStatus.PARTIAL,
                    artifacts, relationships, List.copyOf(diagnostics)));
        } catch (Exception ex) {
            scopes.add(failedGlobal("IAM_GLOBAL", ex, List.of(
                    "iam:GetRole", "iam:ListAttachedRolePolicies", "iam:GetPolicy",
                    "iam:GetPolicyVersion", "iam:ListRolePolicies", "iam:GetRolePolicy")));
        }
    }

    private void collectLambdaUrls(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            AgentContext agents,
            Map<String, List<String>> securityCorrelationVersions,
            List<ScopePayload> scopes
    ) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        try (BedrockAgentClient bedrock = BedrockAgentClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build();
             LambdaClient lambda = LambdaClient.builder()
                     .region(region).credentialsProvider(credentials)
                     .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            for (AgentFact agent : agents.facts().values()) {
                List<String> lambdaArns = new ArrayList<>();
                for (String version : securityCorrelationVersions.getOrDefault(agent.id(), List.of())) {
                    lambdaArns.addAll(actionGroupLambdas(bedrock, agent.id(), version));
                }
                for (String lambdaArn : lambdaArns) {
                    String authType;
                    try {
                        authType = lambda.getFunctionUrlConfig(GetFunctionUrlConfigRequest.builder()
                                .functionName(functionName(lambdaArn)).build()).authTypeAsString();
                    } catch (ResourceNotFoundException ex) {
                        authType = "ABSENT";
                    }
                    artifacts.add(new ArtifactObservation(
                            lambdaArn, "SUPPORTING_RESOURCE", "AWS_LAMBDA_FUNCTION", functionName(lambdaArn),
                            Map.of("functionUrlAuthType", authType, "lambdaArn", lambdaArn)));
                }
            }
            scopes.add(complete("LAMBDA_URLS", artifacts, List.of()));
        } catch (Exception ex) {
            scopes.add(failed("LAMBDA_URLS", ex, List.of(
                    "bedrock:ListAgentActionGroups", "bedrock:GetAgentActionGroup",
                    "lambda:GetFunctionUrlConfig")));
        }
    }

    private void collectKnowledgeBases(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            AgentContext agents,
            Map<String, List<String>> securityCorrelationVersions,
            List<ScopePayload> scopes
    ) {
        List<ArtifactObservation> kbArtifacts = new ArrayList<>();
        List<ArtifactObservation> dataSourceArtifacts = new ArrayList<>();
        List<ArtifactObservation> dataStoreArtifacts = new ArrayList<>();
        List<ArtifactObservation> exposureArtifacts = new ArrayList<>();
        List<RelationshipObservation> knowledgeRelationships = new ArrayList<>();
        List<RelationshipObservation> dataSourceRelationships = new ArrayList<>();
        List<RelationshipObservation> dataStoreRelationships = new ArrayList<>();
        try (BedrockAgentClient bedrock = BedrockAgentClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build();
             S3Client s3 = S3Client.builder().region(region).credentialsProvider(credentials)
                     .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build();
             Macie2Client macie = Macie2Client.builder().region(region).credentialsProvider(credentials)
                     .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            String token = null;
            do {
                var response = bedrock.listKnowledgeBases(ListKnowledgeBasesRequest.builder().nextToken(token).build());
                for (var summary : response.knowledgeBaseSummaries()) {
                    String kbArn = arn(config, region, "knowledge-base/" + summary.knowledgeBaseId());
                    boolean anyPublic = false;
                    List<String> buckets = new ArrayList<>();
                    int dataSourceCount = 0;
                    String dataToken = null;
                    do {
                        var dataSources = bedrock.listDataSources(ListDataSourcesRequest.builder()
                                .knowledgeBaseId(summary.knowledgeBaseId()).nextToken(dataToken).build());
                        dataSourceCount += dataSources.dataSourceSummaries().size();
                        for (var source : dataSources.dataSourceSummaries()) {
                            var detail = bedrock.getDataSource(GetDataSourceRequest.builder()
                                    .knowledgeBaseId(summary.knowledgeBaseId())
                                    .dataSourceId(source.dataSourceId()).build()).dataSource();
                            String dataSourceId = kbArn + "/data-source/" + source.dataSourceId();
                            Map<String, Object> sourceAttributes = new LinkedHashMap<>();
                            sourceAttributes.put("sourceType", detail.dataSourceConfiguration() == null
                                    ? "UNKNOWN" : detail.dataSourceConfiguration().typeAsString());
                            sourceAttributes.put("status", detail.statusAsString());
                            sourceAttributes.put("deletionPolicy", detail.dataDeletionPolicyAsString());
                            sourceAttributes.put("ingestionConfigurationPresent",
                                    detail.dataSourceConfiguration() != null);
                            dataSourceArtifacts.add(new ArtifactObservation(
                                    dataSourceId, "DATA_SOURCE", "AWS_BEDROCK_DATA_SOURCE",
                                    source.name() == null ? source.dataSourceId() : source.name(), sourceAttributes));
                            dataSourceRelationships.add(new RelationshipObservation(
                                    kbArn, dataSourceId, "USES_DATA_SOURCE", Map.of(
                                    "confidence", "DIRECT", "evidence", Map.of(
                                    "sourceApi", "Bedrock GetDataSource", "field", "knowledgeBaseId"))));
                            if (detail.dataSourceConfiguration() != null
                                    && detail.dataSourceConfiguration().s3Configuration() != null) {
                                String bucketArn = detail.dataSourceConfiguration().s3Configuration().bucketArn();
                                String bucketName = bucketArn.substring(bucketArn.lastIndexOf(':') + 1);
                                boolean isPublic = isBucketPublic(s3, bucketName);
                                anyPublic |= isPublic;
                                buckets.add(bucketArn);
                                var pii = maciePiiEnabled
                                        ? maciePiiLookupService.lookup(macie, bucketName)
                                        : new AwsMaciePiiLookupService.PiiLookupResult("NOT_SCANNED", null, List.of(), 0, null);
                                exposureArtifacts.add(new ArtifactObservation(
                                        bucketArn, "SUPPORTING_RESOURCE", "AWS_S3_BUCKET", bucketName,
                                        Map.of("public", isPublic),
                                        pii.status(), pii.source(), pii.infoTypes(), pii.findingCount(), pii.lastScannedAt()));
                                dataStoreArtifacts.add(new ArtifactObservation(
                                        bucketArn, "DATA_STORE", "AWS_S3_BUCKET", bucketName,
                                        Map.of("storeType", "S3", "publicContentAccess", isPublic),
                                        pii.status(), pii.source(), pii.infoTypes(), pii.findingCount(), pii.lastScannedAt()));
                                dataStoreRelationships.add(new RelationshipObservation(
                                        dataSourceId, bucketArn, "BACKED_BY_DATA_STORE", Map.of(
                                        "confidence", "DIRECT", "evidence", Map.of(
                                        "sourceApi", "Bedrock GetDataSource", "field", "s3Configuration.bucketArn"))));
                            }
                        }
                        dataToken = dataSources.nextToken();
                    } while (hasText(dataToken));
                    Map<String, Object> attributes = new LinkedHashMap<>();
                    attributes.put("status", summary.statusAsString());
                    attributes.put("s3Public", anyPublic);
                    attributes.put("s3Buckets", buckets);
                    attributes.put("dataSourceCount", dataSourceCount);
                    kbArtifacts.add(new ArtifactObservation(
                            kbArn, "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", summary.name(), attributes));
                }
                token = response.nextToken();
            } while (hasText(token));

            for (AgentFact agent : agents.facts().values()) {
                for (String version : securityCorrelationVersions.getOrDefault(agent.id(), List.of())) {
                    var versionKnowledgeBases = bedrock.listAgentKnowledgeBases(ListAgentKnowledgeBasesRequest.builder()
                            .agentId(agent.id()).agentVersion(version).build()).agentKnowledgeBaseSummaries();
                    for (var kb : versionKnowledgeBases) {
                        knowledgeRelationships.add(new RelationshipObservation(
                                agent.arn() + "/version/" + version,
                                arn(config, region, "knowledge-base/" + kb.knowledgeBaseId()),
                                "USES_KNOWLEDGE_BASE", Map.of("confidence", "DIRECT", "evidence", Map.of(
                                        "sourceApi", "ListAgentKnowledgeBases",
                                        "field", "agentVersion+knowledgeBaseId"),
                                        "deploymentStage", "DRAFT".equalsIgnoreCase(version)
                                                ? "PRE_DEPLOYMENT" : "SERVED")));
                    }
                }
            }
            scopes.add(complete("BEDROCK_KNOWLEDGE_BASES", kbArtifacts, knowledgeRelationships));
            scopes.add(complete("BEDROCK_DATA_SOURCES", dataSourceArtifacts, dataSourceRelationships));
            scopes.add(complete("BEDROCK_DATA_STORES", dataStoreArtifacts, dataStoreRelationships));
            scopes.add(complete("S3_EXPOSURE", exposureArtifacts, List.of()));
            if (maciePiiEnabled) {
                scopes.add(complete("AWS_MACIE_PII", List.of(), List.of()));
            }
        } catch (Exception ex) {
            scopes.add(failed("BEDROCK_KNOWLEDGE_BASES", ex, List.of(
                    "bedrock:ListKnowledgeBases", "bedrock:ListDataSources", "bedrock:GetDataSource")));
            scopes.add(failed("BEDROCK_DATA_SOURCES", ex, List.of("bedrock:ListDataSources", "bedrock:GetDataSource")));
            scopes.add(failed("BEDROCK_DATA_STORES", ex, List.of("bedrock:GetDataSource")));
            scopes.add(failed("S3_EXPOSURE", ex, List.of("s3:GetBucketPolicyStatus")));
            if (maciePiiEnabled) {
                scopes.add(failed("AWS_MACIE_PII", ex, List.of(
                        "macie2:GetMacieSession", "macie2:ListFindings", "macie2:GetFindings")));
            }
        }
    }

    /** AgentCore control-plane inventory. It deliberately does not contact gateway or target endpoints. */
    private void collectAgentCoreGateways(
            ConnectorSecret config, AwsCredentialsProvider credentials, Region region, List<ScopePayload> scopes
    ) {
        List<ArtifactObservation> gateways = new ArrayList<>();
        List<ArtifactObservation> targets = new ArrayList<>();
        List<ArtifactObservation> servers = new ArrayList<>();
        List<RelationshipObservation> targetRelationships = new ArrayList<>();
        try (BedrockAgentCoreControlClient client = BedrockAgentCoreControlClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            String gatewayToken = null;
            do {
                var page = client.listGateways(ListGatewaysRequest.builder().nextToken(gatewayToken).build());
                for (var summary : page.items()) {
                    var gateway = client.getGateway(GetGatewayRequest.builder().gatewayIdentifier(summary.gatewayId()).build());
                    String gatewayId = gateway.gatewayArn() == null ? arn(config, region, "gateway/" + summary.gatewayId()) : gateway.gatewayArn();
                    Map<String, Object> attributes = new LinkedHashMap<>();
                    attributes.put("status", gateway.statusAsString());
                    attributes.put("protocol", gateway.protocolTypeAsString());
                    attributes.put("inboundAuthType", gateway.authorizerTypeAsString());
                    attributes.put("endpointHost", httpsAuthority(gateway.gatewayUrl()));
                    gateways.add(new ArtifactObservation(gatewayId, "MCP_GATEWAY", "AWS_AGENTCORE_GATEWAY",
                            gateway.name() == null ? summary.gatewayId() : gateway.name(), attributes));
                    String targetToken = null;
                    do {
                        var targetPage = client.listGatewayTargets(ListGatewayTargetsRequest.builder()
                                .gatewayIdentifier(summary.gatewayId()).nextToken(targetToken).build());
                        for (var targetSummary : targetPage.items()) {
                            var target = client.getGatewayTarget(GetGatewayTargetRequest.builder()
                                    .gatewayIdentifier(summary.gatewayId()).targetId(targetSummary.targetId()).build());
                            String targetId = gatewayId + "/target/" + target.targetId();
                            String subtype = target.targetConfiguration() == null || target.targetConfiguration().type() == null
                                    ? "UNKNOWN" : target.targetConfiguration().type().toString();
                            Map<String, Object> targetAttributes = new LinkedHashMap<>();
                            targetAttributes.put("status", target.statusAsString());
                            targetAttributes.put("configurationSubtype", subtype);
                            targetAttributes.put("lastSynchronizedAt", target.lastSynchronizedAt() == null
                                    ? null : target.lastSynchronizedAt().toString());
                            targetAttributes.put("outboundAuthType", target.hasCredentialProviderConfigurations()
                                    ? target.credentialProviderConfigurations().stream().findFirst()
                                    .map(value -> value.credentialProviderTypeAsString()).orElse("UNKNOWN") : "NONE");
                            targets.add(new ArtifactObservation(targetId, "MCP_TARGET", "AWS_AGENTCORE_GATEWAY_TARGET",
                                    target.name() == null ? target.targetId() : target.name(), targetAttributes));
                            targetRelationships.add(new RelationshipObservation(gatewayId, targetId, "CONTAINS_MCP_TARGET", Map.of(
                                    "confidence", "DIRECT", "evidence", Map.of("sourceApi", "AgentCore GetGatewayTarget", "field", "gatewayArn"))));
                            String endpoint = target.targetConfiguration() == null || target.targetConfiguration().mcp() == null
                                    || target.targetConfiguration().mcp().mcpServer() == null ? null
                                    : httpsAuthority(target.targetConfiguration().mcp().mcpServer().endpoint());
                            if (endpoint != null) {
                                String serverId = targetId + "/mcp-server/" + sha256(endpoint).substring(0, 24);
                                servers.add(new ArtifactObservation(serverId, "MCP_SERVER", "AWS_AGENTCORE_MCP_SERVER", endpoint,
                                        Map.of("endpointHost", endpoint, "endpointExposure", "EXTERNAL_ENDPOINT")));
                                targetRelationships.add(new RelationshipObservation(targetId, serverId, "ROUTES_TO", Map.of(
                                        "confidence", "DIRECT", "evidence", Map.of("sourceApi", "AgentCore GetGatewayTarget", "field", "targetConfiguration.mcp.mcpServer.endpoint"))));
                            }
                        }
                        targetToken = targetPage.nextToken();
                    } while (hasText(targetToken));
                }
                gatewayToken = page.nextToken();
            } while (hasText(gatewayToken));
            scopes.add(complete("AWS_AGENTCORE_GATEWAYS", gateways, List.of()));
            scopes.add(complete("AWS_AGENTCORE_GATEWAY_TARGETS", concat(targets, servers), targetRelationships));
        } catch (Exception ex) {
            scopes.add(failed("AWS_AGENTCORE_GATEWAYS", ex, List.of("bedrock-agentcore:ListGateways", "bedrock-agentcore:GetGateway")));
            scopes.add(failed("AWS_AGENTCORE_GATEWAY_TARGETS", ex, List.of("bedrock-agentcore:ListGatewayTargets", "bedrock-agentcore:GetGatewayTarget")));
        }
    }

    /** Inventory AgentCore managed runtimes and built-in tools without inferring ownership edges. */
    private void collectAgentCoreUtilities(
            ConnectorSecret config, AwsCredentialsProvider credentials, Region region,
            List<ScopePayload> scopes) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        try (BedrockAgentCoreControlClient client = BedrockAgentCoreControlClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            String token = null;
            do {
                var page = client.listAgentRuntimes(ListAgentRuntimesRequest.builder().nextToken(token).build());
                for (var runtime : page.agentRuntimes()) {
                    boolean stableRuntimeArn = hasText(runtime.agentRuntimeArn());
                    String runtimeId = stableRuntimeArn
                            ? runtime.agentRuntimeArn() : arn(config, region, "runtime/" + runtime.agentRuntimeId());
                    int relationshipStart = relationships.size();
                    var detail = client.getAgentRuntime(GetAgentRuntimeRequest.builder()
                            .agentRuntimeId(runtime.agentRuntimeId()).build());
                    if (hasText(detail.roleArn())) {
                        artifacts.add(new ArtifactObservation(detail.roleArn(), "SUPPORTING_RESOURCE", "AWS_IAM_ROLE",
                                roleName(detail.roleArn()), Map.of("roleArn", detail.roleArn())));
                        relationships.add(direct(runtimeId, detail.roleArn(), "ASSUMES_ROLE",
                                "GetAgentRuntime", "roleArn"));
                    }
                    if (detail.workloadIdentityDetails() != null
                            && hasText(detail.workloadIdentityDetails().workloadIdentityArn())) {
                        String identityArn = detail.workloadIdentityDetails().workloadIdentityArn();
                        artifacts.add(new ArtifactObservation(identityArn, "SUPPORTING_RESOURCE",
                                "AWS_AGENTCORE_WORKLOAD_IDENTITY", identityArn,
                                Map.of("providerNativeId", identityArn)));
                        relationships.add(direct(runtimeId, identityArn, "USES_EXECUTION_ROLE",
                                "GetAgentRuntime", "workloadIdentityDetails.workloadIdentityArn"));
                    }
                    String versionToken = null;
                    do {
                        var versions = client.listAgentRuntimeVersions(ListAgentRuntimeVersionsRequest.builder()
                                .agentRuntimeId(runtime.agentRuntimeId()).nextToken(versionToken).build());
                        for (var version : versions.agentRuntimes()) {
                            String versionId = runtimeId + "/version/" + version.agentRuntimeVersion();
                            artifacts.add(new ArtifactObservation(versionId, "AI_COMPONENT",
                                    "AWS_AGENTCORE_RUNTIME_VERSION", safeValue(version.agentRuntimeName()), Map.of(
                                    "providerNativeId", safeValue(version.agentRuntimeId()),
                                    "version", safeValue(version.agentRuntimeVersion()),
                                    "status", safeValue(version.statusAsString()), "deployedArtifact", true)));
                            relationships.add(new RelationshipObservation(versionId, runtimeId, "VERSION_OF",
                                    Map.of("confidence", "DIRECT", "sourceApi", "ListAgentRuntimeVersions")));
                        }
                        versionToken = versions.nextToken();
                    } while (hasText(versionToken));
                    String endpointToken = null;
                    do {
                        var endpoints = client.listAgentRuntimeEndpoints(ListAgentRuntimeEndpointsRequest.builder()
                                .agentRuntimeId(runtime.agentRuntimeId()).nextToken(endpointToken).build());
                        for (var endpoint : endpoints.runtimeEndpoints()) {
                            String endpointId = hasText(endpoint.agentRuntimeEndpointArn())
                                    ? endpoint.agentRuntimeEndpointArn() : runtimeId + "/endpoint/" + endpoint.id();
                            artifacts.add(new ArtifactObservation(endpointId, "AI_COMPONENT",
                                    "AWS_AGENTCORE_RUNTIME_ENDPOINT", safeValue(endpoint.name()), Map.of(
                                    "providerNativeId", safeValue(endpoint.id()),
                                    "liveVersion", safeValue(endpoint.liveVersion()),
                                    "targetVersion", safeValue(endpoint.targetVersion()),
                                    "status", safeValue(endpoint.statusAsString()),
                                    "deployedArtifact", true)));
                            relationships.add(direct(runtimeId, endpointId, "HAS_DEPLOYMENT",
                                    "ListAgentRuntimeEndpoints", "agentRuntimeArn"));
                            if (hasText(endpoint.liveVersion())) {
                                relationships.add(direct(endpointId,
                                        runtimeId + "/version/" + endpoint.liveVersion(), "SERVES_VERSION",
                                        "ListAgentRuntimeEndpoints", "liveVersion"));
                            }
                        }
                        endpointToken = endpoints.nextToken();
                    } while (hasText(endpointToken));
                    boolean stableMembership = relationships.subList(relationshipStart, relationships.size()).stream()
                            .anyMatch(edge -> runtimeId.equals(edge.sourceProviderResourceId())
                                    && AiGridRelationshipSemantics.SYSTEM_MEMBERSHIP_RELATIONSHIPS
                                    .contains(edge.relationshipType()));
                    artifacts.add(new ArtifactObservation(runtimeId, "AI_COMPONENT", "AWS_AGENTCORE_RUNTIME",
                            safeValue(runtime.agentRuntimeName()), Map.of(
                                    "providerNativeId", safeValue(runtime.agentRuntimeId()),
                                    "version", safeValue(runtime.agentRuntimeVersion()),
                                    "status", safeValue(runtime.statusAsString()),
                                    "deployedArtifact", true,
                                    "stableRuntimeArnObserved", stableRuntimeArn,
                                    "authoritativeWorkloadBoundaryObserved", true,
                                    "stableMembershipObserved", stableMembership,
                                    "agentCoreRootQualified", stableRuntimeArn && stableMembership)));
                }
                token = page.nextToken();
            } while (hasText(token));
            scopes.add(complete("AWS_AGENTCORE_RUNTIMES", artifacts, relationships));

            collectAgentCoreToolScope("AWS_AGENTCORE_BROWSERS", "bedrock-agentcore:ListBrowsers",
                    () -> listAgentCoreBrowsers(client), scopes);
            collectAgentCoreToolScope("AWS_AGENTCORE_CODE_INTERPRETERS", "bedrock-agentcore:ListCodeInterpreters",
                    () -> listAgentCoreCodeInterpreters(client), scopes);
            collectAgentCoreToolScope("AWS_AGENTCORE_MEMORIES", "bedrock-agentcore:ListMemories",
                    () -> listAgentCoreMemories(client), scopes);
        } catch (Exception ex) {
            scopes.add(failed("AWS_AGENTCORE_RUNTIMES", ex, List.of(
                    "bedrock-agentcore:ListAgentRuntimes", "bedrock-agentcore:GetAgentRuntime",
                    "bedrock-agentcore:ListAgentRuntimeVersions", "bedrock-agentcore:ListAgentRuntimeEndpoints")));
            scopes.add(failed("AWS_AGENTCORE_BROWSERS", ex, List.of("bedrock-agentcore:ListBrowsers")));
            scopes.add(failed("AWS_AGENTCORE_CODE_INTERPRETERS", ex, List.of("bedrock-agentcore:ListCodeInterpreters")));
            scopes.add(failed("AWS_AGENTCORE_MEMORIES", ex, List.of("bedrock-agentcore:ListMemories")));
        }
    }

    private void collectAgentCoreToolScope(String family, String permission,
                                          java.util.function.Supplier<List<ArtifactObservation>> collector,
                                          List<ScopePayload> scopes) {
        try { scopes.add(complete(family, collector.get(), List.of())); }
        catch (Exception ex) { scopes.add(failed(family, ex, List.of(permission))); }
    }

    private List<ArtifactObservation> listAgentCoreBrowsers(BedrockAgentCoreControlClient client) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        String token = null;
        do {
            var page = client.listBrowsers(ListBrowsersRequest.builder().nextToken(token).build());
            for (var item : page.browserSummaries()) artifacts.add(new ArtifactObservation(item.browserArn(),
                    "AI_TOOL", "AWS_AGENTCORE_BROWSER", safeValue(item.name()), Map.of(
                    "status", safeValue(item.statusAsString()), "browserId", safeValue(item.browserId()))));
            token = page.nextToken();
        } while (hasText(token));
        return artifacts;
    }

    private List<ArtifactObservation> listAgentCoreCodeInterpreters(BedrockAgentCoreControlClient client) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        String token = null;
        do {
            var page = client.listCodeInterpreters(ListCodeInterpretersRequest.builder().nextToken(token).build());
            for (var item : page.codeInterpreterSummaries()) artifacts.add(new ArtifactObservation(item.codeInterpreterArn(),
                    "AI_TOOL", "AWS_AGENTCORE_CODE_INTERPRETER", safeValue(item.name()), Map.of(
                    "status", safeValue(item.statusAsString()), "codeInterpreterId", safeValue(item.codeInterpreterId()))));
            token = page.nextToken();
        } while (hasText(token));
        return artifacts;
    }

    private List<ArtifactObservation> listAgentCoreMemories(BedrockAgentCoreControlClient client) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        String token = null;
        do {
            var page = client.listMemories(ListMemoriesRequest.builder().nextToken(token).build());
            for (var item : page.memories()) artifacts.add(new ArtifactObservation(item.arn(),
                    "AI_COMPONENT", "AWS_AGENTCORE_MEMORY", item.id(), Map.of(
                    "status", safeValue(item.statusAsString()), "memoryId", safeValue(item.id()))));
            token = page.nextToken();
        } while (hasText(token));
        return artifacts;
    }

    private List<ArtifactObservation> concat(List<ArtifactObservation> first, List<ArtifactObservation> second) {
        List<ArtifactObservation> all = new ArrayList<>(first);
        all.addAll(second);
        return all;
    }

    /** Returns only a normalized HTTPS authority; malicious URLs are inert and never fetched. */
    static String httpsAuthority(String value) {
        if (value == null || value.isBlank() || value.length() > 2_048) return null;
        try {
            URI uri = URI.create(value.trim());
            if (!"https".equalsIgnoreCase(uri.getScheme()) || uri.getHost() == null || uri.getUserInfo() != null) return null;
            return uri.getHost().toLowerCase(Locale.ROOT) + (uri.getPort() < 0 ? "" : ":" + uri.getPort());
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }

    private void collectGuardrails(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            AgentContext agents,
            List<ScopePayload> scopes
    ) {
        List<ArtifactObservation> artifacts = new ArrayList<>();
        List<RelationshipObservation> relationships = new ArrayList<>();
        Map<String, String> minimumStrength = new HashMap<>();
        try (BedrockClient bedrock = BedrockClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            String token = null;
            do {
                var response = bedrock.listGuardrails(ListGuardrailsRequest.builder().nextToken(token).build());
                for (var summary : response.guardrails()) {
                    String version = hasText(summary.version()) ? summary.version() : "DRAFT";
                    var detail = bedrock.getGuardrail(GetGuardrailRequest.builder()
                            .guardrailIdentifier(summary.id()).guardrailVersion(version).build());
                    String strength = minimumStrength(detail.contentPolicy() == null
                            ? List.of()
                            : detail.contentPolicy().filters());
                    minimumStrength.put(summary.id(), strength);
                    artifacts.add(new ArtifactObservation(
                            summary.arn(), "AI_GUARDRAIL", "AWS_BEDROCK_GUARDRAIL", summary.name(),
                            guardrailAttributes(detail, strength)));
                }
                token = response.nextToken();
            } while (hasText(token));
            for (AgentFact agent : agents.facts().values()) {
                if (hasText(agent.guardrailId())) {
                    String strength = minimumStrength.get(agent.guardrailId());
                    Map<String, Object> attributes = new LinkedHashMap<>();
                    attributes.put("guardrailAttached", true);
                    if (strength != null) {
                        attributes.put("guardrailMinimumStrength", strength);
                    }
                    artifacts.add(agentUpdate(agent, attributes));
                    String guardrailArn = arn(config, region, "guardrail/" + agent.guardrailId());
                    relationships.add(new RelationshipObservation(
                            agent.arn(), guardrailArn, "USES_GUARDRAIL", Map.of()));
                }
            }
            scopes.add(complete("BEDROCK_GUARDRAILS", artifacts, relationships));
        } catch (Exception ex) {
            scopes.add(failed("BEDROCK_GUARDRAILS", ex, List.of(
                    "bedrock:ListGuardrails", "bedrock:GetGuardrail")));
        }
    }

    private void collectInvocationLogging(
            ConnectorSecret config,
            AwsCredentialsProvider credentials,
            Region region,
            List<ScopePayload> scopes
    ) {
        try (BedrockClient bedrock = BedrockClient.builder()
                .region(region).credentialsProvider(credentials)
                .overrideConfiguration(c -> c.addExecutionInterceptor(providerCallInterceptor)).build()) {
            var response = bedrock.getModelInvocationLoggingConfiguration(
                    GetModelInvocationLoggingConfigurationRequest.builder().build());
            boolean enabled = response.loggingConfig() != null;
            String id = "bedrock:logging:" + config.accountId() + ":" + region.id();
            scopes.add(complete("BEDROCK_INVOCATION_LOGGING", List.of(new ArtifactObservation(
                    id, "ACCOUNT_CONFIGURATION", "AWS_BEDROCK_INVOCATION_LOGGING",
                    "Bedrock invocation logging", Map.of("invocationLoggingEnabled", enabled))), List.of()));
        } catch (Exception ex) {
            scopes.add(failed("BEDROCK_INVOCATION_LOGGING", ex, List.of(
                    "bedrock:GetModelInvocationLoggingConfiguration")));
        }
    }

    private List<String> actionGroupLambdas(BedrockAgentClient client, String agentId, String agentVersion) {
        List<String> arns = new ArrayList<>();
        String token = null;
        do {
            var groups = client.listAgentActionGroups(ListAgentActionGroupsRequest.builder()
                    .agentId(agentId).agentVersion(agentVersion).nextToken(token).build());
            for (var group : groups.actionGroupSummaries()) {
                var detail = client.getAgentActionGroup(GetAgentActionGroupRequest.builder()
                        .agentId(agentId).agentVersion(agentVersion)
                        .actionGroupId(group.actionGroupId()).build()).agentActionGroup();
                if (detail.actionGroupExecutor() != null && hasText(detail.actionGroupExecutor().lambda())) {
                    arns.add(detail.actionGroupExecutor().lambda());
                }
            }
            token = groups.nextToken();
        } while (hasText(token));
        return arns;
    }

    private Map<String, Object> rolePolicyFacts(IamClient iam, String roleArn, String accountId) {
        String roleName = roleArn.substring(roleArn.lastIndexOf('/') + 1);
        List<String> documents = new ArrayList<>();
        String token = null;
        do {
            var attached = iam.listAttachedRolePolicies(ListAttachedRolePoliciesRequest.builder()
                    .roleName(roleName).marker(token).build());
            for (var policyRef : attached.attachedPolicies()) {
                var policy = iam.getPolicy(GetPolicyRequest.builder().policyArn(policyRef.policyArn()).build()).policy();
                documents.add(iam.getPolicyVersion(GetPolicyVersionRequest.builder()
                        .policyArn(policyRef.policyArn()).versionId(policy.defaultVersionId()).build())
                        .policyVersion().document());
            }
            token = attached.marker();
        } while (attachedHasMore(iam, roleName, token));

        String inlineToken = null;
        do {
            var inline = iam.listRolePolicies(ListRolePoliciesRequest.builder()
                    .roleName(roleName).marker(inlineToken).build());
            for (String policyName : inline.policyNames()) {
                documents.add(iam.getRolePolicy(GetRolePolicyRequest.builder()
                        .roleName(roleName).policyName(policyName).build()).policyDocument());
            }
            inlineToken = inline.marker();
            if (!inline.isTruncated()) {
                break;
            }
        } while (hasText(inlineToken));
        PolicyFlags flags = new PolicyFlags();
        documents.forEach(document -> analyzePermissionDocument(document, flags));
        var role = iam.getRole(GetRoleRequest.builder().roleName(roleName).build()).role();
        analyzeTrustDocument(role.assumeRolePolicyDocument(), accountId, flags);
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("roleArn", roleArn);
        facts.put("iamWildcardActions", flags.wildcardActions);
        facts.put("iamWildcardResources", flags.wildcardResources);
        facts.put("iamPassRole", flags.passRole);
        facts.put("iamNotAction", flags.notAction);
        facts.put("iamNotResource", flags.notResource);
        boolean boundaryPresent = role.permissionsBoundary() != null;
        facts.put("permissionBoundaryAttached", boundaryPresent);
        facts.put("permissionBoundaryState", boundaryPresent ? "PRESENT" : "ABSENT");
        facts.put("effectiveAccessEvidenceComplete", true);
        facts.put("crossAccountTrust", flags.crossAccountTrust);
        facts.put("trustConditionsPresent", flags.trustConditionsPresent);
        facts.put("evidenceSource", "IAM role, trust, policy and policy-version APIs");
        return facts;
    }

    private boolean attachedHasMore(IamClient iam, String roleName, String marker) {
        return hasText(marker);
    }

    private void analyzePermissionDocument(String encoded, PolicyFlags flags) {
        try {
            JsonNode document = objectMapper.readTree(URLDecoder.decode(encoded, StandardCharsets.UTF_8));
            JsonNode statements = document.path("Statement");
            List<JsonNode> values = statements.isArray()
                    ? toList(statements)
                    : List.of(statements);
            for (JsonNode statement : values) {
                if (!"Allow".equalsIgnoreCase(statement.path("Effect").asText())) {
                    continue;
                }
                flags.notAction |= statement.has("NotAction");
                flags.notResource |= statement.has("NotResource");
                JsonNode actions = statement.path("Action");
                for (JsonNode action : actions.isArray() ? toList(actions) : List.of(actions)) {
                    String value = action.asText();
                    if ("*".equals(value) || value.endsWith(":*")) {
                        flags.wildcardActions = true;
                    }
                    if ("iam:PassRole".equalsIgnoreCase(value) || "iam:*".equalsIgnoreCase(value)
                            || "*".equals(value)) flags.passRole = true;
                }
                JsonNode resources = statement.path("Resource");
                for (JsonNode resource : resources.isArray() ? toList(resources) : List.of(resources))
                    if ("*".equals(resource.asText())) flags.wildcardResources = true;
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to resolve IAM policy evidence", ex);
        }
    }

    private void analyzeTrustDocument(String encoded, String accountId, PolicyFlags flags) {
        try {
            JsonNode document = objectMapper.readTree(URLDecoder.decode(encoded, StandardCharsets.UTF_8));
            JsonNode statements = document.path("Statement");
            for (JsonNode statement : statements.isArray() ? toList(statements) : List.of(statements)) {
                flags.trustConditionsPresent |= statement.has("Condition") && !statement.path("Condition").isEmpty();
                JsonNode aws = statement.path("Principal").path("AWS");
                for (JsonNode principal : aws.isArray() ? toList(aws) : List.of(aws)) {
                    String value = principal.asText();
                    if (hasText(value) && ("*".equals(value)
                            || (value.startsWith("arn:aws:iam::") && !value.contains("::" + accountId + ":")))) {
                        flags.crossAccountTrust = true;
                    }
                }
            }
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to resolve IAM trust evidence", ex);
        }
    }

    private static final class PolicyFlags {
        private boolean wildcardActions;
        private boolean wildcardResources;
        private boolean passRole;
        private boolean notAction;
        private boolean notResource;
        private boolean crossAccountTrust;
        private boolean trustConditionsPresent;
    }

    private boolean isBucketPublic(S3Client s3, String bucketName) {
        try {
            return Boolean.TRUE.equals(s3.getBucketPolicyStatus(GetBucketPolicyStatusRequest.builder()
                    .bucket(bucketName).build()).policyStatus().isPublic());
        } catch (software.amazon.awssdk.services.s3.model.S3Exception ex) {
            String code = ex.awsErrorDetails() == null ? "" : ex.awsErrorDetails().errorCode();
            if (ex.statusCode() == 404 || "NoSuchBucketPolicy".equals(code)) {
                return false;
            }
            throw ex;
        }
    }

    /** Captures the bounded structural GetGuardrail metadata — content filters, denied
     *  topics, word/profanity filters, PII/sensitive-info entities, contextual grounding filters,
     *  topics, filter counts, and KMS key — instead of just the status/minimumStrength scalar summary,
     *  so the AI asset detail page's Observed Facts panel (a generic renderer over this map) shows
     *  the real guardrail configuration rather than two fields. */
    Map<String, Object> guardrailAttributes(GetGuardrailResponse detail, String strength) {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put("status", detail.statusAsString());
        attributes.put("minimumStrength", strength);
        if (hasText(detail.version())) {
            attributes.put("version", detail.version());
        }
        if (detail.createdAt() != null) {
            attributes.put("createdAt", detail.createdAt().toString());
        }
        if (detail.updatedAt() != null) {
            attributes.put("updatedAt", detail.updatedAt().toString());
        }
        attributes.put("kmsKeyArn", safeValue(detail.kmsKeyArn()));
        List<GuardrailContentFilter> contentFilters = detail.contentPolicy() == null
                ? List.of() : detail.contentPolicy().filters();
        attributes.put("contentFilterCount", contentFilters == null ? 0 : contentFilters.size());
        if (contentFilters != null && !contentFilters.isEmpty()) {
            attributes.put("contentFilters", contentFilters.stream()
                    .map(f -> entryMap(
                            "type", f.typeAsString(),
                            "inputStrength", f.inputStrengthAsString(),
                            "outputStrength", f.outputStrengthAsString(),
                            "inputEnabled", f.inputEnabled(),
                            "outputEnabled", f.outputEnabled()))
                    .toList());
        }

        List<GuardrailTopic> deniedTopics = detail.topicPolicy() == null
                ? List.of() : detail.topicPolicy().topics();
        attributes.put("deniedTopicCount", deniedTopics == null ? 0 : deniedTopics.size());
        if (deniedTopics != null && !deniedTopics.isEmpty()) {
            attributes.put("deniedTopics", deniedTopics.stream()
                    .map(t -> entryMap(
                            "name", t.name(),
                            "inputAction", t.inputActionAsString(),
                            "outputAction", t.outputActionAsString()))
                    .toList());
        }

        if (detail.wordPolicy() != null) {
            List<GuardrailWord> words = detail.wordPolicy().words();
            if (words != null && !words.isEmpty()) {
                attributes.put("customWordFilterCount", words.size());
            }
            List<GuardrailManagedWords> managedWordLists = detail.wordPolicy().managedWordLists();
            if (managedWordLists != null && !managedWordLists.isEmpty()) {
                attributes.put("profanityFilterEnabled", true);
            }
        }

        attributes.put("piiEntityCount", detail.sensitiveInformationPolicy() == null
                || detail.sensitiveInformationPolicy().piiEntities() == null
                ? 0 : detail.sensitiveInformationPolicy().piiEntities().size());
        if (detail.sensitiveInformationPolicy() != null) {
            List<GuardrailPiiEntity> piiEntities = detail.sensitiveInformationPolicy().piiEntities();
            if (piiEntities != null && !piiEntities.isEmpty()) {
                attributes.put("piiEntities", piiEntities.stream()
                        .map(e -> entryMap(
                                "type", e.typeAsString(),
                                "inputAction", e.inputActionAsString(),
                                "outputAction", e.outputActionAsString()))
                        .toList());
            }
            List<GuardrailRegex> regexes = detail.sensitiveInformationPolicy().regexes();
            if (regexes != null && !regexes.isEmpty()) {
                attributes.put("sensitiveRegexCount", regexes.size());
            }
        }

        attributes.put("contextualGroundingFilterCount", detail.contextualGroundingPolicy() == null
                || detail.contextualGroundingPolicy().filters() == null
                ? 0 : detail.contextualGroundingPolicy().filters().size());
        if (detail.contextualGroundingPolicy() != null) {
            List<GuardrailContextualGroundingFilter> groundingFilters = detail.contextualGroundingPolicy().filters();
            if (groundingFilters != null && !groundingFilters.isEmpty()) {
                attributes.put("contextualGroundingFilters", groundingFilters.stream()
                        .map(f -> entryMap(
                                "type", f.typeAsString(),
                                "threshold", f.threshold(),
                                "action", f.actionAsString()))
                        .toList());
            }
        }

        return attributes;
    }

    /** Builds a map from alternating key/value pairs, skipping any pair whose value is null —
     *  the AWS SDK's per-direction action/strength accessors return null when a guardrail
     *  predates that field, and Map.of() throws NPE on a null value. */
    private Map<String, Object> entryMap(Object... keyValuePairs) {
        Map<String, Object> map = new LinkedHashMap<>();
        for (int i = 0; i < keyValuePairs.length; i += 2) {
            Object value = keyValuePairs[i + 1];
            if (value != null) {
                map.put((String) keyValuePairs[i], value);
            }
        }
        return map;
    }

    private String minimumStrength(List<GuardrailContentFilter> filters) {
        List<String> order = List.of("NONE", "LOW", "MEDIUM", "HIGH");
        int minimum = order.indexOf("HIGH");
        if (filters == null || filters.isEmpty()) {
            return "NONE";
        }
        for (GuardrailContentFilter filter : filters) {
            minimum = Math.min(minimum, order.indexOf(filter.inputStrengthAsString()));
            minimum = Math.min(minimum, order.indexOf(filter.outputStrengthAsString()));
        }
        return minimum < 0 ? "NONE" : order.get(minimum);
    }

    private ObservationEnvelopeV1 envelope(
            Tenant tenant,
            ConnectorSecret config,
            UUID runId,
            String region,
            ScopePayload scope
    ) {
        String scopeRegion = scope.global() ? "GLOBAL" : region;
        String scopeKey = "AWS:" + config.accountId() + ":" + scopeRegion + ":" + scope.family();
        String content = json(Map.of("artifacts", scope.artifacts(), "relationships", scope.relationships()));
        return new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION,
                runId,
                config.id(),
                tenant.getId(),
                "AWS",
                config.accountId(),
                scopeRegion,
                scope.family(),
                scopeKey,
                0,
                1,
                runId + ":" + scopeKey + ":0",
                sha256(content),
                Instant.now(),
                scope.status(),
                scope.artifacts(),
                scope.relationships(),
                scope.diagnostics());
    }

    private ScopePayload complete(
            String family, List<ArtifactObservation> artifacts, List<RelationshipObservation> relationships) {
        return new ScopePayload(family, false, ScopeStatus.COMPLETE, artifacts, relationships, List.of());
    }

    private ScopePayload disabled(String family, boolean global) {
        return new ScopePayload(family, global, ScopeStatus.DISABLED, List.of(), List.of(), List.of(
                new Diagnostic("FEATURE_DISABLED", "AWS AI discovery is disabled for this resource family",
                        false, List.of(), family)));
    }

    private ScopePayload completeGlobal(String family, List<ArtifactObservation> artifacts) {
        return new ScopePayload(family, true, ScopeStatus.COMPLETE, artifacts, List.of(), List.of());
    }

    private ScopePayload completeGlobal(String family, List<ArtifactObservation> artifacts,
            List<RelationshipObservation> relationships) {
        return new ScopePayload(family, true, ScopeStatus.COMPLETE, artifacts, relationships, List.of());
    }

    private ScopePayload failed(String family, Exception ex, List<String> permissions) {
        return failed(family, false, ex, permissions);
    }

    private ScopePayload failedGlobal(String family, Exception ex, List<String> permissions) {
        return failed(family, true, ex, permissions);
    }

    private ScopePayload failed(String family, boolean global, Exception ex, List<String> permissions) {
        String code = diagnosticCode(ex);
        ScopeStatus status = "ACCESS_DENIED".equals(code) ? ScopeStatus.UNAUTHORIZED
                : "PROVIDER_CALL_BUDGET_EXHAUSTED".equals(code) ? ScopeStatus.PARTIAL : ScopeStatus.ERROR;
        return new ScopePayload(
                family, global, status, List.of(), List.of(),
                List.of(new Diagnostic(
                        code,
                        safeMessage(code),
                        "THROTTLED".equals(code) || "TIMEOUT".equals(code) || "PROVIDER_UNAVAILABLE".equals(code),
                        "ACCESS_DENIED".equals(code) ? permissions : List.of(),
                        UUID.randomUUID().toString())));
    }

    private String diagnosticCode(Exception ex) {
        if (ex instanceof AiGridProviderCallCounter.ProviderCallBudgetExceededException) {
            return "PROVIDER_CALL_BUDGET_EXHAUSTED";
        }
        if (ex instanceof AwsServiceException aws) {
            String code = aws.awsErrorDetails() == null ? "" : aws.awsErrorDetails().errorCode();
            if ("AccessDenied".equalsIgnoreCase(code) || "AccessDeniedException".equalsIgnoreCase(code)) {
                return "ACCESS_DENIED";
            }
            if ("ThrottlingException".equalsIgnoreCase(code) || aws.statusCode() == 429) {
                return "THROTTLED";
            }
        }
        if (ex instanceof java.net.SocketTimeoutException) {
            return "TIMEOUT";
        }
        return "PROVIDER_UNAVAILABLE";
    }

    private String safeMessage(String code) {
        return switch (code) {
            case "ACCESS_DENIED" -> "AWS permissions are insufficient for this discovery scope";
            case "THROTTLED" -> "AWS temporarily throttled this discovery scope";
            case "TIMEOUT" -> "AWS did not respond before the discovery timeout";
            case "PROVIDER_CALL_BUDGET_EXHAUSTED" -> "The in-run provider-call ceiling was exhausted for this scope";
            default -> "AWS discovery could not complete this scope";
        };
    }

    private ArtifactObservation agentUpdate(AgentFact agent, Map<String, Object> attributes) {
        return new ArtifactObservation(agent.arn(), "AI_AGENT", "AWS_BEDROCK_AGENT", agent.name(), attributes);
    }

    /** Relationship evidence is metadata-only: an API name and the allowlisted reference field. */
    private RelationshipObservation direct(
            String source, String target, String type, String sourceApi, String field) {
        return new RelationshipObservation(source, target, type, Map.of(
                "confidence", "DIRECT",
                "evidence", Map.of("sourceApi", sourceApi, "field", field)));
    }

    private String arn(ConnectorSecret config, Region region, String resource) {
        return "arn:aws:bedrock:" + region.id() + ":" + config.accountId() + ":" + resource;
    }

    private String functionName(String arn) {
        return arn.substring(arn.lastIndexOf(':') + 1);
    }

    private String roleName(String arn) {
        int slash = arn == null ? -1 : arn.lastIndexOf('/');
        return slash >= 0 ? arn.substring(slash + 1) : safeValue(arn);
    }

    private List<JsonNode> toList(JsonNode node) {
        List<JsonNode> result = new ArrayList<>();
        node.forEach(result::add);
        return result;
    }

    private String json(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to serialize AI Security discovery result", ex);
        }
    }

    private String sha256(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return java.util.HexFormat.of().formatHex(bytes);
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to hash AI Security observation", ex);
        }
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private String safeValue(String value) {
        return value == null ? "" : value;
    }

    /** Best-effort: a permission gap or transient failure here must not fail the whole scope. */
    private Map<String, Object> foundationModelFacts(
            BedrockClient bedrock, Map<String, GetFoundationModelResponse> cache, String modelIdentifier) {
        try {
            GetFoundationModelResponse response = cache.get(modelIdentifier);
            if (response == null) {
                response = bedrock.getFoundationModel(
                        GetFoundationModelRequest.builder().modelIdentifier(modelIdentifier).build());
                cache.put(modelIdentifier, response);
            }
            var details = response.modelDetails();
            Map<String, Object> facts = new LinkedHashMap<>();
            facts.put("providerName", safeValue(details.providerName()));
            facts.put("modelLifecycleStatus",
                    details.modelLifecycle() == null ? "" : details.modelLifecycle().statusAsString());
            facts.put("inputModalities", details.inputModalitiesAsStrings());
            facts.put("outputModalities", details.outputModalitiesAsStrings());
            facts.put("customizationsSupported", details.customizationsSupportedAsStrings());
            facts.put("inferenceTypesSupported", details.inferenceTypesSupportedAsStrings());
            return facts;
        } catch (Exception ex) {
            LOG.warn("bedrock:GetFoundationModel enrichment unavailable for {}: {}: {}",
                    modelIdentifier, ex.getClass().getName(), ex.getMessage());
            return Map.of();
        }
    }

    private ArtifactObservation foundationModelArtifact(
            BedrockClient bedrock,
            Map<String, GetFoundationModelResponse> cache,
            String modelResourceId,
            String apiModelIdentifier,
            String displayName,
            String referenceFlagKey
    ) {
        Map<String, Object> attributes = new LinkedHashMap<>();
        attributes.put(referenceFlagKey, true);
        attributes.putAll(foundationModelFacts(bedrock, cache, apiModelIdentifier));
        return new ArtifactObservation(modelResourceId, "AI_MODEL", "AWS_BEDROCK_MODEL", displayName, attributes);
    }

    private record AgentFact(
            String id,
            String name,
            String arn,
            String roleArn,
            String modelId,
            String guardrailId
    ) {
    }

    private record AgentContext(Map<String, AgentFact> facts) {
    }

    private record RegionContext(List<ScopePayload> scopes) {
    }

    private record ScopePayload(
            String family,
            boolean global,
            ScopeStatus status,
            List<ArtifactObservation> artifacts,
            List<RelationshipObservation> relationships,
            List<Diagnostic> diagnostics
    ) {
    }

    public record DiscoveryResult(UUID runId, int artifactsObserved, int failedScopes) {
    }
}
