package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.RelationshipObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.FindingResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.PolicyConfigurationResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.PolicyScopeConditionResponse;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityObservationService;
import com.prototype.vulnwatch.aisecurity.service.AiSecuritySyncRunFacade;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.IngestionJobWorkerService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

@PostgresIntegrationTest
@TestPropertySource(properties = {
    "spring.main.allow-circular-references=true"
})
class AiSecurityPolicyConfigurationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_security_policy_configuration");

    private static final String WILDCARD_POLICY = "AWS_BEDROCK_WILDCARD_AGENT_ROLE";
    private static final String GUARDRAIL_POLICY = "AWS_BEDROCK_WEAK_GUARDRAIL";

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService tenantSchemaMigrationService;
    @Autowired private TenantSchemaExecutionService tenantExecution;
    @Autowired private AiSecurityAwsConnectorService connectorService;
    @Autowired private AiSecurityObservationService observationService;
    @Autowired private AiSecuritySyncRunFacade syncRunFacade;
    @Autowired private AiSecurityApiService apiService;
    @Autowired private NamedParameterJdbcTemplate jdbc;

    @MockBean private IngestionJobWorkerService ingestionJobWorkerService;
    @MockBean private FindingDeltaQueueService findingDeltaQueueService;

    @Test
    void excludingAnArtifactSuppressesItsOpenFindingAndReincludingReopensIt() {
        Tenant tenant = provision("Scope Exceptions Co", "scope-exceptions-co");
        assertEquals(WILDCARD_POLICY, apiService.policy(tenant, WILDCARD_POLICY).id(),
                "legacy posture policies with a null evaluation mode remain visible in the catalog");
        UUID connectorId = connector(tenant);
        UUID runId = syncRunFacade.start(tenant).getId();

        UUID agentA = ingestWildcardAgents(tenant, connectorId, runId, "agent-a", "agent-b");

        assertEquals("OPEN", findingStatus(tenant, WILDCARD_POLICY, agentA));

        apiService.addPolicyException(tenant, WILDCARD_POLICY, agentA, "EXCLUDED", "known issue, ticketed", "tester");
        assertEquals("AUTO_CLOSED", findingStatus(tenant, WILDCARD_POLICY, agentA));

        apiService.removePolicyException(tenant, WILDCARD_POLICY, agentA, "tester");
        assertEquals("OPEN", findingStatus(tenant, WILDCARD_POLICY, agentA),
                "re-including a still-noncompliant artifact must reopen its finding");
    }

    @Test
    void matchRulesScopeOnlyAppliesPolicyToMatchingArtifacts() {
        Tenant tenant = provision("Scope Rules Co", "scope-rules-co");
        UUID connectorId = connector(tenant);
        UUID runId = syncRunFacade.start(tenant).getId();

        ingestWildcardAgents(tenant, connectorId, runId, "prod-triage-agent", "sandbox-triage-agent");

        PolicyConfigurationResponse configuration = apiService.updatePolicyScope(
                tenant, WILDCARD_POLICY, "MATCH_RULES", "AND",
                List.of(new PolicyScopeConditionResponse("NAME", "NOT_CONTAINS", "sandbox")),
                "tester");

        assertEquals(1, configuration.matchedArtifactCount());
        assertEquals(2, configuration.totalArtifactCount());
        assertEquals("OPEN", findingStatus(tenant, WILDCARD_POLICY, artifactIdByName(tenant, "prod-triage-agent")));
        assertEquals("AUTO_CLOSED",
                findingStatus(tenant, WILDCARD_POLICY, artifactIdByName(tenant, "sandbox-triage-agent")));
    }

    @Test
    void raisingTheGuardrailParameterAboveALowGuardrailReopensTheFinding() {
        Tenant tenant = provision("Guardrail Params Co", "guardrail-params-co");
        UUID connectorId = connector(tenant);
        UUID runId = syncRunFacade.start(tenant).getId();

        UUID agent = ingestGuardrailAgent(tenant, connectorId, runId, "LOW");
        assertEquals("FAIL", evaluationOutcome(tenant, runId, GUARDRAIL_POLICY, agent),
                "LOW is below the default MEDIUM threshold");
        assertEquals("OPEN", findingStatus(tenant, GUARDRAIL_POLICY, agent));

        apiService.updatePolicyParameters(tenant, GUARDRAIL_POLICY, Map.of("minimumGuardrailStrength", "LOW"), "tester");
        assertEquals("RESOLVED", findingStatus(tenant, GUARDRAIL_POLICY, agent),
                "lowering the required threshold to LOW should resolve the finding for a LOW-strength guardrail");
    }

    private UUID connector(Tenant tenant) {
        return connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();
    }

    private UUID ingestWildcardAgents(Tenant tenant, UUID connectorId, UUID runId, String... agentNames) {
        List<ArtifactObservation> agents = List.of(agentNames).stream()
                .map(name -> new ArtifactObservation(
                        "arn:aws:bedrock:us-east-1:123456789012:agent/" + name,
                        "AI_AGENT",
                        "AWS_BEDROCK_AGENT",
                        name,
                        Map.of("iamWildcardActions", true)))
                .toList();
        observationService.ingest(tenant, evidenceEnvelope(
                tenant, connectorId, runId, "us-east-1", "BEDROCK_AGENTS", "bedrock-agents-hash", agents));
        observationService.ingest(tenant, evidenceEnvelope(
                tenant, connectorId, runId, "GLOBAL", "IAM_GLOBAL", "iam-global-hash", agents));
        return artifactIdByName(tenant, agentNames[0]);
    }

    private UUID ingestGuardrailAgent(Tenant tenant, UUID connectorId, UUID runId, String guardrailStrength) {
        String agentResourceId = "arn:aws:bedrock:us-east-1:123456789012:agent/guardrail-agent";
        String guardrailResourceId = "arn:aws:bedrock:us-east-1:123456789012:guardrail/guardrail-1";
        ArtifactObservation agent = new ArtifactObservation(
                agentResourceId,
                "AI_AGENT",
                "AWS_BEDROCK_AGENT",
                "guardrail-agent",
                Map.of("guardrailAttached", true, "guardrailMinimumStrength", guardrailStrength));
        ArtifactObservation guardrail = new ArtifactObservation(
                guardrailResourceId,
                "OTHER_AI_ARTIFACT",
                "AWS_BEDROCK_GUARDRAIL",
                "guardrail-1",
                Map.of());
        observationService.ingest(tenant, evidenceEnvelope(
                tenant, connectorId, runId, "us-east-1", "BEDROCK_AGENTS", "guardrail-agents-hash", List.of(agent)));
        observationService.ingest(tenant, evidenceEnvelope(
                tenant, connectorId, runId, "us-east-1", "BEDROCK_GUARDRAILS", "guardrails-hash",
                List.of(agent, guardrail), List.of(new RelationshipObservation(
                        agentResourceId, guardrailResourceId, "USES_GUARDRAIL", Map.of()))));
        return artifactIdByName(tenant, "guardrail-agent");
    }

    private UUID artifactIdByName(Tenant tenant, String name) {
        return tenantExecution.run(tenant, () -> jdbc.queryForObject(
                "select id from ai_security_artifacts where name = :name",
                Map.of("name", name), UUID.class));
    }

    private String findingStatus(Tenant tenant, String policyId, UUID artifactId) {
        return tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select f.status from findings f
                 join finding_subjects s on s.finding_id = f.id
                                      and s.subject_type = 'ARTIFACT'
                                      and s.subject_role = 'PRIMARY'
                where f.policy_id = :policyId and s.subject_id = :artifactId
                """, Map.of("policyId", policyId, "artifactId", artifactId), String.class));
    }

    private String evaluationOutcome(Tenant tenant, UUID runId, String policyId, UUID artifactId) {
        return tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select decision from ai_grid_assessments
                 where run_id = :runId and policy_id = :policyId and subject_id = :artifactId
                """, Map.of("runId", runId, "policyId", policyId, "artifactId", artifactId), String.class));
    }

    private Tenant provision(String name, String slug) {
        Tenant tenant = tenantService.createTenant(name, slug, "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);
        return tenant;
    }

    private ObservationEnvelopeV1 evidenceEnvelope(
            Tenant tenant,
            UUID connectorId,
            UUID runId,
            String region,
            String resourceFamily,
            String hash,
            List<ArtifactObservation> artifacts
    ) {
        return evidenceEnvelope(tenant, connectorId, runId, region, resourceFamily, hash, artifacts, List.of());
    }

    private ObservationEnvelopeV1 evidenceEnvelope(
            Tenant tenant,
            UUID connectorId,
            UUID runId,
            String region,
            String resourceFamily,
            String hash,
            List<ArtifactObservation> artifacts,
            List<RelationshipObservation> relationships
    ) {
        String scopeKey = "AWS:123456789012:" + region + ":" + resourceFamily;
        return new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION,
                runId,
                connectorId,
                tenant.getId(),
                "AWS",
                "123456789012",
                region,
                resourceFamily,
                scopeKey,
                0,
                1,
                runId + ":" + scopeKey + ":0",
                hash,
                Instant.now(),
                ScopeStatus.COMPLETE,
                artifacts,
                relationships,
                List.of());
    }
}
