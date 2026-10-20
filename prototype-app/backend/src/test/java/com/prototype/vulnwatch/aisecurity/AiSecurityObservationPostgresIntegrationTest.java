package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.reset;

import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.RelationshipObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityAwsConnectorService;
import com.prototype.vulnwatch.aisecurity.service.AiGridOwnershipService;
import com.prototype.vulnwatch.aisecurity.service.AiGridApiService;
import com.prototype.vulnwatch.aisecurity.service.AiGridBudgetService;
import com.prototype.vulnwatch.aisecurity.service.AiGridCoverageService;
import com.prototype.vulnwatch.aisecurity.service.AiGridCapabilityService;
import com.prototype.vulnwatch.aisecurity.service.AiGridRetentionService;
import com.prototype.vulnwatch.aisecurity.service.AiGridSystemService;
import com.prototype.vulnwatch.aisecurity.service.AiGridReconciliationService;
import com.prototype.vulnwatch.aisecurity.service.AiGridRunMetricsService;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityObservationService;
import com.prototype.vulnwatch.aisecurity.service.AiSecuritySyncRunFacade;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FindingWorkflowUpdateRequest;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.IngestionJobWorkerService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.mock.mockito.SpyBean;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;

@PostgresIntegrationTest
@TestPropertySource(properties = "spring.main.allow-circular-references=true")
class AiSecurityObservationPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_security_observations");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantService tenantService;
    @Autowired private TenantSchemaMigrationService tenantSchemaMigrationService;
    @Autowired private TenantSchemaExecutionService tenantExecution;
    @Autowired private AiSecurityAwsConnectorService connectorService;
    @Autowired private AiSecurityObservationService observationService;
    @Autowired private AiGridOwnershipService ownershipService;
    @Autowired private AiGridApiService aiGridApiService;
    @Autowired private com.prototype.vulnwatch.aisecurity.service.AiGridAssessmentWorker assessmentWorker;
    @Autowired private com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService aiSecurityApiService;
    @Autowired private AiGridBudgetService budgetService;
    @Autowired private AiGridCoverageService coverageService;
    @Autowired private AiGridCapabilityService capabilityService;
    @Autowired private AiGridRetentionService retentionService;
    @Autowired private AiGridSystemService systemService;
    @Autowired private AiGridRunMetricsService runMetricsService;
    @Autowired private FindingWorkflowService findingWorkflowService;
    @Autowired private AiSecuritySyncRunFacade syncRunFacade;
    @Autowired private NamedParameterJdbcTemplate jdbc;
    @Autowired private com.prototype.vulnwatch.aisecurity.service.AiAgentDeploymentService deploymentService;

    @SpyBean private AiGridReconciliationService reconciliationService;

    @MockBean private IngestionJobWorkerService ingestionJobWorkerService;
    @MockBean private FindingDeltaQueueService findingDeltaQueueService;

    @Test
    void verifiedRoutesAndDefinitionVersionsStaySeparateAcrossExpiryAndEmptyEnumeration() {
        Tenant tenant = provision("Served agents Co", "served-agents-co");
        UUID connector = connectorService.save(tenant,new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly",null,List.of("us-east-1"),true)).id();
        String root = "arn:aws:bedrock:us-east-1:123456789012:agent/served";
        UUID run = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant,new ObservationEnvelopeV1(AiSecurityObservationService.CONTRACT_VERSION,
                run,connector,tenant.getId(),"AWS","123456789012","us-east-1","BEDROCK_AGENT_ROUTES",
                "AWS:123456789012:us-east-1:BEDROCK_AGENT_ROUTES",0,1,run + ":routes",run.toString(),Instant.now(),ScopeStatus.COMPLETE,
                List.of(new ArtifactObservation(root,"AI_AGENT","AWS_BEDROCK_AGENT","Served agent",Map.of()),
                        new ArtifactObservation(root + "/alias/prod","AI_COMPONENT","AWS_BEDROCK_AGENT_ALIAS","Production",Map.of("status","PREPARED","invocationState","ACCEPT_INVOCATIONS")),
                        new ArtifactObservation(root + "/version/1","AI_AGENT_VERSION","AWS_BEDROCK_AGENT_VERSION","Served v1",Map.of("version","1")),
                        new ArtifactObservation(root + "/version/2","AI_AGENT_VERSION","AWS_BEDROCK_AGENT_VERSION","Definition v2",Map.of("version","2"))),
                List.of(new RelationshipObservation(root,root + "/alias/prod","HAS_COMPONENT",Map.of()),
                        new RelationshipObservation(root + "/alias/prod",root + "/version/1","SERVES_VERSION",Map.of()),
                        new RelationshipObservation(root + "/version/1",root,"VERSION_OF",Map.of()),
                        new RelationshipObservation(root + "/version/2",root,"VERSION_OF",Map.of()),
                        new RelationshipObservation(root,root + "/version/2","ACTIVE_VERSION",Map.of())),List.of()));
        var roster = aiSecurityApiService.artifactSummaries(tenant,null,null,null,null,null,null,null,"AGENTS",null,0,50);
        assertEquals(1,roster.total());
        var agent = roster.items().get(0);
        assertEquals("SERVED",agent.deployment().status().name());
        var versions = aiSecurityApiService.agentVersions(tenant,agent.id(),0,50);
        assertEquals(2,versions.total());
        assertTrue(versions.items().stream().filter(v -> v.name().equals("Served v1")).allMatch(v -> v.servedVersion() && !v.definitionVersion()));
        assertTrue(versions.items().stream().filter(v -> v.name().equals("Definition v2")).allMatch(v -> !v.servedVersion() && v.definitionVersion()));
        var others = aiSecurityApiService.artifactSummaries(tenant,null,null,null,null,null,null,null,"OTHERS",null,0,50);
        assertTrue(others.items().stream().noneMatch(v -> v.nativeKind().contains("VERSION")));
        assertEquals(1,aiSecurityApiService.summary(tenant).logicalAgentCount());
        var expired = tenantExecution.run(tenant, () -> deploymentService.resolve(List.of(
                new com.prototype.vulnwatch.aisecurity.service.AiAgentDeploymentService.Agent(agent.id(),agent.nativeKind())),
                agent.deployment().expiresAt()).get(agent.id()));
        assertEquals("STALE_EVIDENCE",expired.reasonCode().name());
        assertEquals("SERVED",expired.lastVerifiedObservation().status().name());
        aiSecurityApiService.updateDeploymentSettings(tenant,new com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService.DeploymentSettings(1));
        var fresh = aiSecurityApiService.artifact(tenant,agent.id()).deployment();
        assertEquals(java.time.Duration.ofHours(1),java.time.Duration.between(fresh.observedAt(),fresh.expiresAt()));
        tenantExecution.run(tenant, () -> jdbc.update("update ai_security_snapshot_scopes set started_at=started_at-interval '2 hours' where run_id=:run",Map.of("run",run)));
        assertEquals("STALE_EVIDENCE",aiSecurityApiService.artifact(tenant,agent.id()).deployment().reasonCode().name(),
                "Finalizing old provider observations must not refresh their evidence time");
        UUID emptyRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant,new ObservationEnvelopeV1(AiSecurityObservationService.CONTRACT_VERSION,
                emptyRun,connector,tenant.getId(),"AWS","123456789012","us-east-1","BEDROCK_AGENT_ROUTES",
                "AWS:123456789012:us-east-1:BEDROCK_AGENT_ROUTES",0,1,emptyRun + ":routes",emptyRun.toString(),Instant.now(),ScopeStatus.COMPLETE,
                List.of(new ArtifactObservation(root,"AI_AGENT","AWS_BEDROCK_AGENT","Served agent",Map.of())),List.of(),List.of()));
        assertEquals("NOT_CURRENTLY_SERVED",aiSecurityApiService.artifact(tenant,agent.id()).deployment().status().name());
        assertEquals(1,aiSecurityApiService.summary(tenant).logicalAgentCount());
        assertEquals(2,aiSecurityApiService.agentVersions(tenant,agent.id(),0,50).total());
        assertTrue(aiSecurityApiService.agentVersions(tenant,agent.id(),0,50).items().stream().noneMatch(v -> v.servedVersion()));
        assertTrue(aiSecurityApiService.artifact(tenant,versions.items().get(0).id()) != null);
    }

    @Test
    void logicalAgentRosterKeepsIdentityTotalsAndHistoryAcrossRoutingFailures() {
        Tenant tenant = provision("Logical agents Co", "logical-agents-co");
        UUID connectorId = connectorService.save(tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest("123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)).id();
        String root = "arn:aws:bedrock:us-east-1:123456789012:agent/roster";
        List<ArtifactObservation> agents = List.of(
                new ArtifactObservation(root, "AI_AGENT", "AWS_BEDROCK_AGENT", "Same name", Map.of()),
                new ArtifactObservation(root + "-distinct", "AI_AGENT", "AWS_BEDROCK_AGENT", "Same name", Map.of()));
        UUID enumeration = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, envelope(tenant, connectorId, enumeration, "roster-1", ScopeStatus.COMPLETE, agents));
        UUID duplicate = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, envelope(tenant, connectorId, duplicate, "roster-2", ScopeStatus.COMPLETE, agents));
        var roster = aiSecurityApiService.artifactSummaries(tenant, null, null, "AWS", null, null, null, null, "AGENTS", "Same", 0, 1);
        assertEquals(2, roster.total());
        assertEquals(1, roster.items().size());
        assertEquals(2, aiSecurityApiService.summary(tenant).logicalAgentCount());
        UUID agentId = tenantExecution.run(tenant, () -> jdbc.queryForObject(
                "select id from ai_security_artifacts where provider_resource_id=:id", Map.of("id", root), UUID.class));
        for (ScopeStatus state : List.of(ScopeStatus.COMPLETE, ScopeStatus.ERROR)) {
            UUID run = syncRunFacade.start(tenant).getId();
            observationService.ingest(tenant, new ObservationEnvelopeV1(AiSecurityObservationService.CONTRACT_VERSION,
                    run, connectorId, tenant.getId(), "AWS", "123456789012", "us-east-1", "BEDROCK_AGENT_ROUTES",
                    "AWS:123456789012:us-east-1:BEDROCK_AGENT_ROUTES", 0, 1, run + ":routes", run.toString(), Instant.now(), state,
                    state == ScopeStatus.COMPLETE ? agents : List.of(), List.of(), List.of()));
            assertEquals(2, aiSecurityApiService.artifactSummaries(tenant, null, null, null, null, null, null, null, "AGENTS", null, 0, 50).total());
            var deployment = aiSecurityApiService.artifact(tenant, agentId).deployment();
            assertEquals(state == ScopeStatus.COMPLETE ? "NOT_CURRENTLY_SERVED" : "UNVERIFIED", deployment.status().name());
            assertEquals(state == ScopeStatus.COMPLETE ? "NO_ALIAS_ROUTE" : "PROVIDER_ERROR", deployment.reasonCode().name());
            assertTrue(deployment.lastVerifiedObservation() != null);
        }
        UUID missing = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, envelope(tenant, connectorId, missing, "roster-empty", ScopeStatus.COMPLETE, List.of()));
        assertEquals(0, aiSecurityApiService.summary(tenant).logicalAgentCount());
        assertFalse(aiSecurityApiService.artifact(tenant, agentId).active());
        assertEquals(2, tenantExecution.run(tenant, () -> jdbc.queryForObject("select count(*) from ai_security_artifacts", Map.of(), Integer.class)));
        tenantExecution.run(tenant, () -> {
            jdbc.update("""
                    insert into ai_security_artifacts (id,tenant_id,provider,provider_resource_id,artifact_type,native_kind,
                        name,account_id,region,active,attributes_json,first_observed_at,last_observed_at)
                    select gen_random_uuid(),:tenant,'AWS','representative-agent-' || n,'AI_AGENT','AWS_BEDROCK_AGENT',
                        'Representative ' || n,'123456789012','us-east-1',true,'{}'::jsonb,now(),now()
                    from generate_series(1,1000) n
                    """, Map.of("tenant",tenant.getId()));
            jdbc.getJdbcTemplate().execute("analyze ai_security_artifacts");
            return null;
        });
        var representative = aiSecurityApiService.artifactSummaries(tenant,null,null,null,null,null,null,null,"AGENTS",null,0,50);
        assertEquals(1000,representative.total());
        assertEquals(50,representative.items().size());
        tenantExecution.run(tenant, () -> {
            String query = (String) org.springframework.test.util.ReflectionTestUtils.getField(
                    com.prototype.vulnwatch.aisecurity.service.AiAgentDeploymentService.class,"SCOPE_QUERY");
            String plan = jdbc.queryForObject("explain (analyze,buffers,format json) " + query,
                    Map.of("ids", representative.items().stream().map(item -> item.id()).toList()),String.class);
            assertTrue(plan.contains("Execution Time"));
            try { java.nio.file.Files.writeString(java.nio.file.Path.of("/tmp/agent-deployment-query-plan.json"),plan); }
            catch (java.io.IOException ex) { throw new IllegalStateException(ex); }
            return null;
        });
    }

    @Test
    void capabilityManifestsFinalizeMissingScopesExactlyOnce() {
        Tenant tenant = provision("Capability Manifest Co", "capability-manifest-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();
        UUID runId = syncRunFacade.start(tenant).getId();

        capabilityService.registerRun(tenant, runId, "AWS", connectorId, "123456789012",
                List.of("us-east-1"), List.of("BEDROCK_AGENTS", "IAM_GLOBAL"));
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                runId + ":capability:0", "capability-manifest-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(), List.of(), List.of()));

        capabilityService.finalizeRun(tenant, runId);
        capabilityService.finalizeRun(tenant, runId);

        Map<String, String> states = tenantExecution.run(tenant, () -> jdbc.query(
                "select capability_id,status from ai_grid_capability_observations where run_id=:runId",
                Map.of("runId", runId), rs -> {
                    Map<String, String> result = new java.util.HashMap<>();
                    while (rs.next()) result.put(rs.getString(1), rs.getString(2));
                    return result;
                }));
        assertEquals("COMPLETE", states.get("BEDROCK_AGENTS"));
        assertEquals("PARTIAL", states.get("IAM_ROLE_POLICIES"));
        assertEquals("PARTIAL", states.get("AWS_EFFECTIVE_ACCESS"));
        assertEquals(3, states.size(), "finalization is idempotent and emits one observation per manifest");
        assertEquals(2, tenantExecution.run(tenant, () -> jdbc.queryForObject(
                "select count(*) from ai_grid_capability_observations where run_id=:runId and reason_code='MISSING_EVIDENCE_SCOPE'",
                Map.of("runId", runId), Integer.class)));
    }

    @Test
    void enforcesReplayAndSnapshotCompletenessWithinTenantBoundary() {
        Tenant tenant = provision("AI Security Co", "ai-security-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();

        UUID firstRun = syncRunFacade.start(tenant).getId();
        ObservationEnvelopeV1 first = envelope(
                tenant, connectorId, firstRun, "hash-1", ScopeStatus.COMPLETE,
                List.of(new ArtifactObservation(
                        "arn:aws:bedrock:us-east-1:123456789012:agent/agent-1",
                        "AI_AGENT",
                        "AWS_BEDROCK_AGENT",
                        "Support agent",
                        Map.of("iamWildcardActions", false))));

        var accepted = observationService.ingest(tenant, first);
        var duplicate = observationService.ingest(tenant, first);

        assertEquals(ScopeStatus.COMPLETE, accepted.scopeStatus());
        assertTrue(duplicate.duplicate());
        assertThrows(IllegalArgumentException.class, () ->
                observationService.ingest(
                        tenant,
                        envelope(tenant, connectorId, firstRun, "different-hash",
                                ScopeStatus.COMPLETE, first.artifacts())));
        assertEquals(1, activeArtifacts(tenant));
        assertEquals(1, observationService.countPersistedArtifacts(tenant, firstRun));

        UUID partialRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(
                tenant,
                envelope(tenant, connectorId, partialRun, "hash-2", ScopeStatus.PARTIAL, List.of()));
        assertEquals(1, activeArtifacts(tenant), "partial scope must retain previously observed inventory");

        UUID completeRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(
                tenant,
                envelope(tenant, connectorId, completeRun, "hash-3", ScopeStatus.COMPLETE, List.of()));
        assertEquals(0, activeArtifacts(tenant), "complete empty scope may deactivate missing inventory");

        Tenant otherTenant = provision("Other AI Co", "other-ai-co");
        ObservationEnvelopeV1 mismatched = envelope(
                otherTenant, connectorId, firstRun, "hash-4", ScopeStatus.COMPLETE, List.of());
        assertThrows(IllegalArgumentException.class, () -> observationService.ingest(otherTenant, mismatched));
    }

    @Test
    void requiresRegionalAgentAndAccountGlobalIamScopesBeforePolicyDecision() {
        Tenant tenant = provision("Scope Semantics Co", "scope-semantics-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        ArtifactObservation agent = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/scope-agent",
                "AI_AGENT",
                "AWS_BEDROCK_AGENT",
                "Scope agent",
                Map.of("iamWildcardActions", true));

        observationService.ingest(
                tenant,
                evidenceEnvelope(
                        tenant, connectorId, runId, "us-east-1", "BEDROCK_AGENTS", "agent-scope", List.of(agent)));
        assertEquals("NO_DECISION", wildcardRoleOutcome(tenant, runId));

        observationService.ingest(
                tenant,
                evidenceEnvelope(
                        tenant, connectorId, runId, "us-east-1", "IAM_GLOBAL", "mis-tagged-iam", List.of()));
        assertEquals(
                "NO_DECISION",
                wildcardRoleOutcome(tenant, runId),
                "regional IAM evidence must not satisfy an account-global requirement");

        observationService.ingest(
                tenant,
                evidenceEnvelope(
                        tenant, connectorId, runId, "GLOBAL", "IAM_GLOBAL", "global-iam", List.of(agent)));
        assertEquals("FAIL", wildcardRoleOutcome(tenant, runId));
    }

    @Test
    void scopeOwnedAttributesRemoveOnlyThatScopesStaleKeysAndStayTenantBound() {
        Tenant tenant = provision("Scope Owned Attributes Co", "scope-owned-attributes-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();
        String resourceId = "arn:aws:bedrock:us-east-1:123456789012:agent/owned-attributes-agent";

        UUID firstRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, evidenceEnvelope(
                tenant, connectorId, firstRun, "us-east-1", "BEDROCK_AGENTS", "owned-attributes-1",
                List.of(new ArtifactObservation(resourceId, "AI_AGENT", "AWS_BEDROCK_AGENT", "Owned agent",
                        Map.of("iamWildcardActions", true, "deployedArtifact", true)))));

        UUID otherScopeRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, evidenceEnvelope(
                tenant, connectorId, otherScopeRun, "us-east-1", "BEDROCK_AGENT_VERSIONS", "owned-attributes-2",
                List.of(new ArtifactObservation(resourceId, "AI_AGENT", "AWS_BEDROCK_AGENT", "Owned agent",
                        Map.of("iamEvidenceAvailable", true)))));

        UUID secondRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, evidenceEnvelope(
                tenant, connectorId, secondRun, "us-east-1", "BEDROCK_AGENTS", "owned-attributes-3",
                List.of(new ArtifactObservation(resourceId, "AI_AGENT", "AWS_BEDROCK_AGENT", "Owned agent",
                        Map.of("iamWildcardActions", false)))));

        Map<String, Object> attributes = tenantExecution.run(tenant, () -> jdbc.queryForMap("""
                select attributes_json from ai_security_artifacts
                 where provider_resource_id = :resourceId
                """, Map.of("resourceId", resourceId)));
        String json = String.valueOf(attributes.get("attributes_json"));
        assertTrue(json.contains("iamWildcardActions"));
        assertTrue(json.contains("iamEvidenceAvailable"));
        assertTrue(json.contains("false"));
        assertFalse(json.contains("deployedArtifact"));

        Tenant otherTenant = provision("Other Scope Owned Attributes Co", "other-scope-owned-attributes-co");
        assertEquals(0, tenantExecution.run(otherTenant, () -> jdbc.queryForObject(
                "select count(*) from ai_security_artifacts where provider_resource_id = :resourceId",
                Map.of("resourceId", resourceId), Integer.class)));
    }

    @Test
    void partialScopeCannotDeletePreviouslyOwnedAttributes() {
        Tenant tenant = provision("Partial Attribute Co", "partial-attribute-co");
        UUID connectorId = connectorService.save(tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)).id();
        String resourceId = "arn:aws:bedrock:us-east-1:123456789012:agent/partial-attribute-agent";

        UUID completeRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, envelope(tenant, connectorId, completeRun, "partial-owned-1",
                ScopeStatus.COMPLETE, List.of(new ArtifactObservation(resourceId, "AI_AGENT", "AWS_BEDROCK_AGENT",
                        "Partial agent", Map.of("deployedArtifact", true, "iamWildcardActions", true)))));
        UUID partialRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, envelope(tenant, connectorId, partialRun, "partial-owned-2",
                ScopeStatus.PARTIAL, List.of(new ArtifactObservation(resourceId, "AI_AGENT", "AWS_BEDROCK_AGENT",
                        "Partial agent", Map.of("iamWildcardActions", false)))));

        tenantExecution.run(tenant, () -> {
            String attributes = jdbc.queryForObject("""
                    select attributes_json::text from ai_security_artifacts where provider_resource_id=:resourceId
                    """, Map.of("resourceId", resourceId), String.class);
            assertTrue(attributes.contains("deployedArtifact"));
            assertTrue(attributes.contains("false"));
            return null;
        });
    }

    @Test
    void persistsCanonicalAwsVersionAliasAndToolGraph() {
        Tenant tenant = provision("AWS Definition Graph Co", "aws-definition-graph-co");
        UUID connectorId = connectorService.save(tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        capabilityService.registerRun(tenant, runId, "AWS", connectorId, "123456789012",
                List.of("us-east-1"), List.of("BEDROCK_AGENT_VERSIONS"));
        String agentId = "arn:aws:bedrock:us-east-1:123456789012:agent/graph-agent";
        String versionId = agentId + "/version/3";
        String aliasId = agentId + "/alias/production";
        String toolId = versionId + "/tool/tool-1";
        String lambdaId = "arn:aws:lambda:us-east-1:123456789012:function:tool-1";
        List<ArtifactObservation> artifacts = List.of(
                new ArtifactObservation(agentId, "AI_AGENT", "AWS_BEDROCK_AGENT", "Graph agent", Map.of()),
                new ArtifactObservation(versionId, "AI_AGENT_VERSION", "AWS_BEDROCK_AGENT_VERSION", "Graph agent v3",
                        Map.of("version", "3", "status", "PREPARED")),
                new ArtifactObservation(aliasId, "AI_COMPONENT", "AWS_BEDROCK_AGENT_ALIAS", "production",
                        Map.of("aliasId", "production", "routedVersions", List.of("3"))),
                new ArtifactObservation(toolId, "AI_TOOL", "AWS_BEDROCK_ACTION_GROUP", "tool-1",
                        Map.of("actionGroupId", "tool-1", "lambdaArn", lambdaId)),
                new ArtifactObservation(lambdaId, "SUPPORTING_RESOURCE", "AWS_LAMBDA_FUNCTION", "tool-1",
                        Map.of("lambdaArn", lambdaId)));
        List<RelationshipObservation> relationships = List.of(
                new RelationshipObservation(versionId, agentId, "VERSION_OF", Map.of()),
                new RelationshipObservation(agentId, aliasId, "HAS_COMPONENT", Map.of()),
                new RelationshipObservation(aliasId, versionId, "SERVES_VERSION", Map.of()),
                new RelationshipObservation(versionId, toolId, "USES_TOOL", Map.of()),
                new RelationshipObservation(toolId, lambdaId, "IMPLEMENTED_BY", Map.of()));
        String scopeKey = "AWS:123456789012:us-east-1:BEDROCK_AGENT_VERSIONS";
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENT_VERSIONS", scopeKey, 0, 1,
                runId + ":versions:0", "definition-graph-hash", Instant.now(), ScopeStatus.COMPLETE,
                artifacts, relationships, List.of()));
        capabilityService.finalizeRun(tenant, runId);

        tenantExecution.run(tenant, () -> {
            assertEquals(5, jdbc.queryForObject("select count(*) from ai_security_artifacts where active=true",
                    Map.of(), Integer.class));
            assertEquals(5, jdbc.queryForObject("select count(*) from ai_security_relationships where active=true",
                    Map.of(), Integer.class));
            assertEquals("AI_COMPONENT", jdbc.queryForObject(
                    "select artifact_type from ai_security_artifacts where provider_resource_id=:id",
                    Map.of("id", aliasId), String.class));
            assertEquals("COMPLETE", jdbc.queryForObject("""
                    select status from ai_grid_capability_observations
                     where run_id=:runId and capability_id='BEDROCK_AGENT_VERSIONS_ALIASES'
                    """, Map.of("runId", runId), String.class));
            return null;
        });
    }

    @Test
    void hashesEvidenceIdentityForLongProviderResourceIds() {
        Tenant tenant = provision("Long Resource Co", "long-resource-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        String providerResourceId = "/subscriptions/" + "a".repeat(220);

        observationService.ingest(
                tenant,
                envelope(
                        tenant,
                        connectorId,
                        runId,
                        "f".repeat(64),
                        ScopeStatus.COMPLETE,
                        List.of(new ArtifactObservation(
                                providerResourceId,
                                "AI_MODEL",
                                "AWS_BEDROCK_MODEL",
                                "Long provider resource",
                                Map.of()))));

        Integer hashLength = tenantExecution.run(tenant, () -> jdbc.queryForObject(
                "select length(evidence_hash) from ai_security_artifact_sources",
                Map.of(),
                Integer.class));
        assertEquals(64, hashLength);
    }

    @Test
    void buildsMinimumContextPackAndFirstRunReadinessWithoutShrinkingCoverage() {
        Tenant tenant = provision("AI Grid context co", "ai-grid-context-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        tenantExecution.run(tenant, () -> jdbc.update("""
                insert into ownership_rules
                    (id, tenant_id, name, condition_json, user_group, execution_order, created_at, updated_at)
                values (:id, :tenantId, 'AWS AI ownership',
                        '{"logic":"AND","conditions":[{"table":"ASSET","column":"cloudProvider","operator":"is","value":"AWS"}]}',
                        'Cloud AI Team', 10, now(), now())
                """, Map.of("id", UUID.randomUUID(), "tenantId", tenant.getId())));
        ArtifactObservation agent = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/context-agent",
                "AI_AGENT", "AWS_BEDROCK_AGENT", "Context agent",
                Map.of("iamWildcardActions", false, "tags", Map.of("owner", "AI Platform")));
        ArtifactObservation knowledgeBase = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:knowledge-base/context-kb",
                "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "Context knowledge base", Map.of());
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                runId + ":context:0", "context-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(agent, knowledgeBase), List.of(new RelationshipObservation(
                        agent.providerResourceId(), knowledgeBase.providerResourceId(),
                        "USES_KNOWLEDGE_BASE", Map.of())), List.of()));

        tenantExecution.run(tenant, () -> {
            assertEquals("INFERRED", jdbc.queryForObject("""
                    select owner_state from ai_security_artifacts where native_kind = 'AWS_BEDROCK_AGENT'
                    """, Map.of(), String.class));
            assertEquals("Cloud AI Team", jdbc.queryForObject("""
                    select owner_name from ai_security_artifacts where native_kind = 'AWS_BEDROCK_AGENT'
                    """, Map.of(), String.class));
            assertEquals(true, jdbc.queryForObject("""
                    select value_json = 'true'::jsonb from ai_grid_facts f
                      join ai_security_artifacts a on a.id = f.artifact_id
                     where f.run_id = :runId and f.fact_key = 'data.source_linked'
                       and a.native_kind = 'AWS_BEDROCK_AGENT'
                    """, Map.of("runId", runId), Boolean.class));
            assertEquals("DERIVED", jdbc.queryForObject("""
                    select provenance from ai_grid_facts where run_id = :runId
                     and fact_key = 'data.source_linked'
                    """, Map.of("runId", runId), String.class));
            assertEquals("RELATIONSHIP_GRAPH", jdbc.queryForObject("""
                    select evidence_class from ai_grid_facts where run_id = :runId
                     and fact_key = 'data.source_linked'
                    """, Map.of("runId", runId), String.class));
            assertEquals(0, jdbc.queryForObject("""
                    select count(*) from ai_grid_facts where run_id = :runId
                     and fact_key = 'data.sensitive_content_confirmed'
                    """, Map.of("runId", runId), Integer.class),
                    "a linked source must not be promoted to confirmed sensitive content");
            return null;
        });
        assertEquals(8, TenantContext.runAsPlatform(() -> jdbc.queryForObject("""
                select count(*) from platform.ai_grid_fact_definitions where fact_key in (
                    'network.public_access_configured','network.internet_reachability_verified',
                    'identity.wildcard_permission_observed','identity.effective_admin_access_derived',
                    'data.source_linked','data.sensitive_content_confirmed',
                    'owner.tag_candidate','owner.confirmed')
                """, Map.of(), Integer.class)));

        var readiness = aiGridApiService.policyReadiness(tenant);
        var wildcard = readiness.stream()
                .filter(item -> "AWS_BEDROCK_WILDCARD_AGENT_ROLE".equals(item.policyId()))
                .findFirst().orElseThrow();
        assertEquals("BLOCKED", wildcard.readiness());
        assertTrue(wildcard.missingEvidenceJson().contains("IAM_GLOBAL"));

        var actions = aiGridApiService.setupActions(tenant);
        assertTrue(actions.stream().anyMatch(action -> "RESTORE_SCOPE_ACCESS".equals(action.actionCode())));
        for (int index = 1; index < actions.size(); index++) {
            assertTrue(actions.get(index - 1).priority() <= actions.get(index).priority());
        }

        var coverage = aiGridApiService.coverage(tenant);
        var metrics = aiGridApiService.runMetrics(tenant, runId);
        assertEquals(coverage.expectedAssessments(), metrics.expectedAssessmentCount());
        assertEquals(coverage.missingAssessments(), metrics.missingAssessmentCount());
        assertEquals(connectorId, metrics.connectorConfigId());
        assertEquals(true, metrics.baselineRun());
        assertEquals(80.0, metrics.firstRunTargetPercent());
        assertEquals(metrics.ownerFacingDecisionCount() * 100.0 / metrics.ownerFacingExpectedCount(),
                metrics.ownerFacingUtilityPercent(), 0.01);
        assertEquals(metrics.ownerFacingUtilityPercent() >= metrics.firstRunTargetPercent(),
                metrics.firstRunTargetMet());
    }

    @Test
    void aiGridR0CreatesImmutableFactsAssessmentSystemAndCanonicalFinding() {
        Tenant tenant = provision("AI Grid R0 Co", "ai-grid-r0-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        ArtifactObservation agent = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/r0-agent",
                "AI_AGENT", "AWS_BEDROCK_AGENT", "R0 agent",
                Map.of(
                        "guardrailAttached", true,
                        "guardrailMinimumStrength", "LOW",
                        "tags", Map.of("team", "AI Platform Team")));
        ArtifactObservation guardrail = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:guardrail/r0-guardrail",
                "GUARDRAIL", "AWS_BEDROCK_GUARDRAIL", "R0 guardrail", Map.of());
        String agentScope = "AWS:123456789012:us-east-1:BEDROCK_AGENTS";
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS", agentScope, 0, 1,
                runId + ":agents:0", "agent-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(agent, guardrail), List.of(new RelationshipObservation(
                        agent.providerResourceId(), guardrail.providerResourceId(), "USES_GUARDRAIL", Map.of())), List.of()));

        String guardrailScope = "AWS:123456789012:us-east-1:BEDROCK_GUARDRAILS";
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_GUARDRAILS", guardrailScope, 0, 1,
                runId + ":guardrails:0", "guardrail-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(guardrail), List.of(), List.of()));

        Map<String, String> originalFingerprints = tenantExecution.run(tenant, () -> {
            assertEquals(3, jdbc.queryForObject(
                    "select count(*) from ai_grid_snapshot_manifests where run_id = :runId",
                    Map.of("runId", runId), Integer.class));
            assertEquals(2, jdbc.queryForObject(
                    "select count(*) from ai_grid_snapshot_bodies",
                    Map.of(), Integer.class),
                    "the same guardrail evidence in two manifests must reuse one content-addressed body");
            assertEquals(4, jdbc.queryForObject(
                    "select count(*) from ai_grid_facts where run_id = :runId",
                    Map.of("runId", runId), Integer.class));
            assertEquals("UNKNOWN", jdbc.queryForObject(
                    "select state from ai_grid_facts where run_id=:runId and fact_key='guardrail.baseline_comparison_outcome'",
                    Map.of("runId", runId), String.class), "missing approval is coverage uncertainty, never a passing control");
            assertEquals("FAIL", jdbc.queryForObject("""
                    select decision from ai_grid_assessments
                     where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of("runId", runId), String.class));
            assertEquals(1, jdbc.queryForObject("select count(*) from ai_grid_systems", Map.of(), Integer.class));
            jdbc.update("""
                    update ai_security_relationships set active = false
                     where relationship_type = 'USES_GUARDRAIL'
                    """, Map.of());
            systemService.deriveForRun(tenant, runId);
            assertEquals(1, jdbc.queryForObject("select count(*) from ai_grid_system_revisions", Map.of(), Integer.class),
                    "re-deriving a run must use its relationship snapshot, not changed live relationships");
            assertEquals(1, jdbc.queryForObject(
                    """
                    select count(*) from findings
                     where finding_kind = 'AI_POSTURE' and status = 'OPEN'
                       and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """,
                    Map.of(), Integer.class));
            assertTrue(jdbc.queryForObject("""
                    select due_at is not null from findings
                     where finding_kind = 'AI_POSTURE'
                       and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of(), Boolean.class));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from finding_events event
                      join findings finding on finding.id = event.finding_id
                     where event.event_type = 'CREATED_BY_AI_ASSESSMENT'
                       and finding.policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of(), Integer.class));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from finding_subjects subject
                      join findings finding on finding.id = subject.finding_id
                     where finding.policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of(), Integer.class));
            assertEquals("CANDIDATE", jdbc.queryForObject("""
                    select owner_state from ai_security_artifacts where native_kind = 'AWS_BEDROCK_AGENT'
                    """, Map.of(), String.class));
            assertNull(jdbc.queryForObject("""
                    select owner_group from findings
                     where finding_kind = 'AI_POSTURE'
                       and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of(), String.class));
            assertEquals(2, jdbc.queryForObject("""
                    select completed_scope_count from ai_grid_run_metrics where run_id = :runId
                    """, Map.of("runId", runId), Integer.class));
            assertEquals("UNAVAILABLE", jdbc.queryForObject("""
                    select provider_call_measurement_state from ai_grid_run_metrics where run_id = :runId
                    """, Map.of("runId", runId), String.class));
            assertTrue(jdbc.queryForObject("""
                    select new_snapshot_bytes > 0 from ai_grid_run_metrics where run_id = :runId
                    """, Map.of("runId", runId), Boolean.class));
            UUID agentId = jdbc.queryForObject("""
                    select id from ai_security_artifacts where native_kind = 'AWS_BEDROCK_AGENT'
                    """, Map.of(), UUID.class);
            ownershipService.confirm(tenant, agentId, "AI Platform Team", "integration-reviewer",
                    "Answer-key owner confirmation");
            assertEquals("CONFIRMED", jdbc.queryForObject(
                    "select owner_state from ai_security_artifacts where id = :id", Map.of("id", agentId), String.class));
            assertEquals(0, jdbc.queryForObject("""
                    select count(*) from ai_grid_coverage_gaps where artifact_id = :id
                      and state = 'UNRESOLVED_OWNER' and status = 'OPEN'
                    """, Map.of("id", agentId), Integer.class));
            assertEquals("AI Platform Team", jdbc.queryForObject("""
                    select owner_group from findings
                     where finding_kind = 'AI_POSTURE'
                       and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of(), String.class));

            runMetricsService.recordProviderCalls(tenant, runId, "AWS", 17);
            assertEquals("MEASURED", jdbc.queryForObject("""
                    select provider_call_measurement_state from ai_grid_run_metrics where run_id = :runId
                    """, Map.of("runId", runId), String.class));
            assertEquals(17L, jdbc.queryForObject("""
                    select provider_api_calls from ai_grid_run_metrics where run_id = :runId
                    """, Map.of("runId", runId), Long.class));

            var cadence = new AiGridBudgetService.CadenceCommand(
                    "AWS", "BEDROCK_AGENTS", "PRODUCTION", "HIGH", 3600, true,
                    "Prevent redundant provider scans");
            budgetService.update(tenant, new AiGridBudgetService.BudgetConfigCommand(
                    "THROTTLE", 10L, null, null, null, null, 0.8,
                    "Integration cadence gate"), "integration-reviewer");
            budgetService.upsertCadence(tenant, cadence, "integration-reviewer");
            budgetService.admit(tenant, runId, "AWS", List.of("BEDROCK_AGENTS"), "PRODUCTION", "HIGH");
            assertEquals("ADMITTED", budgetService.admit(tenant, runId, "AWS",
                    List.of("BEDROCK_AGENTS"), "PRODUCTION", "HIGH").decision(),
                    "an admission retry must return the persisted decision");
            var cadenceError = assertThrows(AiGridBudgetService.BudgetExceededException.class,
                    () -> budgetService.admit(tenant, UUID.randomUUID(), "AWS",
                            List.of("BEDROCK_AGENTS"), "PRODUCTION", "HIGH"));
            assertEquals("CADENCE_NOT_DUE", cadenceError.getMessage());
            budgetService.upsertCadence(tenant, new AiGridBudgetService.CadenceCommand(
                    "AWS", "BEDROCK_AGENTS", "PRODUCTION", "HIGH", 3600, false,
                    "Disable cadence to isolate hard budget test"), "integration-reviewer");

            budgetService.update(tenant, new AiGridBudgetService.BudgetConfigCommand(
                    "THROTTLE", 1L, null, null, null, null, 0.8,
                    "Integration budget gate"), "integration-reviewer");
            assertThrows(AiGridBudgetService.BudgetExceededException.class, () -> budgetService.admit(
                    tenant, UUID.randomUUID(), "AWS", List.of("BEDROCK_AGENTS"), "PRODUCTION", "HIGH"));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from ai_grid_budget_alerts
                     where metric = 'DAILY_SCANS' and level = 'EXCEEDED' and status = 'OPEN'
                    """, Map.of(), Integer.class));

            UUID guardrailBodyId = jdbc.queryForObject("""
                    select b.id from ai_grid_snapshot_bodies b
                      join ai_grid_snapshot_manifests m on m.body_id = b.id
                      join ai_security_artifacts a on a.id = m.artifact_id
                     where a.native_kind = 'AWS_BEDROCK_GUARDRAIL' limit 1
                    """, Map.of(), UUID.class);
            jdbc.update("""
                    insert into ai_grid_snapshot_bodies
                        (id, tenant_id, content_hash, content_json, byte_size, redaction_profile,
                         first_run_id, retention_class, retain_until, retention_state)
                    values (:id, :tenantId, :hash, '{}'::jsonb, 2, 'STANDARD', :runId,
                            'ARCHIVE', now() - interval '1 day', 'RETAINED')
                    """, Map.of("id", UUID.randomUUID(), "tenantId", tenant.getId(),
                    "hash", "f".repeat(64), "runId", runId));
            var hold = retentionService.createHold(tenant, new AiGridRetentionService.HoldCommand(
                    guardrailBodyId, "LEGAL_HOLD", "legal-case-1",
                    "Preserve evidence for legal review", null), "integration-reviewer");
            jdbc.update("update ai_grid_snapshot_bodies set retain_until = now() - interval '1 day'", Map.of());
            var protectedSweep = retentionService.sweep(tenant);
            assertTrue(protectedSweep.purgeBlocked() >= 2);
            assertEquals(1, protectedSweep.purged(), "expired unreferenced evidence should be purged safely");
            assertEquals(1, jdbc.queryForObject("select count(*) from ai_grid_retention_purge_audit",
                    Map.of(), Integer.class));
            retentionService.releaseHold(tenant, hold.id(), "integration-reviewer");
            var releasedSweep = retentionService.sweep(tenant);
            assertTrue(releasedSweep.purgeEligible() >= 1);
            assertEquals("PURGE_BLOCKED", jdbc.queryForObject("""
                    select b.retention_state from ai_grid_snapshot_bodies b
                      join ai_grid_snapshot_manifests m on m.body_id = b.id
                      join ai_grid_assessments a on a.snapshot_manifest_id = m.id
                      join findings f on f.assessment_id = a.id
                     where f.status = 'OPEN' limit 1
                    """, Map.of(), String.class));
            return Map.of(
                    "finding", jdbc.queryForObject("""
                            select fingerprint from ai_grid_assessments
                             where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                            """, Map.of("runId", runId), String.class),
                    "decision", jdbc.queryForObject("""
                            select decision_fingerprint from ai_grid_assessments
                             where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                            """, Map.of("runId", runId), String.class));
        });

        UUID reviewedFindingId = tenantExecution.run(tenant, () -> jdbc.queryForObject(
                """
                select id from findings
                 where finding_kind = 'AI_POSTURE'
                   and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                """, Map.of(), UUID.class));
        aiSecurityApiService.review(tenant, reviewedFindingId,
                com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ReviewDisposition.FALSE_POSITIVE,
                "regression: review on the host finding model", "integration-reviewer");
        Integer hostReviewCount = tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select count(*) from finding_reviews where finding_id = :id and disposition = 'FALSE_POSITIVE'
                """, Map.of("id", reviewedFindingId), Integer.class));
        assertEquals(1, hostReviewCount,
                "AI finding review is recorded against the host finding model, not the legacy silo");

        var completeCoverage = aiGridApiService.coverage(tenant);
        jdbc.update("""
                insert into platform.ai_grid_policy_versions (
                    policy_id, version, name, description, severity, lifecycle, workflow_class,
                    default_selection, artifact_types_json, required_capabilities_json,
                    required_relationships_json, required_resource_families_json, required_facts_json,
                    predicate_json, reason_code, remediation, framework_mappings_json,
                    parameter_definitions_json, native_kinds_json, scope_resolution, package_digest, published_at)
                select 'AI_GRID_COVERAGE_OMISSION_TEST', '1.0.0', 'Coverage omission test', description,
                       severity, 'VALIDATED', workflow_class, 'PREVIEW', artifact_types_json,
                       required_capabilities_json, required_relationships_json,
                       required_resource_families_json, required_facts_json, predicate_json,
                       'AI_GRID_COVERAGE_OMISSION', remediation, framework_mappings_json,
                       parameter_definitions_json, native_kinds_json, scope_resolution,
                       'integration-test-coverage-omission-digest', null
                  from platform.ai_grid_policy_versions
                 where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' and version = '2.0.0'
                on conflict do nothing
                """, Map.of());
        jdbc.update("""
                insert into platform.ai_grid_policy_release_decisions
                    (id, policy_id, policy_version, package_digest, decision, reason, decided_by)
                select md5('AI_GRID_COVERAGE_OMISSION_TEST:1.0.0')::uuid,
                       policy_id, version, package_digest, 'APPROVED',
                       'Integration-test package approval', 'integration-test'
                  from platform.ai_grid_policy_versions
                 where policy_id = 'AI_GRID_COVERAGE_OMISSION_TEST' and version = '1.0.0'
                on conflict do nothing
                """, Map.of());
        jdbc.update("""
                update platform.ai_grid_policy_versions
                   set lifecycle='PUBLISHED', published_at=now(), approved_by='integration-test', approved_at=now()
                 where policy_id = 'AI_GRID_COVERAGE_OMISSION_TEST' and version = '1.0.0'
                """, Map.of());
        jdbc.update("""
                insert into platform.ai_grid_policy_distribution
                    (policy_id, available, default_selection, rollout_stage, pinned_version,
                     approved_package_digest, release_decision_id, updated_by)
                select 'AI_GRID_COVERAGE_OMISSION_TEST', true, 'PREVIEW', 'GENERAL_AVAILABILITY', '1.0.0',
                       p.package_digest, r.id, 'integration-test'
                  from platform.ai_grid_policy_versions p
                  join platform.ai_grid_policy_release_decisions r
                    on r.policy_id=p.policy_id and r.policy_version=p.version
                   and r.decision='APPROVED' and r.package_digest=p.package_digest
                 where p.policy_id='AI_GRID_COVERAGE_OMISSION_TEST' and p.version='1.0.0'
                on conflict (policy_id) do update set
                    available = excluded.available,
                    default_selection = excluded.default_selection,
                    rollout_stage = excluded.rollout_stage,
                    approved_package_digest = excluded.approved_package_digest,
                    release_decision_id = excluded.release_decision_id,
                    updated_by = excluded.updated_by,
                    updated_at = now()
                """, Map.of());
        tenantExecution.run(tenant, () -> reconciliationService.reconcile(tenant, runId));
        tenantExecution.run(tenant, () -> {
            UUID epochId = coverageService.refreshCurrent(tenant, runId);
            reconciliationService.reconcileCurrent(tenant, epochId, runId);
            return null;
        });
        var incompleteCoverage = aiGridApiService.coverage(tenant);
        assertEquals(runId, incompleteCoverage.runId());
        assertEquals(completeCoverage.expectedAssessments() + 1, incompleteCoverage.expectedAssessments());
        assertEquals(completeCoverage.recordedAssessments(), incompleteCoverage.recordedAssessments());
        assertEquals(completeCoverage.missingAssessments() + 1, incompleteCoverage.missingAssessments());
        assertTrue(incompleteCoverage.decisionReachabilityPercent()
                < completeCoverage.decisionReachabilityPercent());
        assertEquals(completeCoverage.ownerFacingDecisionReachabilityPercent(),
                incompleteCoverage.ownerFacingDecisionReachabilityPercent());
        assertEquals("MISSING_ASSESSMENT", aiGridApiService.coverageDetails(tenant).stream()
                .filter(item -> "AI_GRID_COVERAGE_OMISSION_TEST".equals(item.policyId()))
                .findFirst().orElseThrow().gapState());
        assertEquals(1, tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select count(*) from ai_grid_coverage_gaps
                 where run_id = :runId and policy_id = 'AI_GRID_COVERAGE_OMISSION_TEST'
                   and state = 'MISSING_ASSESSMENT' and status = 'OPEN'
                """, Map.of("runId", runId), Integer.class)));
        aiGridApiService.executeSelectedPolicies(tenant, java.util.Set.of("AI_GRID_COVERAGE_OMISSION_TEST"));
        assertEquals(0, aiGridApiService.coverage(tenant).missingAssessments());
        assertEquals(0, tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select count(*) from ai_grid_coverage_gaps
                 where policy_id = 'AI_GRID_COVERAGE_OMISSION_TEST'
                   and state = 'MISSING_ASSESSMENT' and status = 'OPEN'
                """, Map.of(), Integer.class)));
        jdbc.update("delete from platform.ai_grid_policy_versions where policy_id = 'AI_GRID_COVERAGE_OMISSION_TEST'",
                Map.of());

        tenantExecution.run(tenant, () -> {
            jdbc.update("update ai_grid_snapshot_manifests set observed_at = now() - interval '48 hours' where run_id = :runId",
                    Map.of("runId", runId));
            jdbc.update("update ai_grid_facts set observed_at = now() - interval '49 hours' where run_id = :runId",
                    Map.of("runId", runId));
            jdbc.update("""
                    update ai_grid_relationship_snapshots
                       set observed_at = now() - interval '48 hours 1 second',
                           valid_from = now() - interval '48 hours 1 second'
                     where run_id = :runId
                    """, Map.of("runId", runId));
            return null;
        });
        aiGridApiService.replay(tenant, runId);
        String agedDecisionFingerprint = tenantExecution.run(tenant, () -> {
            Map<String, Object> replayed = jdbc.queryForMap("""
                    select fingerprint, decision_fingerprint, decision,
                           evaluation_as_of = (select max(observed_at) from ai_grid_snapshot_manifests
                                                where run_id = :runId) as stable_as_of
                      from ai_grid_assessments
                     where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of("runId", runId));
            assertEquals(originalFingerprints.get("finding"), replayed.get("fingerprint"));
            assertEquals("FAIL", replayed.get("decision"),
                    "wall-clock passage must not turn a replayed decision into stale evidence");
            assertEquals(false, replayed.get("stable_as_of"), "Historical replay must not replace a newer current assessment row");
            return (String) replayed.get("decision_fingerprint");
        });
        aiGridApiService.replay(tenant, runId);
        tenantExecution.run(tenant, () -> {
            assertEquals(agedDecisionFingerprint, jdbc.queryForObject("""
                    select decision_fingerprint from ai_grid_assessments
                     where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of("runId", runId), String.class),
                    "identical stored policy and fact material must reproduce the decision-content hash");
            return null;
        });

        Tenant isolatedTenant = provision("AI Grid R0 Isolated Co", "ai-grid-r0-isolated-co");
        assertEquals(0, tenantExecution.run(isolatedTenant, () -> jdbc.queryForObject(
                "select count(*) from ai_grid_snapshot_manifests", Map.of(), Integer.class)),
                "AI Grid evidence must remain isolated in the owning tenant schema");

        UUID findingId = tenantExecution.run(tenant, () -> jdbc.queryForObject(
                """
                select id from findings
                 where finding_kind = 'AI_POSTURE'
                   and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                """,
                Map.of(), UUID.class));
        tenantExecution.run(tenant, () -> findingWorkflowService.updateWorkflow(findingId,
                new FindingWorkflowUpdateRequest("SUPPRESSED", null, null, null,
                        "Approved investigation window", Instant.now().plus(1, ChronoUnit.DAYS),
                        "integration-reviewer")));

        UUID suppressedFailureRun = ingestR0Run(tenant, connectorId, "LOW", "suppressed-failure", true);
        tenantExecution.run(tenant, () -> {
            assertEquals("SUPPRESSED", jdbc.queryForObject(
                    "select status from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals(suppressedFailureRun, jdbc.queryForObject(
                    "select last_observed_run_id from findings where id = :id", Map.of("id", findingId), UUID.class));
            return null;
        });

        UUID remediationRun = ingestR0Run(tenant, connectorId, "MEDIUM", "verified-remediation", true);
        tenantExecution.run(tenant, () -> {
            assertEquals("RESOLVED", jdbc.queryForObject(
                    "select status from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals("VERIFIED_REMEDIATION", jdbc.queryForObject(
                    "select closed_reason from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals(remediationRun, jdbc.queryForObject(
                    "select last_observed_run_id from findings where id = :id", Map.of("id", findingId), UUID.class));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from finding_events
                     where finding_id = :id and event_type = 'RESOLVED_BY_VERIFIED_REASSESSMENT'
                    """, Map.of("id", findingId), Integer.class));
            return null;
        });

        UUID recurrenceRun = ingestR0Run(tenant, connectorId, "LOW", "recurrence", true);
        tenantExecution.run(tenant, () -> {
            assertEquals("OPEN", jdbc.queryForObject(
                    "select status from findings where id = :id", Map.of("id", findingId), String.class));
            assertNull(jdbc.queryForObject(
                    "select closed_reason from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals(recurrenceRun, jdbc.queryForObject(
                    "select last_observed_run_id from findings where id = :id", Map.of("id", findingId), UUID.class));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from finding_events
                     where finding_id = :id and event_type = 'REOPENED_BY_OBSERVATION'
                    """, Map.of("id", findingId), Integer.class));
            return null;
        });

        UUID incompleteRun = ingestR0Run(tenant, connectorId, "LOW", "incomplete-remediation", false);
        tenantExecution.run(tenant, () -> {
            assertEquals("FAIL", jdbc.queryForObject("""
                    select decision from ai_grid_assessments
                     where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """, Map.of("runId", incompleteRun), String.class));
            assertEquals("OPEN", jdbc.queryForObject(
                    "select status from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals(incompleteRun, jdbc.queryForObject(
                    "select last_observed_run_id from findings where id = :id",
                    Map.of("id", findingId), UUID.class),
                    "fresh prior complete guardrail heads can qualify the current failure");
            return null;
        });

        try {
            jdbc.update("""
                    update platform.ai_grid_policy_versions
                       set required_facts_json = jsonb_set(required_facts_json, '{0,minConfidence}', '0.9'::jsonb)
                     where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' and version = '2.0.0'
                    """, Map.of());
            tenantExecution.run(tenant, () -> {
                jdbc.update("update ai_grid_facts set confidence = 0.5 where run_id = :runId",
                        Map.of("runId", incompleteRun));
                assertEquals(0.9, jdbc.queryForObject("""
                        select (required_facts_json->0->>'minConfidence')::double precision
                          from platform.ai_grid_policy_versions
                         where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' and version = '2.0.0'
                        """, Map.of(), Double.class));
                assertEquals(0, jdbc.queryForObject("""
                        select count(*) from ai_grid_facts
                         where run_id = :runId and confidence is distinct from 0.5
                        """, Map.of("runId", incompleteRun), Integer.class));
                assertTrue(jdbc.queryForObject("""
                        select count(*) > 0
                          from ai_grid_snapshot_manifests m
                          join ai_grid_snapshot_bodies b on b.id = m.body_id
                         where m.run_id = :runId
                           and b.content_json->>'artifactType' = 'AI_AGENT'
                           and b.content_json->>'nativeKind' = 'AWS_BEDROCK_AGENT'
                        """, Map.of("runId", incompleteRun), Boolean.class));
                assertEquals(1, jdbc.queryForObject("""
                        select count(*) from platform.ai_grid_policy_versions
                         where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' and lifecycle = 'PUBLISHED'
                        """, Map.of(), Integer.class));
                jdbc.update("update ai_grid_assessments set evaluated_at = '2000-01-01' where run_id = :runId",
                        Map.of("runId", incompleteRun));
                return null;
            });
            aiGridApiService.executeSelectedPolicies(tenant, java.util.Set.of("AWS_BEDROCK_WEAK_GUARDRAIL"));
            tenantExecution.run(tenant, () -> {
                assertTrue(jdbc.queryForObject("""
                        select evaluated_at > '2000-01-02' from ai_grid_assessments
                         where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                        """, Map.of("runId", incompleteRun), Boolean.class),
                        "current reassessment must use the latest complete source head");
                assertEquals("NO_DECISION", jdbc.queryForObject("""
                        select decision from ai_grid_assessments
                         where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                        """, Map.of("runId", incompleteRun), String.class));
                assertEquals("LOW_CONFIDENCE", jdbc.queryForObject("""
                        select evidence_readiness from ai_grid_assessments
                         where run_id = :runId and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                        """, Map.of("runId", incompleteRun), String.class));
                assertEquals("OPEN", jdbc.queryForObject(
                        "select status from findings where id = :id", Map.of("id", findingId), String.class));
                return null;
            });
        } finally {
            jdbc.update("""
                    update platform.ai_grid_policy_versions
                       set required_facts_json = required_facts_json #- '{0,minConfidence}'
                     where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL' and version = '2.0.0'
                    """, Map.of());
        }

        // Required controls are intentionally immutable for tenants.  Use an enabled
        // distribution in this isolated test to exercise the owner-facing closure path.
        jdbc.update("""
                update platform.ai_grid_policy_distribution
                   set default_selection = 'ENABLED', updated_at = now()
                 where policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                """, Map.of());
        aiGridApiService.updateSelection(tenant, "AWS_BEDROCK_WEAK_GUARDRAIL", "DISABLED",
                "integration-reviewer", "Validate governance downgrade lifecycle");
        aiGridApiService.replay(tenant, recurrenceRun);
        tenantExecution.run(tenant, () -> {
            assertEquals("AUTO_CLOSED", jdbc.queryForObject(
                    "select status from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals("AUTO_POLICY_NOT_OWNER_FACING", jdbc.queryForObject(
                    "select closed_reason from findings where id = :id", Map.of("id", findingId), String.class));
            assertEquals(1, jdbc.queryForObject("""
                    select count(*) from finding_events
                     where finding_id = :id and event_type = 'AUTO_CLOSED'
                    """, Map.of("id", findingId), Integer.class));
            return null;
        });

        tenantExecution.run(tenant, () -> {
            assertThrows(DataIntegrityViolationException.class, () -> jdbc.update(
                    "update findings set finding_kind = 'VULNERABILITY' where id = :id",
                    Map.of("id", findingId)));
            return null;
        });
    }

    @Test
    void aiGridFinalizationFailurePreservesCollectionAndCanRecoverDurably() {
        Tenant tenant = provision("AI Grid Atomic Co", "ai-grid-atomic-co");
        UUID connectorId = connectorService.save(tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        ArtifactObservation agent = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/atomic-agent",
                "AI_AGENT", "AWS_BEDROCK_AGENT", "Atomic agent",
                Map.of("guardrailAttached", true, "guardrailMinimumStrength", "LOW"));
        ArtifactObservation guardrail = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:guardrail/atomic-guardrail",
                "GUARDRAIL", "AWS_BEDROCK_GUARDRAIL", "Atomic guardrail", Map.of());
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                runId + ":atomic-agents:0", "atomic-agent-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(agent, guardrail), List.of(new RelationshipObservation(
                        agent.providerResourceId(), guardrail.providerResourceId(), "USES_GUARDRAIL", Map.of())),
                List.of()));

        Map<String, Integer> baseline = tenantExecution.run(tenant, () -> Map.of(
                "assessments", count("ai_grid_assessments"),
                "outbox", count("ai_grid_outbox"),
                "findings", count("findings"),
                "receipts", count("ai_security_observation_receipts")));
        ObservationEnvelopeV1 completingScope = new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_GUARDRAILS",
                "AWS:123456789012:us-east-1:BEDROCK_GUARDRAILS", 0, 1,
                runId + ":atomic-guardrail:0", "atomic-guardrail-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(guardrail), List.of(), List.of());

        doThrow(new IllegalStateException("injected reconciliation failure"))
                .when(reconciliationService).reconcileCurrent(eq(tenant), org.mockito.ArgumentMatchers.any(UUID.class), eq(runId));
        assertEquals(ScopeStatus.COMPLETE, observationService.ingest(tenant, completingScope).scopeStatus());
        reset(reconciliationService);

        tenantExecution.run(tenant, () -> {
            assertTrue(count("ai_grid_assessments")>=baseline.get("assessments"));
            assertTrue(count("ai_grid_outbox")>baseline.get("outbox"));
            assertTrue(count("findings")>=baseline.get("findings"));
            assertEquals(baseline.get("receipts")+1,count("ai_security_observation_receipts"));
            assertEquals(1,jdbc.queryForObject("select count(*) from ai_security_snapshot_scopes where scope_key=:scope and status='COMPLETE'",
                    Map.of("scope",completingScope.scopeKey()),Integer.class));
            UUID failed=jdbc.queryForObject("select id from ai_grid_outbox where event_type='STATIC_ASSESSMENT_REQUESTED' and status='FAILED' order by created_at desc limit 1",Map.of(),UUID.class);
            assessmentWorker.replayFailure(tenant,failed);
            return null;
        });
        assessmentWorker.recover();

        observationService.ingest(tenant, completingScope);
        tenantExecution.run(tenant, () -> {
            assertEquals(1, jdbc.queryForObject(
                    """
                    select count(*) from findings
                     where finding_kind = 'AI_POSTURE'
                       and policy_id = 'AWS_BEDROCK_WEAK_GUARDRAIL'
                    """,
                    Map.of(), Integer.class));
            assertTrue(count("ai_grid_outbox") > baseline.get("outbox"));
            return null;
        });
    }

    @Test
    void azureRaiPolicySliceProducesFailPassAndNoDecisionWithoutOverclaiming() {
        Tenant tenant = provision("Azure RAI Answer Key", "azure-rai-answer-key");
        UUID connectorId = azureConnector(tenant);

        UUID unsafeRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, raiEnvelope(
                tenant, connectorId, unsafeRun, "rai-unsafe",
                Map.of("raiFilterEvidenceComplete", true, "raiNonBlockingFilterObserved", true)));
        tenantExecution.run(tenant, () -> {
            assertEquals("FAIL", raiDecision(unsafeRun));
            assertEquals(1, jdbc.queryForObject(
                    """
                    select count(*) from findings
                     where finding_kind = 'AI_POSTURE' and status = 'OPEN'
                       and policy_id = 'AZURE_RAI_POLICY_NON_BLOCKING_FILTER'
                    """,
                    Map.of(), Integer.class));
            return null;
        });

        UUID safeRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, raiEnvelope(
                tenant, connectorId, safeRun, "rai-safe",
                Map.of("raiFilterEvidenceComplete", true, "raiNonBlockingFilterObserved", false)));
        tenantExecution.run(tenant, () -> {
            assertEquals("PASS", raiDecision(safeRun));
            assertEquals(0, jdbc.queryForObject(
                    """
                    select count(*) from findings
                     where finding_kind = 'AI_POSTURE' and status = 'OPEN'
                       and policy_id = 'AZURE_RAI_POLICY_NON_BLOCKING_FILTER'
                    """,
                    Map.of(), Integer.class));
            return null;
        });

        UUID incompleteRun = syncRunFacade.start(tenant).getId();
        observationService.ingest(tenant, raiEnvelope(
                tenant, connectorId, incompleteRun, "rai-incomplete",
                Map.of("raiFilterEvidenceComplete", false)));
        tenantExecution.run(tenant, () -> {
            assertEquals("NO_DECISION", raiDecision(incompleteRun));
            assertEquals("MISSING_FACTS", jdbc.queryForObject("""
                    select evidence_readiness from ai_grid_assessments
                     where run_id = :runId and policy_id = 'AZURE_RAI_POLICY_NON_BLOCKING_FILTER'
                    """, Map.of("runId", incompleteRun), String.class));
            return null;
        });
    }

    @Test
    void persistsAndProjectsPiiClassificationFields() {
        Tenant tenant = provision("Pii Co", "pii-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();
        UUID runId = syncRunFacade.start(tenant).getId();
        Instant scannedAt = Instant.parse("2026-08-01T00:00:00Z");
        ArtifactObservation bucket = new ArtifactObservation(
                "arn:aws:s3:::pii-bucket",
                "SUPPORTING_RESOURCE",
                "AWS_S3_BUCKET",
                "pii-bucket",
                Map.of("public", false),
                "SCANNED_PII_FOUND",
                "AWS_MACIE",
                List.of("EMAIL_ADDRESS", "NAME"),
                2,
                scannedAt);
        observationService.ingest(tenant, envelope(
                tenant, connectorId, runId, "pii-hash-1", ScopeStatus.COMPLETE, List.of(bucket)));

        var page = aiSecurityApiService.artifacts(tenant, null, 0, 10);
        var artifact = page.items().stream()
                .filter(item -> item.providerResourceId().equals("arn:aws:s3:::pii-bucket"))
                .findFirst().orElseThrow();
        assertEquals("SCANNED_PII_FOUND", artifact.piiScanStatus());
        assertEquals("AWS_MACIE", artifact.piiSource());
        assertEquals(List.of("EMAIL_ADDRESS", "NAME"), artifact.piiInfoTypes());
        assertEquals(2, artifact.piiFindingCount());
        assertEquals(scannedAt, artifact.piiLastScannedAt());
    }

    private ObservationEnvelopeV1 raiEnvelope(
            Tenant tenant, UUID connectorId, UUID runId, String hash, Map<String, Object> attributes
    ) {
        ArtifactObservation policy = new ArtifactObservation(
                "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.CognitiveServices/accounts/ai/raiPolicies/production",
                "AI_GUARDRAIL", "AZURE_RAI_POLICIES", "production", attributes);
        String scopeKey = "AZURE:sub:eastus:AZURE_RAI_POLICIES";
        return new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AZURE",
                "azure-test-tenant", "sub", "eastus", "AZURE_RAI_POLICIES", scopeKey, 0, 1,
                runId + ":rai:0", hash, Instant.now(), ScopeStatus.COMPLETE,
                List.of(policy), List.of(), List.of());
    }

    private String raiDecision(UUID runId) {
        return jdbc.queryForObject("""
                select decision from ai_grid_assessments
                 where run_id = :runId and policy_id = 'AZURE_RAI_POLICY_NON_BLOCKING_FILTER'
                """, Map.of("runId", runId), String.class);
    }

    private UUID azureConnector(Tenant tenant) {
        UUID connectorId = UUID.randomUUID();
        return tenantExecution.run(tenant, () -> {
            jdbc.update("""
                    insert into ai_security_connector_configs
                        (id, tenant_id, provider, account_id, provider_tenant_id,
                         regions_json, resource_families_json, enabled)
                    values (:id, :tenantId, 'AZURE', 'sub', 'azure-test-tenant',
                            '["eastus"]'::jsonb, '["AZURE_RAI_POLICIES"]'::jsonb, true)
                    """, Map.of("id", connectorId, "tenantId", tenant.getId()));
            return connectorId;
        });
    }

    private int count(String table) {
        return jdbc.queryForObject("select count(*) from " + table, Map.of(), Integer.class);
    }

    private UUID ingestR0Run(Tenant tenant, UUID connectorId, String strength, String suffix,
                             boolean completeGuardrailScope) {
        UUID runId = syncRunFacade.start(tenant).getId();
        ArtifactObservation agent = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/r0-agent",
                "AI_AGENT", "AWS_BEDROCK_AGENT", "R0 agent",
                Map.of("guardrailAttached", true, "guardrailMinimumStrength", strength,
                        "tags", Map.of("team", "AI Platform Team")));
        ArtifactObservation guardrail = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:guardrail/r0-guardrail",
                "GUARDRAIL", "AWS_BEDROCK_GUARDRAIL", "R0 guardrail", Map.of());
        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                runId + ":agents:0", suffix + "-agent", Instant.now(), ScopeStatus.COMPLETE,
                List.of(agent, guardrail), List.of(new RelationshipObservation(
                        agent.providerResourceId(), guardrail.providerResourceId(), "USES_GUARDRAIL", Map.of())),
                List.of()));
        if (completeGuardrailScope) {
            observationService.ingest(tenant, new ObservationEnvelopeV1(
                    AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                    "123456789012", "us-east-1", "BEDROCK_GUARDRAILS",
                    "AWS:123456789012:us-east-1:BEDROCK_GUARDRAILS", 0, 1,
                    runId + ":guardrails:0", suffix + "-guardrail", Instant.now(), ScopeStatus.COMPLETE,
                    List.of(guardrail), List.of(), List.of()));
        }
        return runId;
    }

    private Tenant provision(String name, String slug) {
        Tenant tenant = tenantService.createTenant(name, slug, "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);
        return tenant;
    }

    private int activeArtifacts(Tenant tenant) {
        return tenantExecution.run(tenant, () -> jdbc.queryForObject(
                "select count(*) from ai_security_artifacts where active = true",
                Map.of(),
                Integer.class));
    }

    private String wildcardRoleOutcome(Tenant tenant, UUID runId) {
        return tenantExecution.run(tenant, () -> jdbc.queryForObject("""
                select decision
                  from ai_grid_assessments
                 where run_id = :runId
                   and policy_id = 'AWS_BEDROCK_WILDCARD_AGENT_ROLE'
                """, Map.of("runId", runId), String.class));
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
                List.of(),
                List.of());
    }

    private ObservationEnvelopeV1 envelope(
            Tenant tenant,
            UUID connectorId,
            UUID runId,
            String hash,
            ScopeStatus status,
            List<ArtifactObservation> artifacts
    ) {
        return new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION,
                runId,
                connectorId,
                tenant.getId(),
                "AWS",
                "123456789012",
                "us-east-1",
                "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS",
                0,
                1,
                runId + ":BEDROCK_AGENTS:0",
                hash,
                Instant.now(),
                status,
                artifacts,
                List.of(),
                List.of());
    }
}
