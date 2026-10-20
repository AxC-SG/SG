package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ArtifactObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ObservationEnvelopeV1;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.RelationshipObservation;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.ScopeStatus;
import com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService;
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
import org.springframework.web.server.ResponseStatusException;

/** Covers AiSecurityApiService.graph()'s new depth parameter and, more importantly,
 * that multi-hop traversal can never cross a tenant boundary regardless of depth. */
@PostgresIntegrationTest
@TestPropertySource(properties = "spring.main.allow-circular-references=true")
class AiSecurityGraphPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_security_graph");

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
    void depthParameterExpandsTraversalToMultiHopNeighbors() {
        Tenant tenant = provision("Graph Depth Co", "graph-depth-co");
        UUID connectorId = connectorService.save(
                tenant,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();
        UUID runId = syncRunFacade.start(tenant).getId();

        ArtifactObservation agent = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/depth-agent",
                "AI_AGENT", "AWS_BEDROCK_AGENT", "Depth agent", Map.of());
        ArtifactObservation alias = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent-alias/depth-agent/depth-alias",
                "AI_COMPONENT", "AWS_BEDROCK_AGENT_ALIAS", "Depth alias", Map.of());
        ArtifactObservation version = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/depth-agent/version/1",
                "AI_AGENT_VERSION", "AWS_BEDROCK_AGENT_VERSION", "Depth version", Map.of());

        observationService.ingest(tenant, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runId, connectorId, tenant.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                runId + ":depth:0", "depth-hash", Instant.now(), ScopeStatus.COMPLETE,
                List.of(agent, alias, version),
                List.of(
                        new RelationshipObservation(agent.providerResourceId(), alias.providerResourceId(),
                                "HAS_COMPONENT", Map.of()),
                        new RelationshipObservation(alias.providerResourceId(), version.providerResourceId(),
                                "SERVES_VERSION", Map.of())),
                List.of()));

        UUID agentId = tenantExecution.run(tenant, () -> jdbc.queryForObject(
                "select id from ai_security_artifacts where native_kind = 'AWS_BEDROCK_AGENT'",
                Map.of(), UUID.class));

        var depth1 = apiService.graph(tenant, agentId, 1);
        assertEquals(1, depth1.edges().size(), "depth 1 must only surface the agent's direct edge");
        assertEquals(2, depth1.nodes().size(), "depth 1 nodes: agent + alias only");

        var depth2 = apiService.graph(tenant, agentId, 2);
        assertEquals(2, depth2.edges().size(), "depth 2 must include the second hop to the model");
        assertEquals(3, depth2.nodes().size(), "depth 2 nodes: agent + alias + version");
    }

    @Test
    void graphNeverCrossesIntoAnotherTenantsRelationships() {
        Tenant tenantA = provision("Graph Tenant A", "graph-tenant-a");
        Tenant tenantB = provision("Graph Tenant B", "graph-tenant-b");

        UUID connectorA = connectorService.save(
                tenantA,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();
        UUID runA = syncRunFacade.start(tenantA).getId();
        ArtifactObservation agentA = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/tenant-a-agent",
                "AI_AGENT", "AWS_BEDROCK_AGENT", "Tenant A agent", Map.of());
        ArtifactObservation aliasA = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent-alias/tenant-a-agent/alias-a",
                "AI_COMPONENT", "AWS_BEDROCK_AGENT_ALIAS", "Tenant A alias", Map.of());
        observationService.ingest(tenantA, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runA, connectorA, tenantA.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                runA + ":isolation:0", "isolation-hash-a", Instant.now(), ScopeStatus.COMPLETE,
                List.of(agentA, aliasA),
                List.of(new RelationshipObservation(agentA.providerResourceId(), aliasA.providerResourceId(),
                        "HAS_COMPONENT", Map.of())),
                List.of()));

        UUID connectorB = connectorService.save(
                tenantB,
                new AiSecurityAwsConnectorService.ConnectorConfigRequest(
                        "123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)
        ).id();
        UUID runB = syncRunFacade.start(tenantB).getId();
        ArtifactObservation agentB = new ArtifactObservation(
                "arn:aws:bedrock:us-east-1:123456789012:agent/tenant-a-agent",
                "AI_AGENT", "AWS_BEDROCK_AGENT", "Tenant B agent posing as tenant A's ARN", Map.of());
        observationService.ingest(tenantB, new ObservationEnvelopeV1(
                AiSecurityObservationService.CONTRACT_VERSION, runB, connectorB, tenantB.getId(), "AWS",
                "123456789012", "us-east-1", "BEDROCK_AGENTS",
                "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                runB + ":isolation:0", "isolation-hash-b", Instant.now(), ScopeStatus.COMPLETE,
                List.of(agentB), List.of(), List.of()));

        UUID agentAId = tenantExecution.run(tenantA, () -> jdbc.queryForObject(
                "select id from ai_security_artifacts where native_kind = 'AWS_BEDROCK_AGENT'",
                Map.of(), UUID.class));

        var graphFromTenantA = apiService.graph(tenantA, agentAId, 2);
        assertEquals(2, graphFromTenantA.nodes().size(),
                "tenant A's graph must only ever contain tenant A's own artifacts");
        assertTrue(graphFromTenantA.nodes().stream()
                        .noneMatch(node -> "Tenant B agent posing as tenant A's ARN".equals(node.name())),
                "tenant B's artifact must never appear in tenant A's graph, even with a colliding ARN");

        assertThrows(ResponseStatusException.class, () -> apiService.graph(tenantB, agentAId, 2),
                "resolving tenant A's artifact id while scoped to tenant B's schema must 404, not leak");
    }

    private Tenant provision(String name, String slug) {
        Tenant tenant = tenantService.createTenant(name, slug, "pilot", null);
        tenantSchemaMigrationService.provisionNewTenant(tenant);
        return tenant;
    }
}
