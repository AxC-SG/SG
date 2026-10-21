package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.aisecurity.service.AiGridExposureService;
import com.prototype.vulnwatch.aisecurity.service.AiGridCoverageService;
import com.prototype.vulnwatch.aisecurity.service.AiGridApiService;
import com.prototype.vulnwatch.aisecurity.service.AiGridHostContextService;
import com.prototype.vulnwatch.aisecurity.service.AiGridHostContextService.HostFactInput;
import com.prototype.vulnwatch.aisecurity.service.AiGridHostContextService.TrustedFactInput;
import com.prototype.vulnwatch.aisecurity.service.AiGridSystemService;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantSchemaExecutionService;
import com.prototype.vulnwatch.service.TenantSchemaMigrationService;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresITSupport;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

@PostgresIntegrationTest
class AiGridR2ExposurePostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("ai_grid_r2_exposure");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private TenantService tenants;
    @Autowired private TenantSchemaMigrationService migrations;
    @Autowired private TenantSchemaExecutionService tenantExecution;
    @Autowired private NamedParameterJdbcTemplate jdbc;
    @Autowired private AiGridSystemService systems;
    @Autowired private AiGridExposureService exposures;
    @Autowired private AiGridCoverageService coverage;
    @Autowired private AiGridApiService api;
    @Autowired private AiGridHostContextService hostContext;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private com.prototype.vulnwatch.aisecurity.service.AiGridExposureFreshnessService freshness;
    @Autowired private com.prototype.vulnwatch.aisecurity.service.AiSecurityApiService customerApi;

    @Test
    void exposureGraduatesDemotesClosesAndReopensWithStableIdentity() {
        Tenant tenant = tenants.createTenant("R2 exposure " + UUID.randomUUID(),
                "r2-exposure-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        UUID agent = UUID.randomUUID();
        UUID knowledgeBase = UUID.randomUUID();
        tenantExecution.run(tenant, () -> {
            seedArtifact(tenant, agent, "AI_AGENT", "AWS_BEDROCK_AGENT", "agent");
            seedArtifact(tenant, knowledgeBase, "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "kb");

            UUID hypothesisRun = seedRun(tenant, agent, knowledgeBase, true, true);
            systems.deriveForRun(tenant, hypothesisRun);
            var hypothesis = exposures.correlateCompleteRun(tenant, hypothesisRun);
            assertEquals(1, hypothesis.hypotheses());
            assertEquals(0, hypothesis.validated());
            UUID exposureId = jdbc.queryForObject("select id from ai_grid_exposure_paths", Map.of(), UUID.class);
            assertEquals(0, count("select count(*) from findings where finding_kind='AI_EXPOSURE'"));

            addValidatingFacts(tenant, agent, knowledgeBase, Instant.now().plus(1, ChronoUnit.HOURS));
            UUID validatedRun = seedRun(tenant, agent, knowledgeBase, true, false);
            systems.deriveForRun(tenant, validatedRun);
            var validated = exposures.correlateCompleteRun(tenant, validatedRun);
            assertEquals(1, validated.validated());
            assertEquals(1, validated.graduated());
            assertEquals(exposureId, jdbc.queryForObject("select id from ai_grid_exposure_paths", Map.of(), UUID.class));
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE' and status='OPEN'"));

            jdbc.update("update ai_grid_host_context_facts set valid_until=now()-interval '1 second'", Map.of());
            UUID demotionRun = seedRun(tenant, agent, knowledgeBase, true, true);
            systems.deriveForRun(tenant, demotionRun);
            var demoted = exposures.correlateCompleteRun(tenant, demotionRun);
            assertEquals(1, demoted.demoted());
            assertEquals("EXPOSURE_HYPOTHESIS", jdbc.queryForObject(
                    "select state from ai_grid_exposure_paths where id=:id", Map.of("id", exposureId), String.class));
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE' and status='OPEN'"),
                    "stale evidence demotes the exposure without silently closing its finding");
            assertEquals("NEEDS_EVIDENCE", jdbc.queryForObject(
                    "select workflow_class from findings where finding_kind='AI_EXPOSURE'", Map.of(), String.class));
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE' and due_at is null"),
                    "stale validation pauses the finding SLA until evidence returns");

            UUID closureRun = seedRun(tenant, agent, knowledgeBase, false, true);
            systems.deriveForRun(tenant, closureRun);
            assertEquals(0, exposures.correlateCompleteRun(tenant, closureRun).closed(),
                    "A single run cannot establish authoritative absence across connector heads");
            Instant closureObserved=Instant.now();
            seedCompleteScope(tenant,closureRun,"AWS","AWS:test",closureObserved);
            UUID closureEpoch=coverage.refreshCurrent(tenant,closureRun);
            systems.deriveForCurrentEpoch(tenant,closureEpoch,closureRun);
            assertEquals(1,exposures.correlateCurrentEpoch(tenant,closureEpoch,closureRun).closed());
            assertEquals("CLOSED", jdbc.queryForObject("select status from ai_grid_exposure_paths where id=:id",
                    Map.of("id", exposureId), String.class));
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE' and status='RESOLVED'"));

            addValidatingFacts(tenant, agent, knowledgeBase, Instant.now().plus(1, ChronoUnit.HOURS));
            UUID recurrenceRun = seedRun(tenant, agent, knowledgeBase, true, false);
            systems.deriveForRun(tenant, recurrenceRun);
            exposures.correlateCompleteRun(tenant, recurrenceRun);
            assertEquals(exposureId, jdbc.queryForObject("select id from ai_grid_exposure_paths", Map.of(), UUID.class));
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE' and status='OPEN'"));
            assertEquals(3, count("select count(*) from ai_grid_system_revisions"),
                    "returning to a non-current membership set must produce a new immutable revision");
            return null;
        });
    }

    @Test
    void configurationProxyCannotEnterAValidatingHostPort() {
        Tenant tenant = tenants.createTenant("R2 validation " + UUID.randomUUID(),
                "r2-validation-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant, () -> {
            UUID artifact = UUID.randomUUID();
            seedArtifact(tenant, artifact, "AI_AGENT", "AWS_BEDROCK_AGENT", "agent");
            var validatingAttestation = new AiGridHostContextService.AnalystFactInput(
                    "network.internet_reachability_verified", objectMapper.valueToTree(true), "KNOWN",
                    "REACHABILITY", "analyst://claim", Instant.now(), Instant.now(),
                    Instant.now().plus(1, ChronoUnit.HOURS));
            assertThrows(IllegalArgumentException.class,
                    () -> hostContext.attest(tenant, artifact, validatingAttestation));
            assertThrows(IllegalArgumentException.class, () -> hostContext.ingestTrusted(tenant, artifact,
                    "SCOUT_REACHABILITY_GRAPH", new TrustedFactInput("network.internet_reachability_verified",
                    objectMapper.valueToTree(true), "KNOWN", "probe://null-confidence", Instant.now(), Instant.now(),
                    Instant.now().plus(1, ChronoUnit.HOURS), null)));
            return null;
        });
    }

    @Test
    void lowConfidenceTrustedEvidenceRemainsHypothesisAndCannotCreateFinding() {
        Tenant tenant = tenants.createTenant("R2 low confidence " + UUID.randomUUID(),
                "r2-low-confidence-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant, () -> {
            UUID agent = UUID.randomUUID(); UUID kb = UUID.randomUUID();
            seedArtifact(tenant, agent, "AI_AGENT", "AWS_BEDROCK_AGENT", "agent");
            seedArtifact(tenant, kb, "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "kb");
            Instant validUntil = Instant.now().plus(1, ChronoUnit.HOURS);
            for (var item : List.of(
                    Map.entry(agent, "network.internet_reachability_verified"),
                    Map.entry(agent, "identity.inadequate_authentication_verified"),
                    Map.entry(kb, "data.sensitive_access_confirmed"))) {
                String producer = item.getValue().startsWith("data.") ? "SCOUT_DATA_SECURITY" : "SCOUT_REACHABILITY_GRAPH";
                hostContext.ingestTrusted(tenant, item.getKey(), producer, new TrustedFactInput(item.getValue(),
                        objectMapper.valueToTree(true), "KNOWN", "probe://low-confidence", Instant.now(), Instant.now(),
                        validUntil, 0.50));
            }
            UUID run = seedRun(tenant, agent, kb, true, false);
            systems.deriveForRun(tenant, run);
            var result = exposures.correlateCompleteRun(tenant, run);
            assertEquals(1, result.hypotheses());
            assertEquals(0, result.validated());
            assertEquals(0, count("select count(*) from findings where finding_kind='AI_EXPOSURE'"));
            return null;
        });
    }

    @Test
    void userMembershipDecisionIsAuditedAndLineageDoesNotTransferFindings() {
        Tenant tenant = tenants.createTenant("R2 lineage " + UUID.randomUUID(),
                "r2-lineage-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant, () -> {
            UUID agent = UUID.randomUUID(); UUID kb = UUID.randomUUID(); UUID extra = UUID.randomUUID();
            seedArtifact(tenant, agent, "AI_AGENT", "AWS_BEDROCK_AGENT", "agent");
            seedArtifact(tenant, kb, "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "kb");
            seedArtifact(tenant, extra, "SUPPORTING_RESOURCE", "AWS_S3_BUCKET", "data");
            UUID run = seedRun(tenant, agent, kb, true, false);
            systems.deriveForRun(tenant, run);
            UUID systemId = jdbc.queryForObject("select id from ai_grid_systems", Map.of(), UUID.class);
            int revision = systems.reviseMembership(tenant, systemId, extra, "ACCEPT", "analyst", "Confirmed system member",
                    "SUCCESSOR", java.util.List.of(systemId));
            assertEquals(2, revision);
            assertEquals(1, count("select count(*) from ai_grid_system_membership_decisions where decision='ACCEPT'"));
            assertEquals(1, count("select count(*) from ai_grid_system_lineage_events where event_type='SUCCESSOR'"));
            assertEquals(0, count("select count(*) from finding_subjects where subject_type='AI_SYSTEM'"));
            systems.deriveForRun(tenant, run);
            assertEquals(1, count("""
                    select count(*) from ai_grid_systems s join ai_grid_system_revisions r
                      on r.system_id=s.id and r.revision=s.current_revision
                    join ai_grid_system_memberships m on m.system_revision_id=r.id
                     where s.id='""" + systemId + "' and m.artifact_id='" + extra
                    + "' and m.confidence_method='USER_CONFIRMED'"),
                    "confirmed membership overrides must survive deterministic derivation");
            return null;
        });
    }

    @Test
    void authoritativeEpochCorrelatesAcrossScopeHeadsAndReplaysBoundInputs() {
        Tenant tenant = tenants.createTenant("R2 epoch " + UUID.randomUUID(),
                "r2-epoch-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant, () -> {
            UUID agent = UUID.randomUUID(); UUID kb = UUID.randomUUID();
            UUID agentRun = UUID.randomUUID(); UUID dataRun = UUID.randomUUID(); Instant observed = Instant.now();
            seedArtifact(tenant, agent, "AI_AGENT", "AWS_BEDROCK_AGENT", "agent");
            seedArtifact(tenant, kb, "KNOWLEDGE_BASE", "AZURE_AI_SEARCH", "kb");
            seedManifest(tenant, agentRun, agent, observed, "epoch-agent");
            seedManifest(tenant, dataRun, kb, observed, "epoch-kb");
            jdbc.update("update ai_grid_snapshot_manifests set scope_key='AWS:agents' where run_id=:id", Map.of("id", agentRun));
            jdbc.update("update ai_grid_snapshot_manifests set scope_key='AZURE:data' where run_id=:id", Map.of("id", dataRun));
            seedCompleteScope(tenant, agentRun, "AWS", "AWS:agents", observed);
            seedCompleteScope(tenant, dataRun, "AZURE", "AZURE:data", observed);
            seedRelationship(tenant, agentRun, agent, kb, "USES_KNOWLEDGE_BASE", observed);
            addValidatingFacts(tenant, agent, kb, observed.plus(1, ChronoUnit.HOURS));

            UUID epochId = coverage.refreshCurrent(tenant, dataRun);
            systems.deriveForCurrentEpoch(tenant, epochId, dataRun);
            assertEquals(1, exposures.correlateCurrentEpoch(tenant, epochId, dataRun).validated());
            assertEquals(1, count("select count(*) from ai_grid_exposure_executions where coverage_epoch_id='" + epochId + "'"));
            assertEquals(1, exposures.verifyReplay(tenant, dataRun).validated());
            jdbc.update("update ai_grid_host_context_facts set valid_until=now()-interval '1 second'", Map.of());
            UUID staleEpoch = coverage.refreshCurrent(tenant, dataRun);
            systems.deriveForCurrentEpoch(tenant, staleEpoch, dataRun);
            assertEquals(1, exposures.correlateCurrentEpoch(tenant, staleEpoch, dataRun).demoted());
            assertEquals("EXPOSURE_HYPOTHESIS", jdbc.queryForObject(
                    "select state from ai_grid_exposure_paths", Map.of(), String.class));
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE' and status='OPEN'"));
            assertEquals(1, exposures.verifyReplay(tenant, dataRun).hypotheses());
            return null;
        });
    }

    @Test
    void convergentPathsAreBothRetainedAndSharedFindingStaysOpenWhenOneBreaks() {
        Tenant tenant = tenants.createTenant("R2 shared root " + UUID.randomUUID(),
                "r2-shared-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant, () -> {
            UUID agent = UUID.randomUUID(); UUID left = UUID.randomUUID(); UUID right = UUID.randomUUID(); UUID kb = UUID.randomUUID();
            seedArtifact(tenant, agent, "AI_AGENT", "AWS_BEDROCK_AGENT", "agent");
            seedArtifact(tenant, left, "SUPPORTING_RESOURCE", "AWS_LAMBDA_FUNCTION", "left");
            seedArtifact(tenant, right, "SUPPORTING_RESOURCE", "AWS_LAMBDA_FUNCTION", "right");
            seedArtifact(tenant, kb, "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "kb");
            UUID run = seedGraphRun(tenant, List.of(agent, left, right, kb), List.of(
                    new Relationship(agent, left, "USES_DATA_SOURCE"), new Relationship(agent, right, "USES_DATA_SOURCE"),
                    new Relationship(left, kb, "USES_KNOWLEDGE_BASE"), new Relationship(right, kb, "USES_KNOWLEDGE_BASE")));
            addValidatingFacts(tenant, agent, kb, Instant.now().plus(1, ChronoUnit.HOURS));
            systems.deriveForRun(tenant, run);
            assertEquals(2, exposures.correlateCompleteRun(tenant, run).validated());
            assertEquals(2, count("select count(*) from ai_grid_exposure_paths where status='OPEN'"));
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE'"));
            var firstPage = api.exposures(tenant, null, 1);
            assertEquals(1, firstPage.items().size());
            assertNotNull(firstPage.nextCursor());
            assertEquals(1, api.exposures(tenant, firstPage.nextCursor(), 1).items().size());

            UUID next = seedGraphRun(tenant, List.of(agent, left, right, kb), List.of(
                    new Relationship(agent, left, "USES_DATA_SOURCE"), new Relationship(left, kb, "USES_KNOWLEDGE_BASE")));
            systems.deriveForRun(tenant, next);
            exposures.correlateCompleteRun(tenant, next);
            assertEquals(1, count("select count(*) from findings where finding_kind='AI_EXPOSURE' and status='OPEN'"));
            return null;
        });
    }

    @Test
    void toolPrivilegeAndUntrustedExecutionTemplatesRequireTheirExactRoles() {
        Tenant tenant = tenants.createTenant("R2 templates " + UUID.randomUUID(),
                "r2-templates-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant, () -> {
            UUID toolAgent = UUID.randomUUID(); UUID tool = UUID.randomUUID();
            UUID inputAgent = UUID.randomUUID(); UUID input = UUID.randomUUID();
            seedArtifact(tenant, toolAgent, "AI_AGENT", "AWS_BEDROCK_AGENT", "tool-agent");
            seedArtifact(tenant, tool, "SUPPORTING_RESOURCE", "AWS_LAMBDA_FUNCTION", "tool");
            seedArtifact(tenant, inputAgent, "AI_AGENT", "AWS_BEDROCK_AGENT", "input-agent");
            seedArtifact(tenant, input, "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "input");
            UUID run = seedGraphRun(tenant, List.of(toolAgent, tool, inputAgent, input), List.of(
                    new Relationship(toolAgent, tool, "USES_TOOL"),
                    new Relationship(inputAgent, input, "USES_KNOWLEDGE_BASE")));
            Instant until = Instant.now().plus(1, ChronoUnit.HOURS);
            ingestTrusted(tenant, tool, hostFact("identity.effective_excessive_privilege_derived",
                    "GRAPH_ANALYSIS", "IDENTITY", until, "DERIVED"));
            ingestTrusted(tenant, tool, hostFact("impact.secret_or_consequential_access_confirmed",
                    "CIEM", "IDENTITY", until, "HOST_INTEGRATION"));
            ingestTrusted(tenant, inputAgent, hostFact("agent.autonomous_execution_verified",
                    "GRAPH_ANALYSIS", "ASSET", until, "HOST_INTEGRATION"));
            ingestTrusted(tenant, inputAgent, hostFact("control.execution_boundary_inadequate_verified",
                    "GRAPH_ANALYSIS", "ASSET", until, "HOST_INTEGRATION"));
            ingestTrusted(tenant, input, hostFact("input.untrusted_path_verified",
                    "GRAPH_ANALYSIS", "DATA", until, "HOST_INTEGRATION"));
            systems.deriveForRun(tenant, run);
            assertEquals(2, exposures.correlateCompleteRun(tenant, run).validated());
            assertEquals(1, count("select count(*) from ai_grid_exposure_paths where correlation_id='R2_EXCESSIVE_TOOL_PRIVILEGE'"));
            assertEquals(1, count("select count(*) from ai_grid_exposure_paths where correlation_id='R2_UNTRUSTED_AUTONOMOUS_EXECUTION'"));
            return null;
        });
    }

    @Test
    void excessiveFanOutIsBoundedAndStaleEdgesAreExcluded() {
        Tenant tenant = tenants.createTenant("R2 bounds " + UUID.randomUUID(),
                "r2-bounds-" + UUID.randomUUID(), "pilot", null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant, () -> {
            UUID agent = UUID.randomUUID(); UUID runId = UUID.randomUUID(); Instant observed = Instant.now();
            seedArtifact(tenant, agent, "AI_AGENT", "AWS_BEDROCK_AGENT", "agent");
            seedManifest(tenant, runId, agent, observed, "bounded-agent");
            upsertSource(tenant, runId, agent, observed);
            for (int index = 0; index < 102; index++) {
                UUID target = UUID.randomUUID();
                seedArtifact(tenant, target, "KNOWLEDGE_BASE", "AWS_BEDROCK_KNOWLEDGE_BASE", "kb-" + index);
                seedManifest(tenant, runId, target, observed, "bounded-" + index);
                upsertSource(tenant, runId, target, observed);
                seedRelationship(tenant, runId, agent, target, "USES_KNOWLEDGE_BASE", observed);
                if (index == 101) jdbc.update("""
                        update ai_grid_relationship_snapshots set valid_until=:expired
                         where run_id=:runId and target_artifact_id=:target
                        """, new MapSqlParameterSource().addValue("expired", Timestamp.from(observed.minusSeconds(1)))
                        .addValue("runId", runId).addValue("target", target));
            }
            systems.deriveForRun(tenant, runId);
            exposures.correlateCompleteRun(tenant, runId);
            assertEquals(101, count("select count(*) from ai_grid_system_memberships"),
                    "system membership is root plus the first 100 current edges");
            assertEquals(300, count("select graph_traversed_path_count from ai_grid_run_metrics"),
                    "three applicable templates each traverse at most 100 first-hop paths");
            return null;
        });
    }

    @Test
    void suppressionAndOneSlaResetSurviveRepeatedEvidenceRecoveryAndDistinctPagination() {
        Tenant tenant=tenants.createTenant("R2 deadlines "+UUID.randomUUID(),"r2-deadlines-"+UUID.randomUUID(),"pilot",null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant,() -> {
            UUID agent=UUID.randomUUID(), first=UUID.randomUUID(), second=UUID.randomUUID();
            seedArtifact(tenant,agent,"AI_AGENT","AWS_BEDROCK_AGENT","agent");
            seedArtifact(tenant,first,"KNOWLEDGE_BASE","AWS_BEDROCK_KNOWLEDGE_BASE","first data");
            seedArtifact(tenant,second,"KNOWLEDGE_BASE","AWS_BEDROCK_KNOWLEDGE_BASE","second data");
            addValidatingFacts(tenant,agent,first,Instant.now().plusSeconds(3600));
            addValidatingFacts(tenant,agent,second,Instant.now().plusSeconds(3600));
            var artifacts=List.of(agent,first,second);
            var paths=List.of(new Relationship(agent,first,"USES_KNOWLEDGE_BASE"),new Relationship(agent,second,"USES_KNOWLEDGE_BASE"));
            UUID initial=seedGraphRun(tenant,artifacts,paths);
            systems.deriveForRun(tenant,initial); exposures.correlateCompleteRun(tenant,initial);
            UUID finding=jdbc.queryForObject("select id from findings where finding_kind='AI_EXPOSURE'",Map.of(),UUID.class);
            Instant initialDeadline=deadline(finding);
            var page=customerApi.findings(tenant,"R2_EXTERNAL_SENSITIVE_ACCESS","OPEN","AWS","123456789012",null,"AWS_BEDROCK_KNOWLEDGE_BASE",0,1);
            assertEquals(1,page.total()); assertEquals(1,page.items().size());
            assertEquals("AI_EXPOSURE",page.items().get(0).findingKind());
            assertEquals("EXPOSURE_PATH",page.items().get(0).subjectType());
            assertEquals(null,page.items().get(0).executionId());
            assertEquals(2,page.items().get(0).exposurePaths().size());
            assertEquals(0,customerApi.findings(tenant,null,"OPEN",null,null,null,null,1,1).items().size());
            assertEquals(2,customerApi.finding(tenant,finding).exposurePaths().size());
            jdbc.update("update findings set status='SUPPRESSED',suppressed_until=now()+interval '1 hour' where id=:id",Map.of("id",finding));
            UUID suppressed=seedGraphRun(tenant,artifacts,paths);
            systems.deriveForRun(tenant,suppressed); exposures.correlateCompleteRun(tenant,suppressed);
            assertEquals("SUPPRESSED",jdbc.queryForObject("select status from findings where id=:id",Map.of("id",finding),String.class));
            assertEquals(initialDeadline,deadline(finding));
            jdbc.update("update ai_grid_host_context_facts set valid_until=now()-interval '1 second' where artifact_id=:id",Map.of("id",first));
            UUID mixed=seedGraphRun(tenant,artifacts,List.of(paths.get(1),paths.get(0)));
            systems.deriveForRun(tenant,mixed); exposures.correlateCompleteRun(tenant,mixed);
            assertEquals("VALIDATED_EXPOSURE",jdbc.queryForObject("select workflow_class from findings where id=:id",Map.of("id",finding),String.class));
            assertEquals(initialDeadline,deadline(finding),"Any validated path preserves the shared deadline");
            jdbc.update("update findings set status='OPEN',suppressed_until=null where id=:id",Map.of("id",finding));
            expireAndCorrelate(tenant,artifacts,paths);
            assertEquals(null,deadline(finding));
            recoverAndCorrelate(tenant,agent,first,second,artifacts,paths);
            Instant resetDeadline=deadline(finding); assertTrue(resetDeadline.isAfter(initialDeadline));
            expireAndCorrelate(tenant,artifacts,paths);
            recoverAndCorrelate(tenant,agent,first,second,artifacts,paths);
            assertEquals(resetDeadline,deadline(finding),"Repeated recovery restores the durable saved deadline");
            Instant overdue=Instant.now().minusSeconds(3600).truncatedTo(ChronoUnit.MICROS);
            jdbc.update("update findings set due_at=:due where id=:id",Map.of("id",finding,"due",Timestamp.from(overdue)));
            expireAndCorrelate(tenant,artifacts,paths);
            recoverAndCorrelate(tenant,agent,first,second,artifacts,paths);
            assertEquals(overdue,deadline(finding),"Overdue findings receive no extension");
            assertEquals(1,count("select count(*) from finding_events where event_type='EXPOSURE_SLA_RECOVERED' and details_json->>'freshReset'='true'"));
            jdbc.update("update findings set status='SUPPRESSED',suppressed_until=null where id=:id",Map.of("id",finding));
            recoverAndCorrelate(tenant,agent,first,second,artifacts,paths);
            assertEquals("SUPPRESSED",jdbc.queryForObject("select status from findings where id=:id",Map.of("id",finding),String.class));
            assertEquals(overdue,deadline(finding));
            assertEquals(1,count("select count(*) from finding_list_projection where finding_id='"+finding+"' and status='SUPPRESSED'"),"Committed evidence paths refresh the canonical projection");
        });
    }

    @Test void overlappingFreshnessSweepsDeriveOneReplacementEpoch() throws Exception {
        Tenant tenant=tenants.createTenant("R2 freshness "+UUID.randomUUID(),"r2-fresh-"+UUID.randomUUID(),"pilot",null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant, () -> {
            UUID agent=UUID.randomUUID(), kb=UUID.randomUUID();
            seedArtifact(tenant,agent,"AI_AGENT","AWS_BEDROCK_AGENT","agent");
            seedArtifact(tenant,kb,"KNOWLEDGE_BASE","AWS_BEDROCK_KNOWLEDGE_BASE","kb");
            UUID run=seedRun(tenant,agent,kb,true,false);
            seedCompleteScope(tenant,run,"AWS","AWS:test",Instant.now());
            addValidatingFacts(tenant,agent,kb,Instant.now().plusSeconds(3600));
            UUID epoch=coverage.refreshCurrent(tenant,run); systems.deriveForCurrentEpoch(tenant,epoch,run);
            assertEquals(1,exposures.correlateCurrentEpoch(tenant,epoch,run).validated());
            jdbc.update("update ai_grid_relationship_snapshots set valid_until=now()-interval '1 second' where run_id=:id",Map.of("id",run));
            jdbc.update("update ai_grid_exposure_observations set temporal_valid_until=now()-interval '1 second'",Map.of());
        });
        int before=tenantExecution.run(tenant, () -> count("select count(*) from ai_grid_exposure_executions"));
        var start=new java.util.concurrent.CyclicBarrier(2);
        var pool=java.util.concurrent.Executors.newFixedThreadPool(2);
        try {
            java.util.concurrent.Callable<Void> task=() -> { start.await(10,java.util.concurrent.TimeUnit.SECONDS); freshness.demoteExpiredEvidence();return null; };
            var first=pool.submit(task);var second=pool.submit(task);
            first.get(30,java.util.concurrent.TimeUnit.SECONDS);second.get(30,java.util.concurrent.TimeUnit.SECONDS);
        } finally { pool.shutdownNow(); }
        tenantExecution.run(tenant, () -> {
            assertEquals(before+1,count("select count(*) from ai_grid_exposure_executions"));
            assertEquals("NEEDS_EVIDENCE",jdbc.queryForObject("select workflow_class from findings where finding_kind='AI_EXPOSURE'",Map.of(),String.class));
        });
    }

    @Test void expiredRelationshipsDemoteAnAuthoritativePathWithoutAssertingAbsence() {
        Tenant tenant=tenants.createTenant("R2 expired edge "+UUID.randomUUID(),"r2-edge-"+UUID.randomUUID(),"pilot",null);
        migrations.provisionNewTenant(tenant);
        tenantExecution.run(tenant,() -> {
            UUID agent=UUID.randomUUID(),kb=UUID.randomUUID();
            seedArtifact(tenant,agent,"AI_AGENT","AWS_BEDROCK_AGENT","agent"); seedArtifact(tenant,kb,"KNOWLEDGE_BASE","AWS_BEDROCK_KNOWLEDGE_BASE","kb");
            UUID run=seedRun(tenant,agent,kb,true,false); seedCompleteScope(tenant,run,"AWS","AWS:test",Instant.now());
            addValidatingFacts(tenant,agent,kb,Instant.now().plusSeconds(3600));
            UUID epoch=coverage.refreshCurrent(tenant,run); systems.deriveForCurrentEpoch(tenant,epoch,run);
            assertEquals(1,exposures.correlateCurrentEpoch(tenant,epoch,run).validated());
            jdbc.update("update ai_grid_relationship_snapshots set valid_until=now()-interval '1 second' where run_id=:id",Map.of("id",run));
            UUID staleEpoch=coverage.refreshCurrent(tenant,run); systems.deriveForCurrentEpoch(tenant,staleEpoch,run);
            var stale=exposures.correlateCurrentEpoch(tenant,staleEpoch,run);
            assertEquals(0,stale.closed()); assertEquals(0,stale.validated());
            assertEquals("NEEDS_EVIDENCE",jdbc.queryForObject("select workflow_class from findings where finding_kind='AI_EXPOSURE'",Map.of(),String.class));
            assertEquals(1,count("select count(*) from findings where finding_kind='AI_EXPOSURE' and status='OPEN'"));
        });
    }
    private Instant deadline(UUID finding) { return jdbc.query("select due_at from findings where id=:id",Map.of("id",finding),rs -> rs.next() && rs.getTimestamp(1)!=null ? rs.getTimestamp(1).toInstant() : null); }
    private void expireAndCorrelate(Tenant tenant,List<UUID> artifacts,List<Relationship> paths) {
        jdbc.update("update ai_grid_host_context_facts set valid_until=now()-interval '1 second'",Map.of());
        UUID run=seedGraphRun(tenant,artifacts,paths); systems.deriveForRun(tenant,run); exposures.correlateCompleteRun(tenant,run);
    }
    private void recoverAndCorrelate(Tenant tenant,UUID agent,UUID first,UUID second,List<UUID> artifacts,List<Relationship> paths) {
        addValidatingFacts(tenant,agent,first,Instant.now().plusSeconds(3600)); addValidatingFacts(tenant,agent,second,Instant.now().plusSeconds(3600));
        UUID run=seedGraphRun(tenant,artifacts,paths); systems.deriveForRun(tenant,run); exposures.correlateCompleteRun(tenant,run);
    }

    private void addValidatingFacts(Tenant tenant, UUID agent, UUID kb, Instant validUntil) {
        ingestTrusted(tenant, agent, hostFact("network.internet_reachability_verified", "GRAPH_ANALYSIS", "REACHABILITY", validUntil));
        ingestTrusted(tenant, agent, hostFact("identity.inadequate_authentication_verified", "GRAPH_ANALYSIS", "IDENTITY", validUntil));
        ingestTrusted(tenant, kb, hostFact("data.sensitive_access_confirmed", "DSPM", "DATA", validUntil));
    }

    private void ingestTrusted(Tenant tenant, UUID artifactId, HostFactInput input) {
        String producer = switch (input.factKey()) {
            case "network.internet_reachability_verified", "identity.inadequate_authentication_verified" ->
                    "SCOUT_REACHABILITY_GRAPH";
            case "data.sensitive_access_confirmed" -> "SCOUT_DATA_SECURITY";
            case "identity.effective_excessive_privilege_derived",
                    "impact.secret_or_consequential_access_confirmed" -> "SCOUT_IDENTITY_GRAPH";
            default -> "SCOUT_RUNTIME_CONTROL";
        };
        hostContext.ingestTrusted(tenant, artifactId, producer, new TrustedFactInput(input.factKey(), input.value(),
                input.state(), input.evidenceReference(), input.observedAt(), input.validFrom(), input.validUntil(),
                input.confidence()));
    }

    private HostFactInput hostFact(String key, String evidenceClass, String port, Instant validUntil) {
        return hostFact(key, evidenceClass, port, validUntil, "HOST_INTEGRATION");
    }

    private HostFactInput hostFact(String key, String evidenceClass, String port, Instant validUntil,
                                   String provenance) {
        Instant now = Instant.now().minus(1, ChronoUnit.SECONDS);
        return new HostFactInput(key, objectMapper.valueToTree(true), "KNOWN", provenance,
                evidenceClass, port, "evidence://" + key, now, now, validUntil,
                "APPROVED_HOST_EVIDENCE", "1.0.0", 0.99);
    }

    private UUID seedRun(Tenant tenant, UUID agent, UUID kb, boolean relationship, boolean proxies) {
        UUID runId = UUID.randomUUID(); Instant observed = Instant.now();
        UUID agentManifest = seedManifest(tenant, runId, agent, observed, "agent-" + runId);
        seedManifest(tenant, runId, kb, observed, "kb-" + runId);
        upsertSource(tenant, runId, agent, observed);
        upsertSource(tenant, runId, kb, observed);
        if (relationship) jdbc.update("""
                insert into ai_grid_relationship_snapshots
                    (id,tenant_id,run_id,source_artifact_id,target_artifact_id,relationship_type,
                     observed_at,valid_from)
                values (gen_random_uuid(),:tenantId,:runId,:agent,:kb,'USES_KNOWLEDGE_BASE',:observed,:observed),
                       (gen_random_uuid(),:tenantId,:runId,:kb,:agent,'USES_DATA_SOURCE',:observed,:observed)
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("runId", runId)
                .addValue("agent", agent).addValue("kb", kb).addValue("observed", Timestamp.from(observed)));
        if (proxies) {
            seedFact(tenant, runId, agent, agentManifest, "network.public_access_configured", "true", observed);
            seedFact(tenant, runId, agent, agentManifest, "identity.local_auth_enabled_configured", "true", observed);
            seedFact(tenant, runId, agent, agentManifest, "data.source_linked", "true", observed);
        }
        return runId;
    }

    private UUID seedGraphRun(Tenant tenant, List<UUID> artifacts, List<Relationship> relationships) {
        UUID runId = UUID.randomUUID(); Instant observed = Instant.now();
        for (UUID artifact : artifacts) {
            seedManifest(tenant, runId, artifact, observed, runId + ":" + artifact);
            upsertSource(tenant, runId, artifact, observed);
        }
        for (Relationship relationship : relationships)
            seedRelationship(tenant, runId, relationship.source(), relationship.target(), relationship.type(), observed);
        return runId;
    }

    private void seedRelationship(Tenant tenant, UUID runId, UUID source, UUID target, String type, Instant observed) {
        jdbc.update("""
                insert into ai_grid_relationship_snapshots
                    (id,tenant_id,run_id,source_artifact_id,target_artifact_id,relationship_type,observed_at,valid_from)
                values (gen_random_uuid(),:tenantId,:runId,:source,:target,:type,:observed,:observed)
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("runId", runId)
                .addValue("source", source).addValue("target", target).addValue("type", type)
                .addValue("observed", Timestamp.from(observed)));
    }

    private void seedCompleteScope(Tenant tenant, UUID runId, String provider, String scope, Instant observed) {
        jdbc.update("""
                insert into ai_security_snapshot_scopes
                    (id,tenant_id,run_id,provider,account_id,region,resource_family,scope_key,status,
                     expected_chunks,accepted_chunks,started_at,completed_at)
                values (gen_random_uuid(),:tenantId,:runId,:provider,'account','region','family',:scope,'COMPLETE',
                        1,1,:observed,:observed)
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("runId", runId)
                .addValue("provider", provider).addValue("scope", scope).addValue("observed", Timestamp.from(observed)));
    }

    private void seedArtifact(Tenant tenant, UUID id, String type, String nativeKind, String name) {
        jdbc.update("""
                insert into ai_security_artifacts
                    (id,tenant_id,provider,provider_resource_id,artifact_type,native_kind,name,account_id,region,
                     attributes_json,first_observed_at,last_observed_at)
                values (:id,:tenantId,'AWS',:resourceId,:type,:nativeKind,:name,'123456789012','us-east-1',
                        '{}'::jsonb,now(),now())
                """, new MapSqlParameterSource().addValue("id", id).addValue("tenantId", tenant.getId())
                .addValue("resourceId", "arn:test:" + id).addValue("type", type)
                .addValue("nativeKind", nativeKind).addValue("name", name));
    }

    private UUID seedManifest(Tenant tenant, UUID runId, UUID artifactId, Instant observed, String seed) {
        UUID bodyId = UUID.randomUUID(); UUID manifestId = UUID.randomUUID();
        jdbc.update("""
                insert into ai_grid_snapshot_bodies
                    (id,tenant_id,content_hash,content_json,byte_size,redaction_profile,first_run_id)
                values (:id,:tenantId,:hash,'{}'::jsonb,2,'STANDARD_V1',:runId)
                """, new MapSqlParameterSource().addValue("id", bodyId).addValue("tenantId", tenant.getId())
                .addValue("hash", String.format("%064x", Math.abs(seed.hashCode()))).addValue("runId", runId));
        jdbc.update("""
                insert into ai_grid_snapshot_manifests
                    (id,tenant_id,run_id,artifact_id,scope_key,body_id,schema_version,observed_at)
                values (:id,:tenantId,:runId,:artifactId,'AWS:test',:bodyId,'1.0.0',:observed)
                """, new MapSqlParameterSource().addValue("id", manifestId).addValue("tenantId", tenant.getId())
                .addValue("runId", runId).addValue("artifactId", artifactId).addValue("bodyId", bodyId)
                .addValue("observed", Timestamp.from(observed)));
        return manifestId;
    }

    private void upsertSource(Tenant tenant, UUID runId, UUID artifactId, Instant observed) {
        jdbc.update("""
                insert into ai_security_artifact_sources
                    (id,tenant_id,artifact_id,scope_key,run_id,observed_at,evidence_hash)
                values (gen_random_uuid(),:tenantId,:artifactId,'AWS:test',:runId,:observed,:hash)
                on conflict (tenant_id,artifact_id,scope_key) do update set run_id=excluded.run_id,
                    observed_at=excluded.observed_at,evidence_hash=excluded.evidence_hash
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("artifactId", artifactId)
                .addValue("runId", runId).addValue("observed", Timestamp.from(observed)).addValue("hash", runId.toString()));
    }

    private void seedFact(Tenant tenant, UUID runId, UUID artifactId, UUID manifestId,
                          String key, String value, Instant observed) {
        jdbc.update("""
                insert into ai_grid_facts
                    (id,tenant_id,run_id,artifact_id,snapshot_manifest_id,fact_key,value_type,value_json,state,
                     provenance,evidence_class,source,observed_at,fact_schema_version)
                values (gen_random_uuid(),:tenantId,:runId,:artifactId,:manifestId,:key,'BOOLEAN',cast(:value as jsonb),
                        'KNOWN','PROVIDER_OBSERVED','CONFIGURATION','test',:observed,'1.0.0')
                """, new MapSqlParameterSource().addValue("tenantId", tenant.getId()).addValue("runId", runId)
                .addValue("artifactId", artifactId).addValue("manifestId", manifestId).addValue("key", key)
                .addValue("value", value).addValue("observed", Timestamp.from(observed)));
    }

    private int count(String sql) { Integer count = jdbc.queryForObject(sql, Map.of(), Integer.class); return count == null ? 0 : count; }
    private record Relationship(UUID source, UUID target, String type) {}
}
