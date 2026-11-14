package com.prototype.vulnwatch.aisecurity;

import static org.junit.jupiter.api.Assertions.*;
import com.prototype.vulnwatch.aisecurity.model.AiSecurityContracts.*;
import com.prototype.vulnwatch.aisecurity.service.*;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.*;
import com.prototype.vulnwatch.support.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.server.ResponseStatusException;

@PostgresControllerIntegrationTest
@TestPropertySource(properties = {"spring.main.allow-circular-references=true", "app.tenancy.allow-header-tenant-selection=true"})
class AiHarmBaselinePostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE = LocalPostgresTestDatabase.provision("harm_baselines");
    @DynamicPropertySource static void properties(DynamicPropertyRegistry registry) { PostgresITSupport.registerDatabaseProperties(registry, DATABASE); }
    @Autowired TenantService tenants;
    @Autowired TenantSchemaMigrationService migrations;
    @Autowired TenantSchemaExecutionService execution;
    @Autowired AiSecurityAwsConnectorService connectors;
    @Autowired AiSecurityObservationService ingestion;
    @Autowired AiSecuritySyncRunFacade runs;
    @Autowired AiSecurityDigestBaselineService baselines;
    @Autowired NamedParameterJdbcTemplate jdbc;
    @Autowired org.springframework.test.web.servlet.MockMvc mvc;
    @Autowired com.fasterxml.jackson.databind.ObjectMapper mapper;
    @MockitoBean org.springframework.security.oauth2.jwt.JwtDecoder decoder;
    @MockitoBean JwtTenantAuthenticationService jwtAuthentication;
    @MockitoBean IngestionJobWorkerService workers;
    @MockitoBean FindingDeltaQueueService deltas;

    @Test void approvalDriftReapprovalRevocationRotationAndLateObservations() throws Exception {
        Tenant tenant = tenants.createTenant("Harm Baselines", "harm-baselines", "pilot", null);
        migrations.provisionNewTenant(tenant);
        UUID connector = connectors.save(tenant, new AiSecurityAwsConnectorService.ConnectorConfigRequest("123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)).id();
        Instant now = Instant.now().minusSeconds(60).truncatedTo(java.time.temporal.ChronoUnit.MICROS);
        observe(tenant, connector, "one", "v1", now);
        UUID artifact = execution.run(tenant, () -> jdbc.queryForObject("select id from ai_security_artifacts where provider_resource_id='prompt:approval-test'", Map.of(), UUID.class));
        var first = baselines.observations(tenant, artifact).get(0);
        assertEquals("UNAPPROVED", first.comparisonOutcome());
        assertThrows(ResponseStatusException.class, () -> baselines.approveObservation(tenant, artifact,
                new AiSecurityDigestBaselineService.ObservationRequest("PROMPT", UUID.randomUUID(), now), "analyst", false));
        String url = "/api/ai-security/artifacts/" + artifact + "/digest-baselines/approve-observation";
        var jwt = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("reader.jwt").header("alg", "none").subject("reader").build();
        org.mockito.Mockito.when(decoder.decode("reader.jwt")).thenReturn(jwt);
        org.mockito.Mockito.when(jwtAuthentication.authenticate(org.mockito.ArgumentMatchers.eq(jwt), org.mockito.ArgumentMatchers.anyString()))
                .thenReturn(new AuthenticatedTenantActor("reader", UUID.randomUUID(), "reader@example.test", "Reader",
                        tenant.getId(), tenant.getName(), tenant.getSchemaName(), Set.of("OPERATOR")));
        mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post(url)
                .header("Authorization", "Bearer reader.jwt").contentType("application/json").content(mapper.writeValueAsString(ref(first))))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isForbidden());
        mvc.perform(AuthRequest.withTenant(AuthRequest.asAnalyst(AuthRequest.authedPost(url)), tenant.getId().toString())
                .contentType("application/json").content(mapper.writeValueAsString(ref(first))))
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.status().isOk())
                .andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath("$.approvedDigest").doesNotExist());
        assertEquals("UNCHANGED", baselines.observations(tenant, artifact).get(0).comparisonOutcome());
        observe(tenant, connector, "two", "v1", now.plusSeconds(10));
        assertEquals("CHANGED_AFTER_APPROVAL", baselines.observations(tenant, artifact).get(0).comparisonOutcome());
        assertEquals(1, openFindings(tenant, artifact));
        observe(tenant, connector, "one", "v1", now.minusSeconds(10));
        assertEquals("CHANGED_AFTER_APPROVAL", baselines.observations(tenant, artifact).get(0).comparisonOutcome());
        assertEquals("v2", baselines.observations(tenant, artifact).get(0).observationVersion(), "approval version comes from the source snapshot even after a late observation");
        baselines.approveObservation(tenant, artifact, ref(baselines.observations(tenant, artifact).get(0)), "analyst", true);
        assertEquals(0, openFindings(tenant, artifact));
        assertEquals(2, baselines.history(tenant, artifact).size());
        observe(tenant, connector, "three", "v1", now.plusSeconds(15));
        assertEquals(1, openFindings(tenant, artifact));
        observe(tenant, connector, "rotated", "v2", now.plusSeconds(20));
        assertEquals("BASELINE_UNKNOWN_REAPPROVAL_REQUIRED", baselines.observations(tenant, artifact).get(0).comparisonOutcome());
        assertTrue(execution.run(tenant, () -> jdbc.queryForObject("select evidence_key from ai_grid_setup_actions where artifact_id=:id and status='OPEN' and evidence_key like 'digest:PROMPT:%'", Map.of("id", artifact), String.class)).endsWith("BASELINE_UNKNOWN_REAPPROVAL_REQUIRED"));
        assertEquals(0, openFindings(tenant, artifact));
        execution.run(tenant, () -> baselines.revoke(tenant, artifact, "PROMPT", "analyst"));
        assertEquals("UNAPPROVED", baselines.observations(tenant, artifact).get(0).comparisonOutcome());
        assertEquals(3, baselines.history(tenant, artifact).size());
        assertTrue(execution.run(tenant, () -> jdbc.queryForObject("select count(*) from ai_grid_setup_actions where artifact_id=:id and status='OPEN'", Map.of("id", artifact), Integer.class)) > 0);
        Tenant other = tenants.createTenant("Other Harm", "other-harm", "pilot", null);
        migrations.provisionNewTenant(other);
        assertTrue(baselines.observations(other, artifact).isEmpty());
        assertThrows(ResponseStatusException.class, () -> baselines.approveObservation(other, artifact, ref(first), "analyst", false));
        assertFalse(baselines.list(tenant, artifact).toString().contains("rotated"));
        assertFalse(baselines.history(tenant, artifact).toString().contains("rotated"));
        execution.run(tenant, () -> jdbc.update("update ai_security_artifact_digest_observations set observed_at=now()-interval '2 days' where artifact_id=:id", Map.of("id", artifact)));
        var stale = baselines.observations(tenant, artifact).get(0);
        assertTrue(stale.stale());
        assertThrows(ResponseStatusException.class, () -> baselines.approveObservation(tenant, artifact, ref(stale), "analyst", true));
        assertEquals(3, baselines.history(tenant, artifact).size());
    }
    @Test void unboundApprovalsRequireReapprovalAndPreserveAuditHistory() {
        Tenant tenant = tenants.createTenant("Harm Upgrade", "harm-upgrade", "pilot", null);
        String schema = tenant.getSchemaName();
        var datasource = new org.springframework.jdbc.datasource.DriverManagerDataSource(DATABASE.url(), DATABASE.username(), DATABASE.password());
        var raw = new org.springframework.jdbc.core.JdbcTemplate(datasource);
        migrate(tenant, datasource, "1");
        UUID artifact = UUID.randomUUID();
        raw.update("""
                insert into "%s".ai_security_artifacts
                    (id,tenant_id,provider,provider_resource_id,artifact_type,native_kind,name,account_id,region,first_observed_at,last_observed_at)
                values (?,?,'AWS','prompt:upgrade','AI_PROMPT','AWS_BEDROCK_PROMPT','Upgrade','123456789012','us-east-1',now(),now())
                """.formatted(schema), artifact, tenant.getId());
        raw.update("""
                insert into "%s".ai_security_artifact_digest_baselines
                    (id,tenant_id,artifact_id,digest_kind,algorithm,key_version,approved_digest,approval_status,approved_by,approved_at)
                values (?,?,?,'PROMPT','HMAC-SHA-256','v1','existing-approved-value','APPROVED','original-approver',now())
                """.formatted(schema), UUID.randomUUID(), tenant.getId(), artifact);
        raw.update("""
                insert into "%s".ai_security_artifact_digest_baselines
                    (id,tenant_id,artifact_id,digest_kind,algorithm,key_version,approved_digest,approval_status,approved_by,approved_at,revoked_by,revoked_at)
                values (?,?,?,'TOOL_DEFINITION','HMAC-SHA-256','v1','existing-revoked-value','REVOKED','original-approver',now()-interval '1 hour','original-revoker',now())
                """.formatted(schema), UUID.randomUUID(), tenant.getId(), artifact);
        // Unbound approvals can still be imported by development fixtures; V1 no longer
        // upgrades an old database. Seed their history explicitly to exercise reapproval.
        raw.update("""
                insert into "%s".ai_security_baseline_history
                    (id,tenant_id,artifact_id,digest_kind,action,actor,algorithm,key_version,approved_value,recorded_at)
                select gen_random_uuid(),tenant_id,artifact_id,digest_kind,'APPROVED',approved_by,
                       algorithm,key_version,approved_digest,approved_at
                  from "%s".ai_security_artifact_digest_baselines;
                insert into "%s".ai_security_baseline_history
                    (id,tenant_id,artifact_id,digest_kind,action,actor,algorithm,key_version,approved_value,recorded_at)
                select gen_random_uuid(),tenant_id,artifact_id,digest_kind,'REVOKED',revoked_by,
                       algorithm,key_version,approved_digest,revoked_at
                  from "%s".ai_security_artifact_digest_baselines where revoked_at is not null
                """.formatted(schema, schema, schema, schema));
        migrate(tenant, datasource, "1");
        assertEquals("existing-approved-value", raw.queryForObject("select approved_digest from " + schema + ".ai_security_artifact_digest_baselines where digest_kind='PROMPT'", String.class));
        assertEquals("existing-approved-value", raw.queryForObject("select approved_value from " + schema + ".ai_security_baseline_history where digest_kind='PROMPT'", String.class));
        assertEquals("original-approver", raw.queryForObject("select actor from " + schema + ".ai_security_baseline_history where digest_kind='PROMPT'", String.class));
        assertEquals("original-revoker", raw.queryForObject("select actor from " + schema + ".ai_security_baseline_history where action='REVOKED'", String.class));
        assertEquals(false, raw.queryForObject("select approval_reference_verified from " + schema + ".ai_security_artifact_digest_baselines where digest_kind='PROMPT'", Boolean.class));
        migrations.provisionNewTenant(tenant);
        UUID connector = connectors.save(tenant, new AiSecurityAwsConnectorService.ConnectorConfigRequest("123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)).id();
        UUID run = runs.start(tenant).getId();
        Instant observed = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.MICROS);
        ingestion.ingest(tenant, new ObservationEnvelopeV1(AiSecurityObservationService.CONTRACT_VERSION, run, connector, tenant.getId(),
                "AWS", "123456789012", "us-east-1", "BEDROCK_AGENTS", "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                run.toString(), run.toString(), observed, ScopeStatus.COMPLETE,
                List.of(new ArtifactObservation("prompt:upgrade", "AI_PROMPT", "AWS_BEDROCK_PROMPT", "Upgrade", Map.of("promptDigest", "existing-approved-value", "digestAlgorithm", "HMAC-SHA-256", "digestKeyVersion", "v1"))), List.of(), List.of()));
        assertEquals("BASELINE_UNKNOWN_REAPPROVAL_REQUIRED", baselines.observations(tenant, artifact).get(0).comparisonOutcome(), "a matching hash does not verify an unbound legacy approval");
        baselines.approveObservation(tenant, artifact, ref(baselines.observations(tenant, artifact).get(0)), "analyst", true);
        assertEquals("UNCHANGED", baselines.observations(tenant, artifact).get(0).comparisonOutcome());
        // Exercise legacy revocation after its current observation has been removed.
        execution.run(tenant, () -> jdbc.update("delete from ai_security_artifact_digest_observations where artifact_id=:id", Map.of("id", artifact)));
        execution.run(tenant, () -> baselines.revoke(tenant, artifact, "PROMPT", "analyst"));
        assertEquals("REVOKED", baselines.list(tenant, artifact).get(0).approvalStatus());
        assertEquals(5, baselines.history(tenant, artifact).size());
    }
    private void migrate(Tenant tenant, javax.sql.DataSource source, String target) {
        org.flywaydb.core.Flyway.configure().dataSource(source).schemas(tenant.getSchemaName()).defaultSchema(tenant.getSchemaName())
                .table("tenant_schema_history").locations("classpath:db/migration/tenant")
                .placeholders(Map.of("tenantId", tenant.getId().toString(), "tenantSchema", tenant.getSchemaName()))
                .callbacks(new com.prototype.vulnwatch.migration.TenantSearchPathFlywayCallback(tenant.getSchemaName()))
                .initSql("SET search_path TO " + tenant.getSchemaName() + ", public").target(target).load().migrate();
    }
    @Test void storesGuardrailSnapshotsAndRequiresReleaseGatesForFindings() {
        Tenant tenant = tenants.createTenant("Harm Guardrail", "harm-guardrail", "pilot", null);
        migrations.provisionNewTenant(tenant);
        UUID connector = connectors.save(tenant, new AiSecurityAwsConnectorService.ConnectorConfigRequest("123456789012", "arn:aws:iam::123456789012:role/NoScanPilotReadOnly", null, List.of("us-east-1"), true)).id();
        Instant now = Instant.now().minusSeconds(30).truncatedTo(java.time.temporal.ChronoUnit.MICROS);
        observeControl(tenant, connector, Map.of("guardrailAttached", true, "guardrailId", "g1", "guardrailVersion", "1"), now);
        UUID artifact = execution.run(tenant, () -> jdbc.queryForObject("select id from ai_security_artifacts where provider_resource_id='agent:guardrail-baseline'", Map.of(), UUID.class));
        baselines.approveObservation(tenant, artifact, ref(baselines.observations(tenant, artifact).get(0)), "analyst", false);
        UUID attachmentRun = baselines.observations(tenant, artifact).get(0).sourceRunId();
        observeControl(tenant, connector, "BEDROCK_GUARDRAILS", Map.of("guardrailAttached", true, "guardrailMinimumStrength", "MEDIUM"), now.plusSeconds(2));
        assertEquals(attachmentRun, baselines.observations(tenant, artifact).get(0).sourceRunId(), "aggregate enrichment must not replace complete attachment evidence");
        assertEquals("UNCHANGED", baselines.observations(tenant, artifact).get(0).comparisonOutcome());
        observeControl(tenant, connector, Map.of("guardrailAttached", false), now.plusSeconds(5));
        assertEquals("CONTROL_WEAKENED", baselines.observations(tenant, artifact).get(0).comparisonOutcome());
        assertTrue(baselines.observations(tenant, artifact).get(0).changedFields().contains("guardrailAttached"));
        assertEquals("FAIL", execution.run(tenant, () -> jdbc.queryForObject("select decision from ai_grid_assessments where subject_id=:id and reason_code='CONTROL_WEAKENED'", Map.of("id", artifact), String.class)));
        assertEquals("CONTROL_WEAKENED", execution.run(tenant, () -> jdbc.queryForObject("select value_json #>> '{}' from ai_grid_facts where artifact_id=:id and fact_key='guardrail.baseline_comparison_outcome' and state='KNOWN'", Map.of("id", artifact), String.class)));
        assertEquals(0, execution.run(tenant, () -> jdbc.queryForObject("select count(*) from findings where policy_id='AI_GUARDRAIL_CONFIGURATION_CHANGED_AFTER_APPROVAL' and status='OPEN'", Map.of(), Integer.class)));
        baselines.approveObservation(tenant, artifact, ref(baselines.observations(tenant, artifact).get(0)), "analyst", true);
        assertEquals("UNCHANGED", baselines.observations(tenant, artifact).get(0).comparisonOutcome());
        assertEquals(2, baselines.history(tenant, artifact).size());
    }
    private void observeControl(Tenant tenant, UUID connector, Map<String,Object> attributes, Instant at) {
        observeControl(tenant, connector, "BEDROCK_AGENTS", attributes, at);
    }
    private void observeControl(Tenant tenant, UUID connector, String family, Map<String,Object> attributes, Instant at) {
        UUID run = runs.start(tenant).getId();
        ingestion.ingest(tenant, new ObservationEnvelopeV1(AiSecurityObservationService.CONTRACT_VERSION, run, connector, tenant.getId(),
                "AWS", "123456789012", "us-east-1", family, "AWS:123456789012:us-east-1:" + family, 0, 1,
                run.toString(), run.toString(), at, ScopeStatus.COMPLETE,
                List.of(new ArtifactObservation("agent:guardrail-baseline", "AI_AGENT", "AWS_BEDROCK_AGENT", "Guardrail agent", attributes)), List.of(), List.of()));
    }
    private int openFindings(Tenant tenant, UUID artifact) {
        return execution.run(tenant, () -> jdbc.queryForObject("select count(*) from findings f join finding_subjects s on s.finding_id=f.id where s.subject_id=:id and f.status='OPEN'", Map.of("id", artifact), Integer.class));
    }
    private AiSecurityDigestBaselineService.ObservationRequest ref(AiSecurityDigestBaselineService.ObservationResponse observation) {
        return new AiSecurityDigestBaselineService.ObservationRequest(observation.digestKind(), observation.sourceRunId(), observation.observedAt());
    }
    private void observe(Tenant tenant, UUID connector, String digest, String key, Instant at) {
        UUID run = runs.start(tenant).getId();
        var envelope = new ObservationEnvelopeV1(AiSecurityObservationService.CONTRACT_VERSION, run, connector, tenant.getId(),
                "AWS", "123456789012", "us-east-1", "BEDROCK_AGENTS", "AWS:123456789012:us-east-1:BEDROCK_AGENTS", 0, 1,
                run.toString(), run.toString(), at, ScopeStatus.COMPLETE,
                List.of(new ArtifactObservation("prompt:approval-test", "AI_PROMPT", "AWS_BEDROCK_PROMPT", "Prompt", Map.of("promptDigest", digest, "digestAlgorithm", "HMAC-SHA-256", "digestKeyVersion", key, "version", "one".equals(digest) ? "v1" : "rotated".equals(digest) ? "v3" : "v2"))), List.of(), List.of());
        ingestion.ingest(tenant, envelope);
        assertTrue(ingestion.ingest(tenant, envelope).duplicate());
    }
}
