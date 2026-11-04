package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.cbom.CbomContradictionService;
import com.prototype.vulnwatch.service.cbom.CbomEvidenceExpiryService;
import com.prototype.vulnwatch.service.cbom.CbomGraphService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.support.TransactionTemplate;

/** Milestone 4 relationships, blast radius, contradiction review and evidence expiry against real PostgreSQL. */
@PostgresControllerIntegrationTest
class CbomRelationshipsPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("cbom_relationships");
    private static final String SERIAL = "urn:uuid:5c1b7a52-3f0e-4d7b-9a1e-0b6c2d4e8f11";

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private TenantService tenantService;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private TransactionTemplate transactions;
    @Autowired private CbomContradictionService contradictions;
    @Autowired private CbomEvidenceExpiryService expiry;
    @Autowired private CbomGraphService graph;

    @Test
    void typedRelationshipsAndBlastRadiusReachTheOwningApplication() throws Exception {
        String bomId = push("graph-" + UUID.randomUUID());
        Map<String, String> byRef = componentsByRef(bomId);
        String key = byRef.get("crypto/key/credential-encryption-key");
        String aes = byRef.get("crypto/algorithm/aes-256-gcm");

        JsonNode keyGraph = get("/api/bom/cbom/graph?startType=COMPONENT&startId=" + key + "&depth=1");
        List<String> types = new ArrayList<>();
        keyGraph.path("edges").forEach(edge -> types.add(edge.path("relationshipType").asText()));
        assertTrue(types.contains("USES_ALGORITHM"), types.toString());
        assertTrue(types.contains("DEPENDS_ON"), types.toString());
        assertTrue(types.contains("APPLICATION_USES"), types.toString());
        boolean labelled = false;
        for (JsonNode node : keyGraph.path("nodes")) labelled |= "AES-GCM".equals(node.path("label").asText());
        assertTrue(labelled, "graph nodes carry component labels");

        JsonNode radius = get("/api/bom/cbom/blast-radius?componentId=" + aes);
        assertEquals(1, radius.path("applications").size(), "a weakness in AES reaches its application");
        assertTrue(radius.path("affectedComponents").asInt() >= 3, radius.toString());
        mockMvc.perform(asPlatformOwner(authedGet("/api/bom/cbom/blast-radius?componentId=" + aes + "&depth=4"))).andExpect(status().isBadRequest());
    }

    @Test
    void contradictoryDocumentsAreDetectedAndReviewedWithOptimisticConcurrency() throws Exception {
        String bomId = push("contradiction-" + UUID.randomUUID());
        String rival = UUID.randomUUID().toString();
        inTenant(() -> {
            jdbc.update("""
                    insert into bom_ingestion_records (id, tenant_id, asset_id, bom_type, status, document_name, ingested_at)
                    select ?::uuid, tenant_id, asset_id, 'CBOM', 'ACTIVE', 'rival.cdx.json', now() from bom_ingestion_records where id = ?::uuid
                    """, rival, bomId);
            jdbc.update("""
                    insert into cbom_components (id, tenant_id, asset_id, source_bom_id, bom_ref, component_fingerprint, name, asset_type,
                        primitive, active, created_at, updated_at)
                    select gen_random_uuid(), tenant_id, asset_id, ?::uuid, bom_ref, 'rival-' || id, name, asset_type, 'des', true, now(), now()
                      from cbom_components where source_bom_id = ?::uuid and bom_ref = 'crypto/algorithm/aes-256-gcm'
                    """, rival, bomId);
            return transactions.execute(tx -> contradictions.detect(tenantService.getDefaultTenant().getId(), UUID.fromString(rival)));
        });

        JsonNode open = get("/api/bom/cbom/contradictions");
        assertEquals(1, open.size());
        JsonNode contradiction = open.get(0);
        assertEquals("primitive", contradiction.path("claim").asText());
        String id = contradiction.path("id").asText();
        String review = "/api/bom/cbom/contradictions/" + id + "/review";
        mockMvc.perform(asPlatformOwner(authedPost(review)).contentType("application/json").content("{\"decision\":\"GUESS\",\"note\":\"x\"}"))
                .andExpect(status().isBadRequest());
        mockMvc.perform(asPlatformOwner(authedPost(review)).contentType("application/json")
                .content("{\"decision\":\"DISMISSED\",\"note\":\"stale\",\"version\":99}")).andExpect(status().isConflict());
        JsonNode reviewed = json(mockMvc.perform(asPlatformOwner(authedPost(review)).contentType("application/json")
                .content("{\"decision\":\"ACCEPTED_A\",\"note\":\"Runtime config confirms\",\"version\":" + contradiction.path("version").asLong() + "}"))
                .andExpect(status().isOk()).andReturn());
        assertEquals("ACCEPTED_A", reviewed.path("status").asText());
        mockMvc.perform(asPlatformOwner(authedPost(review)).contentType("application/json")
                .content("{\"decision\":\"DISMISSED\",\"note\":\"again\"}")).andExpect(status().isConflict());
        assertEquals(0, get("/api/bom/cbom/contradictions").size());
        assertEquals(1, get("/api/bom/cbom/contradictions?status=ACCEPTED_A").size());
    }

    @Test
    void evidenceExpiryReevaluatesCertificatesThatExpiredSinceTheirLastEvaluationOnce() throws Exception {
        String bomId = push("expiry-" + UUID.randomUUID());
        inTenant(() -> jdbc.update("""
                insert into cbom_components (id, tenant_id, asset_id, source_bom_id, bom_ref, component_fingerprint, name, asset_type,
                    signature_algorithm, not_after, active, created_at, updated_at)
                select gen_random_uuid(), tenant_id, asset_id, id, 'crypto/cert/edge', 'cert-edge-' || id, 'edge certificate', 'CERTIFICATE',
                       'sha256WithRSAEncryption', current_date - 1, true, now() - interval '10 days', now() - interval '10 days'
                  from bom_ingestion_records where id = ?::uuid
                """, bomId));
        Tenant tenant = tenantService.getDefaultTenant();
        var first = expiry.sweep(tenant);
        assertTrue(first.reevaluatedArtifacts() >= 1);
        long expired = inTenant(() -> jdbc.queryForObject("""
                select count(*) from cbom_risk_findings r join cbom_components c on c.id = r.cbom_component_id
                 where c.bom_ref = 'crypto/cert/edge' and c.source_bom_id = ?::uuid and r.rule_id = 'CBOM-CERT-EXPIRED' and r.status = 'OPEN'
                """, Long.class, bomId));
        assertEquals(1, expired, "re-evaluation raises the expired-certificate finding");
        assertEquals(0, expiry.sweep(tenant).reevaluatedArtifacts(), "an evaluated certificate is not swept again");
    }

    @Test
    void boundedTraversalMeetsTheDepthThreeFiveHundredNodeBudget() {
        Tenant tenant = tenantService.getDefaultTenant();
        UUID bom = UUID.randomUUID();
        UUID root = UUID.randomUUID();
        inTenant(() -> {
            jdbc.update("insert into bom_ingestion_records (id, tenant_id, bom_type, status, document_name, ingested_at)"
                    + " values (?, ?, 'CBOM', 'ACTIVE', 'graph-perf', now())", bom, tenant.getId());
            // A 1 + 10 + 100 + 1000 node tree rooted at one component.
            jdbc.update("""
                    with recursive tree(level, id, parent) as (
                        select 0, ?::uuid, null::uuid
                        union all
                        select t.level + 1, gen_random_uuid(), t.id from tree t, generate_series(1, 10) where t.level < 3)
                    insert into cbom_relationships (id, tenant_id, source_bom_id, source_type, source_id, target_type, target_id,
                        relationship_type, evidence_kind)
                    select gen_random_uuid(), ?, ?, 'COMPONENT', parent, 'COMPONENT', id, 'DEPENDS_ON', 'DECLARED' from tree where parent is not null
                    """, root, tenant.getId(), bom);
            jdbc.execute("analyze cbom_relationships");
            return null;
        });
        inTenant(() -> graph.traverse(tenant, "COMPONENT", root, 3, null, 500));
        List<Long> samples = new ArrayList<>();
        Map<String, Object> last = new HashMap<>();
        for (int i = 0; i < 10; i++) {
            long started = System.nanoTime();
            var result = inTenant(() -> graph.traverse(tenant, "COMPONENT", root, 3, null, 500));
            samples.add((System.nanoTime() - started) / 1_000_000);
            last.put("nodes", result.nodes().size());
            last.put("truncated", result.truncated());
        }
        Collections.sort(samples);
        long p95 = samples.get(9);
        assertEquals(500, last.get("nodes"));
        assertEquals(true, last.get("truncated"));
        assertTrue(p95 < 2000, "depth-3, 500-node traversal p95 " + p95 + "ms exceeds the 2 s budget");
    }

    // ---------------------------------------------------------------- helpers

    private String push(String application) throws Exception {
        String body = Files.readString(Path.of("src/test/resources/fixtures/bom/cbom-9-assets.cdx.json"))
                .replace(SERIAL, "urn:uuid:" + UUID.randomUUID()).replace("scoutgrid-prototype-app", application);
        return json(mockMvc.perform(asPlatformOwner(authedPost("/api/bom/ingest?bomType=CBOM")).contentType("application/json")
                .content(body.getBytes(StandardCharsets.UTF_8))).andExpect(status().is2xxSuccessful()).andReturn()).path("bomId").asText();
    }

    private Map<String, String> componentsByRef(String bomId) {
        Map<String, String> byRef = new HashMap<>();
        inTenant(() -> {
            jdbc.query("select bom_ref, id from cbom_components where source_bom_id = ?::uuid and active",
                    rs -> { byRef.put(rs.getString(1), rs.getString(2)); }, bomId);
            return null;
        });
        return byRef;
    }

    private <T> T inTenant(Supplier<T> work) {
        Tenant tenant = tenantService.getDefaultTenant();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
        try {
            return work.get();
        } finally {
            TenantContext.clear();
        }
    }

    private JsonNode json(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private JsonNode get(String path) throws Exception {
        return json(mockMvc.perform(asPlatformOwner(authedGet(path))).andExpect(status().isOk()).andReturn());
    }
}
