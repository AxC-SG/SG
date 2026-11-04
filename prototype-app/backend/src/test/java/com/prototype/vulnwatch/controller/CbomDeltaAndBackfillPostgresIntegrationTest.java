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
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.cbom.CbomFindingMirrorSweep;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/**
 * CBOM Milestone 1 operations against real PostgreSQL: CBOM_DELTA publication on ingest and
 * withdrawal, the bounded mirror repair query, and the assessment backfill endpoints.
 */
@PostgresControllerIntegrationTest
class CbomDeltaAndBackfillPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("cbom_delta_backfill");
    private static final String SERIAL = "urn:uuid:5c1b7a52-3f0e-4d7b-9a1e-0b6c2d4e8f11";

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private FindingDeltaQueueService deltaQueue;
    @Autowired private CbomFindingMirrorSweep repairSweep;
    @Autowired private TenantService tenantService;
    @Autowired private JdbcTemplate jdbc;

    @Test
    void ingestPublishesCbomDeltasThatMirrorWithoutATenantScan() throws Exception {
        String bomId = pushCbom();
        Set<String> ids = cbomFindingIds(bomId);
        assertTrue(ids.size() >= 3);

        long pending = inTenant(() -> jdbc.queryForObject(
                "select count(*) from finding_delta_queue where event_type = 'CBOM_DELTA' and status = 'PENDING'", Long.class));
        assertTrue(pending >= ids.size(), "each mirrored CBOM finding has a pending CBOM_DELTA");
        assertEquals(0, cryptoFindingsFor(ids).size(), "the mirror runs from the queue, not inline in the ingest");

        drainDeltas();

        Map<String, JsonNode> crypto = cryptoFindingsFor(ids);
        assertEquals(ids.size(), crypto.size(), "every CBOM finding is mirrored once its delta is processed");
        crypto.values().forEach(row -> assertEquals("OPEN", row.path("status").asText()));
    }

    @Test
    void boundedRepairRestoresMissingAndStaleMirrorRows() throws Exception {
        String bomId = pushCbom();
        Set<String> ids = cbomFindingIds(bomId);
        drainDeltas();
        String missing = ids.iterator().next();
        String stale = ids.stream().skip(1).findFirst().orElseThrow();

        // Drift that no producer reported: a canonical row lost its link, and a source finding was
        // withdrawn behind the mirror's back.
        inTenant(() -> {
            jdbc.update("update findings set fingerprint = 'drifted:' || id::text where fingerprint = ?", "cbom:" + missing);
            jdbc.update("update cbom_risk_findings set evidence_state = 'WITHDRAWN' where id = ?::uuid", stale);
            return null;
        });
        assertEquals(0, mirrorRows(missing));

        repairSweep.sweep();
        drainDeltas();

        Map<String, JsonNode> repaired = cryptoFindingsFor(Set.of(missing, stale));
        assertEquals(1, mirrorRows(missing), "a live finding regains its mirror row");
        assertEquals("AUTO_CLOSED", repaired.get(stale).path("status").asText(), "a withdrawn finding is closed by repair");

        long candidates = inTenant(() -> jdbc.queryForObject("""
                select count(*) from cbom_risk_findings r join cbom_components c on c.id = r.cbom_component_id
                 left join findings f on f.fingerprint = 'cbom:' || r.id::text and f.finding_kind = 'CRYPTO'
                 where r.id in (?::uuid, ?::uuid)
                   and ((r.status = 'OPEN' and c.active and r.evidence_state <> 'WITHDRAWN' and f.id is null)
                     or (f.status = 'OPEN' and not (r.status = 'OPEN' and c.active and r.evidence_state <> 'WITHDRAWN')))
                """, Long.class, missing, stale));
        assertEquals(0, candidates, "repaired rows leave the drift candidate set");
    }

    @Test
    void backfillReportsProgressAndIsIdempotentAcrossStarts() throws Exception {
        pushCbom();

        JsonNode before = json(mockMvc.perform(asPlatformOwner(authedGet("/api/bom/cbom/assessment-backfill")))
                .andExpect(status().isOk()).andReturn());
        assertTrue(before.path("activeArtifacts").asInt() >= 1);
        assertTrue(before.path("rulePackageDigest").asText().length() > 0);

        // Ingest already queued an assessment for the new artifact, so a start finds nothing new
        // for it; a second start never duplicates work that is queued.
        JsonNode first = json(mockMvc.perform(asPlatformOwner(authedPost("/api/bom/cbom/assessment-backfill?limit=50")))
                .andExpect(status().isOk()).andReturn());
        JsonNode second = json(mockMvc.perform(asPlatformOwner(authedPost("/api/bom/cbom/assessment-backfill?limit=50")))
                .andExpect(status().isOk()).andReturn());
        assertEquals(0, second.path("enqueued").asInt());
        JsonNode status = second.path("status");
        assertEquals(status.path("activeArtifacts").asInt(),
                status.path("assessed").asInt() + status.path("queued").asInt() + status.path("running").asInt()
                        + status.path("failed").asInt() + status.path("notStarted").asInt());
        assertEquals(0, status.path("notStarted").asInt(), "every active artifact is assessed or queued after a start");
        assertTrue(first.path("enqueued").asInt() >= 0);

        JsonNode fleet = json(mockMvc.perform(asPlatformOwner(authedGet("/api/platform/cbom/assessment-backfill")))
                .andExpect(status().isOk()).andReturn());
        assertTrue(fleet.isArray() && fleet.size() >= 1);
    }

    @Test
    void backfillStartRequiresTenantAdmin() throws Exception {
        // The plain API key carries OPERATOR/SECURITY_ANALYST only.
        mockMvc.perform(authedPost("/api/bom/cbom/assessment-backfill")).andExpect(status().isForbidden());
        mockMvc.perform(authedPost("/api/platform/cbom/assessment-backfill")).andExpect(status().isForbidden());
        mockMvc.perform(authedGet("/api/bom/cbom/assessment-backfill")).andExpect(status().isOk());
    }

    // ---------------------------------------------------------------- helpers

    private void drainDeltas() {
        for (int i = 0; i < 5; i++) {
            deltaQueue.processPendingDeltas();
        }
    }

    private long mirrorRows(String cbomFindingId) {
        return inTenant(() -> jdbc.queryForObject(
                "select count(*) from findings where fingerprint = ? and status = 'OPEN'", Long.class, "cbom:" + cbomFindingId));
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

    private String pushCbom() throws Exception {
        String body = Files.readString(Path.of("src/test/resources/fixtures/bom/cbom-9-assets.cdx.json"))
                .replace(SERIAL, "urn:uuid:" + UUID.randomUUID())
                // A distinct application per push, so documents do not supersede one another.
                .replace("scoutgrid-prototype-app", "delta-it-" + UUID.randomUUID());
        return json(mockMvc.perform(asPlatformOwner(authedPost("/api/bom/ingest?bomType=CBOM"))
                        .contentType("application/json")
                        .content(body.getBytes(StandardCharsets.UTF_8)))
                .andExpect(status().is2xxSuccessful()).andReturn()).path("bomId").asText();
    }

    private Set<String> cbomFindingIds(String bomId) throws Exception {
        Set<String> ids = new LinkedHashSet<>();
        for (JsonNode row : get("/api/bom/inventory/" + bomId + "/cbom-assets")) {
            row.path("findings").forEach(f -> ids.add(f.path("id").asText()));
        }
        return ids;
    }

    private Map<String, JsonNode> cryptoFindingsFor(Set<String> cbomFindingIds) throws Exception {
        Map<String, JsonNode> byCbomFinding = new HashMap<>();
        for (JsonNode row : get("/api/findings?findingKind=CRYPTO&page=0&size=500").path("items")) {
            String id = objectMapper.readTree(row.path("evidence").asText("{}")).path("cbomFindingId").asText();
            if (cbomFindingIds.contains(id)) {
                byCbomFinding.put(id, row);
            }
        }
        return byCbomFinding;
    }
}
