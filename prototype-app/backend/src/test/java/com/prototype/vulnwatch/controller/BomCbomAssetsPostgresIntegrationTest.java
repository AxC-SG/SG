package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedDelete;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

@PostgresControllerIntegrationTest
class BomCbomAssetsPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("bom_cbom_assets");
    private static final String SERIAL = "urn:uuid:5c1b7a52-3f0e-4d7b-9a1e-0b6c2d4e8f11";

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private com.prototype.vulnwatch.service.FindingDeltaQueueService deltaQueue;

    /** Scheduling is off in ITs; drain CBOM_DELTA entries the way the 2-second poller would. */
    private void drainDeltas() {
        for (int i = 0; i < 5; i++) {
            deltaQueue.processPendingDeltas();
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
                .replace(SERIAL, "urn:uuid:" + UUID.randomUUID());
        JsonNode pushed = json(mockMvc.perform(asPlatformOwner(authedPost("/api/bom/ingest?bomType=CBOM"))
                        .contentType("application/json")
                        .content(body.getBytes(StandardCharsets.UTF_8)))
                // 201 for a first document, 200 when it replaces an earlier CBOM of the same application.
                .andExpect(status().is2xxSuccessful()).andReturn());
        assertEquals(9, pushed.path("componentCount").asInt());
        return pushed.path("bomId").asText();
    }

    @Test
    void aCbomReportsItsCryptoAssetsInInventoryDetailDashboardAndAssetList() throws Exception {
        long dashboardBefore = get("/api/bom/dashboard").path("componentCount").asLong();
        String bomId = pushCbom();

        JsonNode item = null;
        for (JsonNode candidate : get("/api/bom/inventory?page=0&size=200")) {
            if (bomId.equals(candidate.path("id").asText())) {
                item = candidate;
            }
        }
        assertTrue(item != null, "the CBOM should be listed");
        assertEquals(9, item.path("componentCount").asInt());
        assertEquals(9, get("/api/bom/inventory/" + bomId).path("componentCount").asInt());
        assertEquals(dashboardBefore + 9, get("/api/bom/dashboard").path("componentCount").asLong());

        int cryptoRows = 0;
        for (JsonNode row : get("/api/bom/components?page=0&size=2000")) {
            if ("crypto".equals(row.path("ecosystem").asText())) {
                assertEquals("CBOM", row.path("bomTypes").path(0).asText());
                cryptoRows++;
            }
        }
        assertTrue(cryptoRows >= 9, "the CBOM's assets are rows in the BOM Components grid");

        JsonNode assets = get("/api/bom/inventory/" + bomId + "/cbom-assets");
        assertEquals(9, assets.size());
        int linkedFindings = 0;
        boolean sawAlgorithm = false;
        boolean sawProtocol = false;
        for (JsonNode row : assets) {
            assertEquals(bomId, row.path("asset").path("sourceBomId").asText());
            String type = row.path("asset").path("assetType").asText();
            sawAlgorithm |= "ALGORITHM".equals(type);
            sawProtocol |= "PROTOCOL".equals(type);
            for (JsonNode finding : row.path("findings")) {
                assertEquals(row.path("asset").path("id").asText(), finding.path("componentId").asText());
                linkedFindings++;
            }
        }
        assertTrue(sawAlgorithm && sawProtocol, "algorithm and protocol assets are listed");
        assertTrue(linkedFindings >= 3, "the CBOM's risk findings are linked to their assets");
    }

    /** The canonical CRYPTO rows that mirror the given CBOM findings, keyed by CBOM finding id. */
    private java.util.Map<String, JsonNode> cryptoFindingsFor(java.util.Set<String> cbomFindingIds) throws Exception {
        drainDeltas();
        java.util.Map<String, JsonNode> byCbomFinding = new java.util.HashMap<>();
        for (JsonNode row : get("/api/findings?findingKind=CRYPTO&page=0&size=200").path("items")) {
            String cbomFindingId = objectMapper.readTree(row.path("evidence").asText("{}")).path("cbomFindingId").asText();
            if (cbomFindingIds.contains(cbomFindingId)) {
                byCbomFinding.put(cbomFindingId, row);
            }
        }
        return byCbomFinding;
    }

    @Test
    void cbomFindingsAreListedAsCryptoFindingsAndFollowAcceptAndDelete() throws Exception {
        String bomId = pushCbom();
        java.util.Set<String> cbomFindingIds = new java.util.LinkedHashSet<>();
        for (JsonNode row : get("/api/bom/inventory/" + bomId + "/cbom-assets")) {
            row.path("findings").forEach(f -> cbomFindingIds.add(f.path("id").asText()));
        }
        assertTrue(cbomFindingIds.size() >= 3);

        java.util.Map<String, JsonNode> crypto = cryptoFindingsFor(cbomFindingIds);
        assertEquals(cbomFindingIds.size(), crypto.size(), "every CBOM finding is in the findings list");
        for (JsonNode row : crypto.values()) {
            assertEquals("CRYPTO", row.path("findingKind").asText());
            assertEquals("OPEN", row.path("status").asText());
            assertTrue(!row.path("packageName").asText().isBlank(), "the crypto asset stands in for the package");
            assertTrue(!row.path("vulnerabilityId").asText().isBlank(), "the rule id stands in for the CVE id");
        }

        // Direct CBOM acceptance is a 410 tombstone; it must not suppress the canonical finding.
        String accepted = cbomFindingIds.iterator().next();
        mockMvc.perform(asPlatformOwner(authedPost("/api/bom/cbom/findings/" + accepted + "/accept")))
                .andExpect(status().isGone());
        assertEquals("OPEN", cryptoFindingsFor(cbomFindingIds).get(accepted).path("status").asText());

        mockMvc.perform(asPlatformOwner(authedDelete("/api/bom/inventory/" + bomId))).andExpect(status().isOk());
        java.util.Map<String, JsonNode> afterDelete = cryptoFindingsFor(cbomFindingIds);
        for (String id : cbomFindingIds) {
            assertEquals("AUTO_CLOSED", afterDelete.get(id).path("status").asText(),
                    "deleting the CBOM closes its open crypto findings without calling them remediated");
        }
    }

    @Test
    void assetListIsNotFoundForAnUnknownOrNonCbomRecord() throws Exception {
        mockMvc.perform(asPlatformOwner(authedGet("/api/bom/inventory/" + UUID.randomUUID() + "/cbom-assets")))
                .andExpect(status().isNotFound());

        String sbom = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"serialNumber\":\"urn:uuid:" + UUID.randomUUID()
                + "\",\"metadata\":{\"component\":{\"type\":\"application\",\"name\":\"plain-app\"}},"
                + "\"components\":[{\"type\":\"library\",\"name\":\"left-pad\",\"version\":\"1.0.0\"}]}";
        String sbomId = json(mockMvc.perform(asPlatformOwner(authedPost("/api/bom/ingest?bomType=SBOM"))
                        .contentType("application/json").content(sbom.getBytes(StandardCharsets.UTF_8)))
                .andExpect(status().isCreated()).andReturn()).path("bomId").asText();
        mockMvc.perform(asPlatformOwner(authedGet("/api/bom/inventory/" + sbomId + "/cbom-assets")))
                .andExpect(status().isNotFound());
    }

    @Test
    void assetListRequiresAuthentication() throws Exception {
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                        .get("/api/bom/inventory/" + UUID.randomUUID() + "/cbom-assets"))
                .andExpect(status().is4xxClientError());
    }
}
