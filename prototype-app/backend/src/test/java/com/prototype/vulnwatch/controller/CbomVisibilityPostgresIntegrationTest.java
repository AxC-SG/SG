package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.service.FindingDeltaQueueService;
import com.prototype.vulnwatch.service.TenantContext;
import com.prototype.vulnwatch.service.TenantService;
import com.prototype.vulnwatch.service.cbom.CbomAssessmentWorkerService;
import com.prototype.vulnwatch.service.cbom.CbomReportService;
import com.prototype.vulnwatch.service.cbom.CbomVisibilityService;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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

/**
 * Milestone 2 visibility against real PostgreSQL: executive overview, trends and daily snapshots,
 * the filtered analyst inventory and evidence drawer, the semantic diff between two versions of a
 * CBOM, and the persisted report lifecycle (idempotent request, worker generation, audited
 * download, regeneration and retention expiry).
 */
@PostgresControllerIntegrationTest
class CbomVisibilityPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("cbom_visibility");
    private static final String SERIAL = "urn:uuid:5c1b7a52-3f0e-4d7b-9a1e-0b6c2d4e8f11";

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private MockMvc mockMvc;
    @Autowired private ObjectMapper objectMapper;
    @Autowired private FindingDeltaQueueService deltaQueue;
    @Autowired private CbomAssessmentWorkerService worker;
    @Autowired private CbomVisibilityService visibility;
    @Autowired private CbomReportService reports;
    @Autowired private TenantService tenantService;
    @Autowired private TransactionTemplate transactions;
    @Autowired private JdbcTemplate jdbc;

    @Test
    void overviewTrendsInventoryAndEvidenceDrawerReflectAnAssessedCbom() throws Exception {
        String application = "visibility-" + UUID.randomUUID();
        String bomId = push(fixture(application, false));
        awaitAssessment(bomId);
        drainDeltas();

        JsonNode overview = get("/api/bom/cbom/overview");
        assertTrue(overview.path("componentsByType").path("ALGORITHM").asInt() >= 4);
        assertTrue(overview.path("assurance").path("assessedArtifacts").asInt() >= 1);
        assertTrue(overview.path("assurance").path("averageCompleteness").isNumber());
        assertTrue(overview.path("remediation").path("open").asInt() >= 1, "mirrored CRYPTO findings are open");
        assertTrue(overview.path("cryptoExposureNote").asText().contains("do not change Exposure CVE counts"));

        JsonNode trends = get("/api/bom/cbom/trends?days=30");
        JsonNode live = trends.path("points").get(trends.path("points").size() - 1);
        assertTrue(live.path("live").asBoolean());
        assertEquals(overview.path("remediation").path("open").asInt(), live.path("openCryptoFindings").asInt());
        inTenant(() -> transactions.execute(tx -> { visibility.snapshot(tenantService.getDefaultTenant()); return null; }));
        inTenant(() -> transactions.execute(tx -> { visibility.snapshot(tenantService.getDefaultTenant()); return null; }));
        assertEquals(1L, (long) inTenant(() -> jdbc.queryForObject(
                "select count(*) from cbom_posture_snapshots where snapshot_date = current_date", Long.class)), "snapshots are idempotent per day");

        JsonNode algorithms = get("/api/bom/cbom/inventory?assetType=ALGORITHM&bomId=" + bomId + "&size=2");
        assertEquals(2, algorithms.path("items").size());
        assertTrue(algorithms.path("hasNext").asBoolean());
        assertEquals(4, algorithms.path("total").asInt());
        assertFalse(algorithms.path("totalCapped").asBoolean());
        algorithms.path("items").forEach(item -> assertEquals("ALGORITHM", item.path("assetType").asText()));
        JsonNode named = get("/api/bom/cbom/inventory?q=bcrypt&bomId=" + bomId);
        assertEquals(1, named.path("items").size());
        mockMvc.perform(asPlatformOwner(authedGet("/api/bom/cbom/inventory?severity=SEVERE"))).andExpect(status().isBadRequest());

        JsonNode withFindings = get("/api/bom/cbom/inventory?bomId=" + bomId + "&size=50");
        String componentId = null;
        for (JsonNode item : withFindings.path("items")) {
            if (item.path("openFindings").asInt() > 0) { componentId = item.path("id").asText(); break; }
        }
        assertTrue(componentId != null, "the fixture produces at least one component with an open finding");
        JsonNode drawer = get("/api/bom/cbom/components/" + componentId);
        assertEquals(bomId, drawer.path("provenance").path("bomId").asText());
        assertTrue(drawer.path("provenance").path("rulePackage").asText().startsWith("scoutgrid-baseline@"));
        assertTrue(drawer.path("claims").size() >= 1);
        JsonNode finding = drawer.path("findings").get(0);
        assertTrue(finding.path("recommendation").asText().length() > 0);
        assertTrue(finding.path("canonical").path("displayId").asText().length() > 0, "drawer links the canonical finding");
        mockMvc.perform(asPlatformOwner(authedGet("/api/bom/cbom/components/" + UUID.randomUUID()))).andExpect(status().isBadRequest());
    }

    @Test
    void semanticDiffClassifiesOmissionChangeAndIntroducedFindingsAgainstThePredecessor() throws Exception {
        String application = "diff-" + UUID.randomUUID();
        String first = push(fixture(application, false));
        String second = push(fixture(application, true));

        JsonNode noBaseline = get("/api/bom/inventory/" + first + "/diff");
        assertEquals("NONE", noBaseline.path("baselineSource").asText());

        JsonNode diff = get("/api/bom/inventory/" + second + "/diff");
        assertEquals("PREDECESSOR", diff.path("baselineSource").asText());
        assertEquals(first, diff.path("baselineBomId").asText());
        assertEquals(1, diff.path("componentSummary").path("NOT_OBSERVED").asInt(), "bcrypt was omitted");
        assertTrue(diff.path("componentSummary").path("CHANGED").asInt() >= 1, "the TLS protocol version changed");
        boolean protocolChange = false;
        for (JsonNode change : diff.path("componentChanges")) {
            for (JsonNode field : change.path("fields")) {
                if ("protocolVersion".equals(field.path("field").asText())) {
                    protocolChange = true;
                    assertEquals("PROTOCOL", field.path("category").asText());
                    assertEquals("TLSv1.0", field.path("after").asText());
                }
            }
        }
        assertTrue(protocolChange);
        assertTrue(diff.path("findingSummary").path("INTRODUCED").asInt() >= 1, "TLS 1.0 introduces a deprecated-protocol finding");
        assertEquals(0, diff.path("ambiguous").size());

        JsonNode explicit = get("/api/bom/inventory/" + first + "/diff?baselineBomId=" + second);
        assertEquals("REQUESTED", explicit.path("baselineSource").asText());
        assertEquals(1, explicit.path("componentSummary").path("ADDED").asInt());
        mockMvc.perform(asPlatformOwner(authedGet("/api/bom/inventory/" + first + "/diff?baselineBomId=" + first)))
                .andExpect(status().isBadRequest());
    }

    @Test
    void reportsAreIdempotentGeneratedByTheWorkerAuditedOnDownloadAndExpire() throws Exception {
        String bomId = push(fixture("report-" + UUID.randomUUID(), false));
        String runId = awaitAssessment(bomId);
        String body = "{\"assessmentRunId\":\"" + runId + "\",\"format\":\"html\"}";

        mockMvc.perform(asPlatformOwner(authedPost("/api/bom/inventory/" + bomId + "/reports"))
                .contentType("application/json").content(body)).andExpect(status().isBadRequest());
        String key = "report-" + UUID.randomUUID();
        JsonNode requested = json(mockMvc.perform(asPlatformOwner(authedPost("/api/bom/inventory/" + bomId + "/reports"))
                .header("Idempotency-Key", key).contentType("application/json").content(body))
                .andExpect(status().isAccepted()).andReturn());
        JsonNode repeated = json(mockMvc.perform(asPlatformOwner(authedPost("/api/bom/inventory/" + bomId + "/reports"))
                .header("Idempotency-Key", key).contentType("application/json").content(body))
                .andExpect(status().isAccepted()).andReturn());
        assertEquals(requested.path("id").asText(), repeated.path("id").asText(), "the idempotency key returns the same report");
        mockMvc.perform(asPlatformOwner(authedPost("/api/bom/inventory/" + bomId + "/reports"))
                .header("Idempotency-Key", key).contentType("application/json")
                .content("{\"assessmentRunId\":\"" + runId + "\",\"format\":\"json\"}")).andExpect(status().isConflict());

        String reportId = requested.path("id").asText();
        String base = "/api/bom/inventory/" + bomId + "/reports/" + reportId;
        mockMvc.perform(asPlatformOwner(authedGet(base + "/download"))).andExpect(status().isConflict());
        JsonNode ready = awaitReport(base);
        assertEquals("UNSIGNED", ready.path("signatureStatus").asText());
        assertEquals(64, ready.path("checksumSha256").asText().length());

        MvcResult download = mockMvc.perform(asPlatformOwner(authedGet(base + "/download")))
                .andExpect(status().isOk())
                .andExpect(header().string("X-Content-SHA256", ready.path("checksumSha256").asText()))
                .andExpect(header().string("X-Report-Signature-Status", "UNSIGNED"))
                .andExpect(header().string("Cache-Control", "no-store")).andReturn();
        String html = download.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertTrue(html.contains(CbomReportService.UNSIGNED_NOTICE));
        assertTrue(html.contains("default-src 'none'"), "the HTML report blocks external resources");
        assertEquals(1, get(base).path("downloadCount").asInt());
        assertEquals(1L, (long) inTenant(() -> jdbc.queryForObject(
                "select count(*) from audit_events where action = 'cbom.report.downloaded' and target_id = ?", Long.class, reportId)));

        JsonNode regenerated = json(mockMvc.perform(asPlatformOwner(authedPost(base + "/regenerate"))
                .header("Idempotency-Key", "regen-" + UUID.randomUUID())).andExpect(status().isAccepted()).andReturn());
        assertNotEquals(reportId, regenerated.path("id").asText());
        assertEquals(reportId, regenerated.path("regeneratedFrom").asText());
        assertTrue(get("/api/bom/inventory/" + bomId + "/reports").size() >= 2);

        inTenant(() -> jdbc.update("update cbom_report_artifacts set expires_at = now() - interval '1 minute' where id = ?::uuid", reportId));
        assertTrue(reports.expire(tenantService.getDefaultTenant()) >= 1);
        assertEquals("EXPIRED", get(base).path("status").asText());
        mockMvc.perform(asPlatformOwner(authedGet(base + "/download"))).andExpect(status().isGone());
    }

    // ---------------------------------------------------------------- helpers

    /** The 9-asset fixture; the second version omits bcrypt and declares TLSv1.0 outbound. */
    private byte[] fixture(String application, boolean secondVersion) throws Exception {
        String text = Files.readString(Path.of("src/test/resources/fixtures/bom/cbom-9-assets.cdx.json"))
                .replace(SERIAL, "urn:uuid:" + UUID.randomUUID())
                .replace("scoutgrid-prototype-app", application);
        ObjectNode document = (ObjectNode) objectMapper.readTree(text);
        if (secondVersion) {
            ArrayNode components = (ArrayNode) document.path("components");
            for (int i = components.size() - 1; i >= 0; i--) {
                JsonNode component = components.get(i);
                if ("crypto/algorithm/bcrypt".equals(component.path("bom-ref").asText())) components.remove(i);
                if ("crypto/protocol/tls-outbound".equals(component.path("bom-ref").asText())) {
                    ((ObjectNode) component.path("cryptoProperties").path("protocolProperties")).put("version", "TLSv1.0");
                }
            }
        }
        return objectMapper.writeValueAsBytes(document);
    }

    private String push(byte[] body) throws Exception {
        return json(mockMvc.perform(asPlatformOwner(authedPost("/api/bom/ingest?bomType=CBOM"))
                        .contentType("application/json").content(body))
                .andExpect(status().is2xxSuccessful()).andReturn()).path("bomId").asText();
    }

    private String awaitAssessment(String bomId) throws Exception {
        for (int attempt = 0; attempt < 60; attempt++) {
            worker.poll();
            for (JsonNode run : get("/api/bom/cbom/assessments?bomId=" + bomId)) {
                if ("SUCCEEDED".equals(run.path("status").asText())) return run.path("id").asText();
            }
            Thread.sleep(250);
        }
        throw new AssertionError("assessment did not complete for " + bomId);
    }

    private JsonNode awaitReport(String path) throws Exception {
        for (int attempt = 0; attempt < 60; attempt++) {
            worker.poll();
            JsonNode report = get(path);
            if ("READY".equals(report.path("status").asText())) return report;
            if ("FAILED".equals(report.path("status").asText())) throw new AssertionError("report failed: " + report);
            Thread.sleep(250);
        }
        throw new AssertionError("report was not generated: " + path);
    }

    private void drainDeltas() {
        for (int i = 0; i < 5; i++) deltaQueue.processPendingDeltas();
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
