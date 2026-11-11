package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.BomFetchRequest;
import com.prototype.vulnwatch.dto.BomSourceSelector;
import com.prototype.vulnwatch.service.cbom.CbomIngestionResult;
import com.prototype.vulnwatch.service.cbom.CbomIngestionService;
import com.prototype.vulnwatch.service.sbomingestion.SbomIngestionSourceMetadata;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;

/** Calls the Spring proxies with no surrounding test transaction; assertions see committed state. */
@PostgresIntegrationTest
@Import(BomUploadRollbackPostgresIntegrationTest.OfflineHttp.class)
class BomUploadRollbackPostgresIntegrationTest {
    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("bom_upload_rollback");

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired private BomIngestionOrchestrator orchestrator;
    @Autowired private TenantService tenantService;
    @Autowired private AssetRepository assets;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private RestTemplate restTemplate;
    @MockitoSpyBean private CbomIngestionService cbomIngestionService;
    private Tenant tenant;
    private MockRestServiceServer server;

    @BeforeEach
    void selectTenantBeforeAnyTransaction() {
        tenant = tenantService.getDefaultTenant();
        TenantContext.setCurrentTenantId(tenant.getId());
        TenantContext.setCurrentSchemaName(tenant.getSchemaName());
        server = MockRestServiceServer.bindTo(restTemplate).build();
    }

    @AfterEach
    void clearContext() {
        TenantContext.clear();
    }

    static Stream<Arguments> rejectedDocuments() {
        return Stream.of("UPLOAD", "FETCHED", "URL").flatMap(path ->
                Stream.of(BomType.SBOM, BomType.CBOM).flatMap(type -> Stream.of(
                        Arguments.of(path, type, "{\"components\":["),
                        Arguments.of(path, type, "{\"unrecognized\":true}"),
                        Arguments.of(path, type, "<bom xmlns=\"urn:unsupported\"><components>"
                                + "<component><name>plausible</name></component></components></bom>"),
                        Arguments.of(path, type, "{\"bomFormat\":\"CycloneDX\",\"components\":[]}"),
                        Arguments.of(path, type, "<bom><components><component>"))));
    }

    @ParameterizedTest
    @MethodSource("rejectedDocuments")
    void rejectedReplacementPreservesEveryPreviouslyAcceptedRow(String path, BomType type, String invalid)
            throws Exception {
        String identifier = "rollback-existing-" + UUID.randomUUID();
        String url = "https://example.test/" + identifier;
        var initial = upload(type, identifier, valid(type, "1"), url);
        Map<String, List<Map<String, Object>>> before = snapshot(initial.assetId());
        assertFalse(before.get("bom_ingestion_records").isEmpty());
        assertFalse(before.get(type == BomType.CBOM ? "cbom_components" : "bom_component_evidence").isEmpty());

        assertThrows(IOException.class, () -> rejectThrough(path, type, identifier, invalid, url));

        assertEquals(before, snapshot(initial.assetId()),
                "Rejected documents must preserve the old BOM, components, evidence, asset and source pointer/revision");
        server.verify();
    }

    @ParameterizedTest
    @MethodSource("rejectedDocuments")
    void rejectedNewDocumentLeavesNoAssetOrSource(String path, BomType type, String invalid) {
        String identifier = "rollback-new-" + UUID.randomUUID();
        long sourceCount = count("bom_sources");
        long bomCount = count("bom_ingestion_records");
        long uploadCount = count("sbom_uploads");
        assertThrows(IOException.class, () -> rejectThrough(path, type, identifier, invalid,
                "https://example.test/" + identifier));
        assertTrue(assets.findByIdentifier(identifier).isEmpty());
        assertEquals(sourceCount, count("bom_sources"));
        assertEquals(bomCount, count("bom_ingestion_records"));
        assertEquals(uploadCount, count("sbom_uploads"));
        server.verify();
    }

    @Test
    void checkedFailureAfterPromotionRollsBackSupersessionEvidenceWithdrawalAndNewPointer() throws Exception {
        String identifier = "rollback-late-" + UUID.randomUUID();
        String url = "https://example.test/" + identifier;
        var initial = upload(BomType.CBOM, identifier, valid(BomType.CBOM, "1"), url);
        var before = snapshot(initial.assetId());
        assertFalse(before.get("cbom_risk_findings").isEmpty());
        // The orchestrator rejects an empty persistence result after deactivating the old CBOM
        // and updating the source pointer. The checked exception must roll both changes back.
        doReturn(new CbomIngestionResult(0, 0))
                .when(cbomIngestionService).ingestPrepared(any(), any(), any(), any());

        assertThrows(IOException.class, () -> upload(BomType.CBOM, identifier, valid(BomType.CBOM, "2"), url));

        assertEquals(before, snapshot(initial.assetId()));
    }

    private com.prototype.vulnwatch.dto.BomIngestionResultResponse upload(
            BomType type, String identifier, String content, String url) throws IOException {
        return orchestrator.ingestFromUpload(tenant, type, AssetType.APPLICATION, "accepted-name", identifier,
                "acme", bytes(content), "accepted.json", selector(type, url));
    }

    private void rejectThrough(String path, BomType type, String identifier, String content, String url)
            throws IOException {
        switch (path) {
            case "UPLOAD" -> orchestrator.ingestFromUpload(tenant, type, AssetType.APPLICATION,
                    "rejected-name", identifier, "changed-supplier", bytes(content), "rejected.json", selector(type, url));
            case "FETCHED" -> orchestrator.ingestFetchedContent(tenant, type, AssetType.APPLICATION,
                    "rejected-name", identifier, "changed-supplier", url, "URL", bytes(content), "rejected.json",
                    new SbomIngestionSourceMetadata("REMOTE_ENDPOINT", "api", "rejected.json", url,
                            200, "application/json", (long) bytes(content).length, null),
                    asset -> asset.setName("rejected-customizer"), selector(type, url));
            case "URL" -> {
                server.expect(requestTo(url)).andRespond(withSuccess(content, MediaType.APPLICATION_JSON));
                orchestrator.ingestFromUrl(tenant, new BomFetchRequest(type, AssetType.APPLICATION,
                        "rejected-name", identifier, url, "rejected", "changed-supplier", null));
            }
            default -> throw new IllegalArgumentException(path);
        }
    }

    private BomSourceSelector selector(BomType type, String url) {
        return BomSourceSelector.keyed("endpoint:" + type.name() + ":" + url);
    }

    private String valid(BomType type, String serial) {
        String component = type == BomType.CBOM
                ? "{\"type\":\"cryptographic-asset\",\"name\":\"weak-rsa\",\"cryptoProperties\":{"
                    + "\"assetType\":\"algorithm\",\"algorithmProperties\":{\"primitive\":\"RSA\",\"keySize\":1024}}}"
                : "{\"type\":\"library\",\"name\":\"a\",\"version\":\"1\",\"purl\":\"pkg:npm/a@1\"}";
        return "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.6\",\"serialNumber\":\"" + serial
                + "\",\"components\":[" + component + "]}";
    }

    private Map<String, List<Map<String, Object>>> snapshot(UUID assetId) {
        Map<String, List<Map<String, Object>>> rows = new LinkedHashMap<>();
        rows.put("assets", jdbc.queryForList("select * from assets where id = ?", assetId));
        for (String table : List.of("bom_sources", "bom_ingestion_records", "sbom_uploads", "inventory_components")) {
            rows.put(table, jdbc.queryForList("select * from " + table + " where asset_id = ? order by id", assetId));
        }
        for (String table : List.of("bom_components", "bom_component_evidence")) {
            rows.put(table, jdbc.queryForList("select * from " + table
                    + " where bom_id in (select id from bom_ingestion_records where asset_id = ?) order by id", assetId));
        }
        rows.put("cbom_components", jdbc.queryForList(
                "select * from cbom_components where asset_id = ? order by id", assetId));
        rows.put("cbom_risk_findings", jdbc.queryForList("select * from cbom_risk_findings where cbom_component_id in "
                + "(select id from cbom_components where asset_id = ?) order by id", assetId));
        return rows;
    }

    private long count(String table) {
        return jdbc.queryForObject("select count(*) from " + table, Long.class);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class OfflineHttp {
        @Bean
        @Primary
        OutboundHostPolicy offlineHostPolicy() {
            return OutboundHostPolicy.forTests();
        }
    }

    private byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
