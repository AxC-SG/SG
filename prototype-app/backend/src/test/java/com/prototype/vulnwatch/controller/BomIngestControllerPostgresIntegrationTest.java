package com.prototype.vulnwatch.controller;

import static com.prototype.vulnwatch.support.AuthRequest.asPlatformOwner;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import com.prototype.vulnwatch.support.PostgresControllerIntegrationTest;
import com.prototype.vulnwatch.support.PostgresITSupport;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

@PostgresControllerIntegrationTest
class BomIngestControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("bom_ingest_api");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        PostgresITSupport.registerDatabaseProperties(registry, DATABASE);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static String cycloneDx(String app, String serial, String... componentNames) {
        StringBuilder components = new StringBuilder();
        for (String name : componentNames) {
            if (components.length() > 0) {
                components.append(',');
            }
            components.append("{\"type\":\"library\",\"name\":\"").append(name)
                    .append("\",\"version\":\"1.0.0\",\"purl\":\"pkg:npm/").append(name).append("@1.0.0\"}");
        }
        return "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"serialNumber\":\"urn:uuid:" + serial
                + "\",\"metadata\":{\"component\":{\"type\":\"application\",\"name\":\"" + app
                + "\",\"purl\":\"pkg:generic/" + app + "@9.9.9\"}},\"components\":[" + components + "]}";
    }

    private static String spdxXml(String app, String namespace) {
        return """
                <?xml version="1.0" encoding="UTF-8"?>
                <Document xmlns="http://spdx.org/spdxdocs/%1$s">
                  <spdxVersion>SPDX-2.3</spdxVersion>
                  <SPDXID>SPDXRef-DOCUMENT</SPDXID>
                  <name>%1$s</name>
                  <documentNamespace>%2$s</documentNamespace>
                  <packages>
                    <name>%1$s</name>
                    <SPDXID>SPDXRef-RootPackage</SPDXID>
                    <versionInfo>2.0.0</versionInfo>
                  </packages>
                  <packages>
                    <name>lodash</name>
                    <SPDXID>SPDXRef-lodash</SPDXID>
                    <versionInfo>4.17.21</versionInfo>
                    <externalRefs>
                      <referenceCategory>PACKAGE-MANAGER</referenceCategory>
                      <referenceType>purl</referenceType>
                      <referenceLocator>pkg:npm/lodash@4.17.21</referenceLocator>
                    </externalRefs>
                  </packages>
                </Document>
                """.formatted(app, namespace);
    }

    private MockHttpServletRequestBuilder push(String ignoredType, String contentType, String body, String query) {
        MockHttpServletRequestBuilder request = asPlatformOwner(authedPost("/api/bom/ingest" + query));
        if (contentType != null) {
            request.contentType(contentType);
        }
        return request.content(body.getBytes(StandardCharsets.UTF_8));
    }

    private JsonNode json(MvcResult result) throws Exception {
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    @Test
    void firstPushCreatesDerivesTheAssetAndReportsStatus() throws Exception {
        String app = "pay-" + UUID.randomUUID().toString().substring(0, 8);
        MvcResult created = mockMvc.perform(push("SBOM", "application/json",
                        cycloneDx(app, UUID.randomUUID().toString(), "left-pad", "right-pad"),
                        "?bomType=SBOM&pipeline=github-actions&buildId=1042"))
                .andExpect(status().isCreated())
                .andReturn();

        JsonNode body = json(created);
        assertEquals("CREATED", body.path("action").asText());
        assertEquals("CYCLONEDX", body.path("format").asText());
        assertEquals(2, body.path("componentCount").asInt());
        String statusUrl = body.path("statusUrl").asText();
        assertEquals("/api/bom/ingest/" + body.path("bomId").asText() + "/status", statusUrl);

        JsonNode state = json(mockMvc.perform(authedGet(statusUrl)).andExpect(status().isOk()).andReturn());
        assertEquals("ACTIVE", state.path("state").asText());
        assertEquals("github-actions", state.path("pipeline").asText());
        assertEquals("1042", state.path("build").asText());
    }

    @Test
    void aPushShowsUpInTheInventoryWithItsPipelineBuildAndCorrelator() throws Exception {
        String app = "inv-" + UUID.randomUUID().toString().substring(0, 8);
        JsonNode pushed = json(mockMvc.perform(push("SBOM", "application/json",
                        cycloneDx(app, UUID.randomUUID().toString(), "left-pad"),
                        "?bomType=SBOM&pipeline=jenkins&buildId=88&correlator=acme/" + app))
                .andExpect(status().isCreated()).andReturn());

        JsonNode inventory = json(mockMvc.perform(asPlatformOwner(authedGet("/api/bom/inventory?page=0&size=200")))
                .andExpect(status().isOk()).andReturn());
        JsonNode item = null;
        for (JsonNode candidate : inventory) {
            if (pushed.path("bomId").asText().equals(candidate.path("id").asText())) {
                item = candidate;
            }
        }
        assertTrue(item != null, "the pushed BOM should be listed");
        assertEquals("API", item.path("sourceType").asText());
        assertEquals("jenkins", item.path("sourceSystem").asText());
        assertEquals("build:88", item.path("sourceLabel").asText());
        assertEquals("acme/" + app, item.path("sourceReference").asText());
    }

    @Test
    void retriedIdenticalPushIsUnchangedAndAChangedPushReplacesTheVersion() throws Exception {
        String app = "retry-" + UUID.randomUUID().toString().substring(0, 8);
        String serial = UUID.randomUUID().toString();
        String document = cycloneDx(app, serial, "left-pad");

        JsonNode first = json(mockMvc.perform(push("SBOM", "application/json", document, "?bomType=SBOM"))
                .andExpect(status().isCreated()).andReturn());
        JsonNode retry = json(mockMvc.perform(push("SBOM", "application/json", document, "?bomType=SBOM"))
                .andExpect(status().isOk()).andReturn());
        assertEquals("UNCHANGED", retry.path("action").asText());
        assertEquals(first.path("bomId").asText(), retry.path("bomId").asText());

        JsonNode replaced = json(mockMvc.perform(push("SBOM", "application/json",
                        cycloneDx(app, UUID.randomUUID().toString(), "left-pad", "right-pad"), "?bomType=SBOM"))
                .andExpect(status().isOk()).andReturn());
        assertEquals("REPLACED", replaced.path("action").asText());
        assertNotEquals(first.path("bomId").asText(), replaced.path("bomId").asText());

        JsonNode old = json(mockMvc.perform(authedGet(first.path("statusUrl").asText()))
                .andExpect(status().isOk()).andReturn());
        assertEquals("SUPERSEDED", old.path("state").asText());
        assertEquals(replaced.path("bomId").asText(), old.path("supersededBy").asText());
    }

    @Test
    void sameSerialWithDifferentContentIsRejectedRatherThanSilentlyDropped() throws Exception {
        String app = "serial-" + UUID.randomUUID().toString().substring(0, 8);
        String serial = UUID.randomUUID().toString();
        mockMvc.perform(push("SBOM", "application/json", cycloneDx(app, serial, "left-pad"), "?bomType=SBOM"))
                .andExpect(status().isCreated());

        JsonNode error = json(mockMvc.perform(push("SBOM", "application/json",
                        cycloneDx(app, serial, "left-pad", "right-pad"), "?bomType=SBOM"))
                .andExpect(status().isConflict()).andReturn());
        assertEquals("DUPLICATE_SERIAL_NUMBER", error.path("code").asText());
    }

    @Test
    void spdxXmlIsIngestedAndMatchesWhatSpdxJsonProduces() throws Exception {
        String app = "spdx-" + UUID.randomUUID().toString().substring(0, 8);
        JsonNode body = json(mockMvc.perform(push("SBOM", "application/xml",
                        spdxXml(app, "https://example.test/" + UUID.randomUUID()), "?bomType=SBOM"))
                .andExpect(status().isCreated()).andReturn());

        assertEquals("SPDX", body.path("format").asText());
        assertEquals("XML", body.path("documentFormat").asText());
        assertEquals("2.3", body.path("formatVersion").asText());
        assertEquals(2, body.path("componentCount").asInt());
        assertTrue(body.path("supported").asBoolean());
    }

    @Test
    void aNewSpdxXmlVersionOfTheSameSourceReplacesTheOldOne() throws Exception {
        String app = "spdxv-" + UUID.randomUUID().toString().substring(0, 8);
        mockMvc.perform(push("SBOM", "text/xml", spdxXml(app, "https://example.test/" + UUID.randomUUID()),
                "?bomType=SBOM&assetName=" + app + "&assetIdentifier=pkg:generic/" + app))
                .andExpect(status().isCreated());

        JsonNode second = json(mockMvc.perform(push("SBOM", "text/xml",
                        spdxXml(app, "https://example.test/" + UUID.randomUUID()),
                        "?bomType=SBOM&assetName=" + app + "&assetIdentifier=pkg:generic/" + app))
                .andExpect(status().isOk()).andReturn());
        assertEquals("REPLACED", second.path("action").asText());
    }

    @Test
    void aCorrelatorGroupsPushesIntoOneSourceAcrossDifferentAssetNames() throws Exception {
        String suffix = UUID.randomUUID().toString().substring(0, 8);
        String correlator = "corr-" + suffix;
        mockMvc.perform(push("SBOM", "application/json", cycloneDx("matrix-a-" + suffix,
                        UUID.randomUUID().toString(), "left-pad"),
                "?bomType=SBOM&assetIdentifier=pkg:generic/shared-" + suffix + "&correlator=" + correlator))
                .andExpect(status().isCreated());

        JsonNode second = json(mockMvc.perform(push("SBOM", "application/json", cycloneDx("matrix-b-" + suffix,
                        UUID.randomUUID().toString(), "right-pad"),
                "?bomType=SBOM&assetIdentifier=pkg:generic/shared-" + suffix + "&correlator=" + correlator))
                .andExpect(status().isOk()).andReturn());
        assertEquals("REPLACED", second.path("action").asText());
    }

    @Test
    void contentTypeAndBodyProblemsReturnStableCodes() throws Exception {
        String doc = cycloneDx("bad", UUID.randomUUID().toString(), "left-pad");

        assertEquals("MISSING_CONTENT_TYPE", json(mockMvc.perform(push("SBOM", null, doc, "?bomType=SBOM"))
                .andExpect(status().isBadRequest()).andReturn()).path("code").asText());
        assertEquals("UNSUPPORTED_CONTENT_TYPE", json(mockMvc.perform(push("SBOM", "text/plain", doc, "?bomType=SBOM"))
                .andExpect(status().isBadRequest()).andReturn()).path("code").asText());
        assertEquals("EMPTY_BODY", json(mockMvc.perform(push("SBOM", "application/json", "", "?bomType=SBOM"))
                .andExpect(status().isBadRequest()).andReturn()).path("code").asText());
        assertEquals("INVALID_PARAMETER", json(mockMvc.perform(push("SBOM", "application/json", doc, "?bomType=NOPE"))
                .andExpect(status().isBadRequest()).andReturn()).path("code").asText());
        assertEquals("INVALID_PARAMETER", json(mockMvc.perform(push("SBOM", "application/json", doc, ""))
                .andExpect(status().isBadRequest()).andReturn()).path("code").asText());
    }

    @Test
    void unparseableUnsupportedAndAnonymousDocumentsAreRejectedWithDistinctCodes() throws Exception {
        assertEquals("INVALID_DOCUMENT", json(mockMvc.perform(push("SBOM", "application/json", "{not json", "?bomType=SBOM"))
                .andExpect(status().isUnprocessableEntity()).andReturn()).path("code").asText());
        assertEquals("UNSUPPORTED_FORMAT", json(mockMvc.perform(push("SBOM", "application/json", "{\"hello\":1}", "?bomType=SBOM"))
                .andExpect(status().isUnprocessableEntity()).andReturn()).path("code").asText());

        String noMetadata = "{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\","
                + "\"components\":[{\"type\":\"library\",\"name\":\"left-pad\",\"version\":\"1.0.0\"}]}";
        assertEquals("ASSET_NOT_DERIVABLE", json(mockMvc.perform(push("SBOM", "application/json", noMetadata, "?bomType=SBOM"))
                .andExpect(status().isUnprocessableEntity()).andReturn()).path("code").asText());
    }

    @Test
    void anUnauthenticatedPushIsRejected() throws Exception {
        mockMvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/api/bom/ingest?bomType=SBOM")
                        .contentType("application/json").content("{}"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void statusForAnUnknownBomIsNotFound() throws Exception {
        JsonNode error = json(mockMvc.perform(authedGet("/api/bom/ingest/" + UUID.randomUUID() + "/status"))
                .andExpect(status().isNotFound()).andReturn());
        assertEquals("BOM_NOT_FOUND", error.path("code").asText());
    }
}
