package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.dto.BomInspectionResponse;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.dto.ParsedComponent;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class SbomParserServiceTest {

    private final SbomParserService parser = new SbomParserService(new ObjectMapper());

    @Test
    void preservesExistingBestEffortJsonDetectionButRejectsUnknownXmlNamespace() throws Exception {
        Assertions.assertEquals(SbomFormat.CYCLONEDX,
                parser.detectFormat("{\"components\":[{\"name\":\"a\"}]}".getBytes(StandardCharsets.UTF_8)));
        Assertions.assertEquals(SbomFormat.UNKNOWN, parser.detectFormat((
                "<bom xmlns=\"urn:unsupported\"><components><component><name>a</name>"
                + "</component></components></bom>").getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void shouldParseGithubWrappedSpdxSbom() throws Exception {
        String payload = """
                {
                  "sbom": {
                    "spdxVersion": "SPDX-2.3",
                    "packages": [
                      {
                        "name": "lodash",
                        "versionInfo": "4.17.21",
                        "externalRefs": [
                          {
                            "referenceType": "purl",
                            "referenceLocator": "pkg:npm/lodash@4.17.21"
                          }
                        ]
                      }
                    ]
                  }
                }
                """;

        SbomFormat format = parser.detectFormat(payload.getBytes(StandardCharsets.UTF_8));
        List<ParsedComponent> components = parser.parse(payload.getBytes(StandardCharsets.UTF_8));

        Assertions.assertEquals(SbomFormat.SPDX, format);
        Assertions.assertEquals(1, components.size());
        Assertions.assertEquals("npm", components.get(0).ecosystem());
        Assertions.assertEquals("lodash", components.get(0).packageName());
        Assertions.assertEquals("4.17.21", components.get(0).version());
        Assertions.assertTrue(components.get(0).cpes().stream().anyMatch(cpe -> cpe.contains(":lodash:")));
    }

    @Test
    void shouldExtractDigestFromCycloneDxHashes() throws Exception {
        String payload = """
                {
                  "bomFormat": "CycloneDX",
                  "components": [
                    {
                      "name": "requests",
                      "version": "2.31.0",
                      "purl": "pkg:pypi/requests@2.31.0",
                      "hashes": [
                        {
                          "alg": "SHA-256",
                          "content": "4d5f0ca4f0d4f9f95f2f96b3f3f2c12f2f4b6e8f8f4d9a1f8a2c3b4d5e6f7081"
                        }
                      ]
                    }
                  ]
                }
                """;

        List<ParsedComponent> components = parser.parse(payload.getBytes(StandardCharsets.UTF_8));
        Assertions.assertEquals(1, components.size());
        Assertions.assertEquals("sha256:4d5f0ca4f0d4f9f95f2f96b3f3f2c12f2f4b6e8f8f4d9a1f8a2c3b4d5e6f7081", components.get(0).digest());
    }

    @Test
    void shouldParseCycloneDxXmlBom() throws Exception {
        String payload = """
                <?xml version="1.0" encoding="UTF-8"?>
                <bom xmlns="http://cyclonedx.org/schema/bom/1.6" version="1">
                  <metadata>
                    <component type="application">
                      <name>orders-service</name>
                      <version>2.5.1</version>
                      <purl>pkg:maven/com.securitygrid/orders-service@2.5.1</purl>
                    </component>
                  </metadata>
                  <components>
                    <component type="library">
                      <name>jackson-databind</name>
                      <version>2.17.2</version>
                      <purl>pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.2</purl>
                    </component>
                  </components>
                </bom>
                """;

        SbomFormat format = parser.detectFormat(payload.getBytes(StandardCharsets.UTF_8));
        List<ParsedComponent> components = parser.parse(payload.getBytes(StandardCharsets.UTF_8));

        Assertions.assertEquals(SbomFormat.CYCLONEDX, format);
        Assertions.assertEquals(1, components.size());
        Assertions.assertEquals("jackson-databind", components.get(0).packageName());
        Assertions.assertEquals("2.17.2", components.get(0).version());
        Assertions.assertEquals("pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.17.2", components.get(0).purl());
    }

    @Test
    void shouldMarkCycloneDxCurrentVersionAsSupported() {
        BomInspectionResponse inspection = parser.inspectResolved("CYCLONEDX", "1.6", "CYCLONEDX", "XML");

        Assertions.assertTrue(inspection.supported());
        Assertions.assertEquals("CURRENT", inspection.supportLevel());
        Assertions.assertTrue(inspection.warnings().isEmpty());
    }

    @Test
    void shouldMarkSpdxPreviousVersionAsSupported() {
        BomInspectionResponse inspection = parser.inspectResolved("SPDX", "2.2", "SPDX", "JSON");

        Assertions.assertTrue(inspection.supported());
        Assertions.assertEquals("PREVIOUS", inspection.supportLevel());
        Assertions.assertTrue(inspection.warnings().isEmpty());
    }

    @Test
    void shouldWarnForLegacyCycloneDxVersion() {
        BomInspectionResponse inspection = parser.inspectResolved("CYCLONEDX", "1.4", "CYCLONEDX", "JSON");

        Assertions.assertTrue(inspection.supported());
        Assertions.assertEquals("LEGACY", inspection.supportLevel());
        Assertions.assertTrue(
                inspection.warnings().stream()
                        .anyMatch(warning -> warning.contains("legacy spec version"))
        );
    }

    @Test
    void shouldRejectUnsupportedSpdxVersion() {
        BomInspectionResponse inspection = parser.inspectResolved("SPDX", "2.0", "SPDX", "JSON");

        Assertions.assertFalse(inspection.supported());
        Assertions.assertEquals("UNKNOWN", inspection.supportLevel());
        Assertions.assertTrue(
                inspection.warnings().stream()
                        .anyMatch(warning -> warning.contains("not in the supported matrix"))
        );
    }

    private static final String SPDX_JSON = """
            {
              "spdxVersion": "SPDX-2.3",
              "SPDXID": "SPDXRef-DOCUMENT",
              "documentNamespace": "https://example.test/spdx/app-1",
              "packages": [
                {
                  "name": "lodash",
                  "SPDXID": "SPDXRef-lodash",
                  "versionInfo": "4.17.21",
                  "licenseDeclared": "MIT",
                  "checksums": [{"algorithm": "SHA256", "checksumValue": "abc123"}],
                  "externalRefs": [
                    {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                     "referenceLocator": "pkg:npm/lodash@4.17.21"}
                  ]
                }
              ]
            }
            """;

    private static final String SPDX_XML = """
            <?xml version="1.0" encoding="UTF-8"?>
            <Document xmlns="http://spdx.org/spdxdocs/app-1">
              <spdxVersion>SPDX-2.3</spdxVersion>
              <SPDXID>SPDXRef-DOCUMENT</SPDXID>
              <documentNamespace>https://example.test/spdx/app-1</documentNamespace>
              <packages>
                <name>lodash</name>
                <SPDXID>SPDXRef-lodash</SPDXID>
                <versionInfo>4.17.21</versionInfo>
                <licenseDeclared>MIT</licenseDeclared>
                <checksums>
                  <algorithm>SHA256</algorithm>
                  <checksumValue>abc123</checksumValue>
                </checksums>
                <externalRefs>
                  <referenceCategory>PACKAGE-MANAGER</referenceCategory>
                  <referenceType>purl</referenceType>
                  <referenceLocator>pkg:npm/lodash@4.17.21</referenceLocator>
                </externalRefs>
              </packages>
            </Document>
            """;

    @Test
    void spdxXmlIsDetectedAndParsesToTheSameComponentsAsSpdxJson() throws Exception {
        byte[] xml = SPDX_XML.getBytes(StandardCharsets.UTF_8);

        Assertions.assertEquals(SbomFormat.SPDX, parser.detectFormat(xml));

        List<ParsedComponent> fromXml = parser.parse(xml);
        List<ParsedComponent> fromJson = parser.parse(SPDX_JSON.getBytes(StandardCharsets.UTF_8));
        Assertions.assertEquals(1, fromXml.size());
        Assertions.assertEquals(fromJson, fromXml);
        Assertions.assertEquals("lodash", fromXml.get(0).packageName());
        Assertions.assertEquals("4.17.21", fromXml.get(0).version());
        Assertions.assertEquals("pkg:npm/lodash@4.17.21", fromXml.get(0).purl());
    }

    @Test
    void spdxXmlInspectionReportsVersionAndXmlDocumentFormat() throws Exception {
        BomInspectionResponse inspection = parser.inspect(SPDX_XML.getBytes(StandardCharsets.UTF_8));

        Assertions.assertEquals("SPDX", inspection.specFamily());
        Assertions.assertEquals("XML", inspection.documentFormat());
        Assertions.assertEquals("2.3", inspection.formatVersion());
        Assertions.assertTrue(inspection.supported());
    }

    @Test
    void spdxXmlWithSeveralPackagesAndOneExternalRefKeepsArrays() throws Exception {
        String xml = SPDX_XML.replace("</Document>", """
                  <packages>
                    <name>left-pad</name>
                    <versionInfo>1.3.0</versionInfo>
                  </packages>
                </Document>
                """);

        List<ParsedComponent> parsed = parser.parse(xml.getBytes(StandardCharsets.UTF_8));

        Assertions.assertEquals(2, parsed.size());
        Assertions.assertEquals("left-pad", parsed.get(1).packageName());
    }

    @Test
    void spdxXmlRejectsDoctypeDeclarations() {
        String hostile = "<!DOCTYPE Document [<!ENTITY x SYSTEM \"file:///etc/passwd\">]>"
                + "<Document><spdxVersion>SPDX-2.3</spdxVersion><packages><name>&x;</name></packages></Document>";

        Assertions.assertEquals(SbomFormat.UNKNOWN, detectQuietly(hostile));
    }

    private SbomFormat detectQuietly(String content) {
        try {
            return parser.detectFormat(content.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            return SbomFormat.UNKNOWN;
        }
    }
}
