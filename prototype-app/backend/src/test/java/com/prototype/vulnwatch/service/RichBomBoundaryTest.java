package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.util.BomInputLimits;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** Combined byte/component boundary using rich components, rather than a whitespace-only byte fixture. */
class RichBomBoundaryTest {
    @ParameterizedTest
    @ValueSource(strings = {"cyclonedx", "spdx", "xml"})
    void richInventoryAtBothExistingLimitsPreservesTheLastComponent(String format) throws Exception {
        String component = switch (format) {
            case "xml" -> """
                    <component type="library"><name>controlled-library</name><version>1.2.3</version>
                    <purl>pkg:maven/example/controlled-library@1.2.3</purl>
                    <cpe>cpe:2.3:a:example:controlled:1.2.3:*:*:*:*:*:*:*</cpe>
                    <description>Controlled boundary fixture with supplier, identity and licensing metadata</description>
                    <supplier><name>Example</name></supplier><licenses><license><id>MIT</id></license></licenses></component>
                    """;
            case "spdx" -> """
                    {"SPDXID":"SPDXRef-controlled","name":"controlled-library","versionInfo":"1.2.3",
                     "supplier":"Organization: Example","licenseConcluded":"MIT","downloadLocation":"NOASSERTION",
                     "externalRefs":[{"referenceCategory":"PACKAGE-MANAGER","referenceType":"purl","referenceLocator":"pkg:maven/example/controlled-library@1.2.3"},
                     {"referenceCategory":"SECURITY","referenceType":"cpe23Type","referenceLocator":"cpe:2.3:a:example:controlled:1.2.3:*:*:*:*:*:*:*"}]}
                    """;
            default -> """
                    {"type":"library","name":"controlled-library","version":"1.2.3",
                     "purl":"pkg:maven/example/controlled-library@1.2.3","cpe":"cpe:2.3:a:example:controlled:1.2.3:*:*:*:*:*:*:*",
                     "supplier":{"name":"Example"},"licenses":[{"license":{"id":"MIT"}}],
                     "properties":[{"name":"fixture.provenance","value":"controlled-rich-boundary"}],
                     "description":"Controlled library with identity, supplier, provenance and licensing metadata"}
                    """;
        };
        String body;
        if ("xml".equals(format)) {
            body = "<bom><components>" + component.repeat(BomInputLimits.MAX_COMPONENTS) + "</components></bom>";
        } else {
            String prefix = "spdx".equals(format) ? "{\"spdxVersion\":\"SPDX-2.3\",\"packages\":["
                    : "{\"bomFormat\":\"CycloneDX\",\"components\":[";
            body = prefix + (component + ",").repeat(BomInputLimits.MAX_COMPONENTS - 1) + component + "]}";
        }
        byte[] content = body.getBytes(StandardCharsets.UTF_8);
        assertTrue(content.length > BomInputLimits.MAX_BOM_BYTES / 2);
        assertTrue(content.length <= BomInputLimits.MAX_BOM_BYTES);
        byte[] exact = java.util.Arrays.copyOf(content, (int) BomInputLimits.MAX_BOM_BYTES);
        java.util.Arrays.fill(exact, content.length, exact.length, (byte) ' ');
        var parsed = new SbomParserService(new ObjectMapper()).parse(exact);
        assertEquals(BomInputLimits.MAX_COMPONENTS, parsed.size());
        assertEquals("controlled-library", parsed.get(parsed.size() - 1).packageName());
        assertEquals("1.2.3", parsed.get(parsed.size() - 1).version());
    }
}
