package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.cbom.CbomComponentParser;
import com.prototype.vulnwatch.util.BomInputLimits;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import javax.xml.parsers.DocumentBuilderFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

class BomInputBoundsTest {
    private final SbomParserService parser = new SbomParserService(new ObjectMapper());
    private final CbomComponentParser cbomParser = new CbomComponentParser(new ObjectMapper());

    @ParameterizedTest
    @ValueSource(strings = {"cyclonedx", "spdx", "wrapped-spdx", "xml"})
    void acceptsExistingComponentCeilingAndRejectsOneMore(String format) throws Exception {
        assertEquals(BomInputLimits.MAX_COMPONENTS, parser.parse(document(format, 100_000)).size());
        assertThrows(IOException.class, () -> parser.parse(document(format, 100_001)));
    }

    @ParameterizedTest
    @ValueSource(strings = {"cyclonedx", "xml"})
    void cbomAppliesTheSameCountToAllDeclaredComponents(String format) throws Exception {
        // Non-crypto entries also count. Filtering them out must not bypass admission.
        assertEquals(0, cbomParser.parse(document(format, 100_000)).size());
        assertThrows(IOException.class, () -> cbomParser.parse(document(format, 100_001)));
    }

    @Test
    void acceptsExactlyFiftyMiBAndRejectsOneByteMoreBeforeParsing() throws Exception {
        byte[] atLimit = new byte[(int) BomInputLimits.MAX_BOM_BYTES];
        Arrays.fill(atLimit, (byte) ' ');
        byte[] valid = "{\"components\":[{\"name\":\"a\"}]}".getBytes(StandardCharsets.UTF_8);
        System.arraycopy(valid, 0, atLimit, 0, valid.length);
        assertEquals(1, parser.parse(atLimit).size());
        byte[] tooLarge = Arrays.copyOf(atLimit, atLimit.length + 1);
        assertThrows(IOException.class, () -> parser.parse(tooLarge));
        assertThrows(IOException.class, () -> cbomParser.parse(tooLarge));
    }

    @Test
    void malformedXmlCannotReturnACollectedPrefix() {
        assertThrows(IOException.class, () -> parser.parse(bytes(
                "<bom><components><component><name>a</name></component><component>")));
    }

    @Test
    void deepXmlTextUsesFiniteIterationAndJsonKeepsExistingJacksonDepthBound() throws Exception {
        // Exercise the traversal independently of the JDK parser's depth ceiling.
        // Java 25 rejects XML deeper than 100 elements before traversal begins.
        var document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        Element name = document.createElement("name");
        document.appendChild(name);
        Node parent = name;
        for (int depth = 0; depth < 10_000; depth++) {
            Element child = document.createElement("x");
            parent.appendChild(child);
            parent = child;
        }
        parent.appendChild(document.createTextNode("a"));
        assertTimeoutPreemptively(Duration.ofSeconds(10), () ->
                assertEquals("a", BomInputLimits.xmlText(name)));
        String xml = "<bom><components><component><name>" + "<x>".repeat(64)
                + "a" + "</x>".repeat(64) + "</name></component></components></bom>";
        assertTimeoutPreemptively(Duration.ofSeconds(10), () ->
                assertEquals("a", parser.parse(bytes(xml)).get(0).packageName()));
        String json = "{\"components\":[],\"extra\":" + "[".repeat(2_000)
                + "0" + "]".repeat(2_000) + "}";
        assertTimeoutPreemptively(Duration.ofSeconds(5), () ->
                assertThrows(IOException.class, () -> parser.parse(bytes(json))));
    }

    private byte[] document(String format, int count) {
        String component = "xml".equals(format)
                ? "<component><name>a</name></component>" : "{\"name\":\"a\"}";
        String entries = component.repeat(count);
        if ("xml".equals(format)) {
            return bytes("<bom xmlns=\"http://cyclonedx.org/schema/bom/1.6\"><components>"
                    + entries + "</components></bom>");
        }
        entries = (component + ",").repeat(count - 1) + component;
        String body = "spdx".equals(format) || "wrapped-spdx".equals(format)
                ? "{\"spdxVersion\":\"SPDX-2.3\",\"packages\":[" + entries + "]}"
                : "{\"bomFormat\":\"CycloneDX\",\"components\":[" + entries + "]}";
        return bytes("wrapped-spdx".equals(format) ? "{\"sbom\":" + body + "}" : body);
    }

    private byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
