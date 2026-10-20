package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verifyNoInteractions;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomComponentRepository;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

/** Exercises the categorized extraction that previously silently truncated at 100,000. */
@ExtendWith(MockitoExtension.class)
class BomCategorizedBoundsTest {
    @Spy private ObjectMapper objectMapper = new ObjectMapper();
    @Spy private SbomParserService parser = new SbomParserService(objectMapper);
    @Spy private BomComponentCategorizationService categorization = new BomComponentCategorizationService();
    @Mock private BomComponentRepository components;
    @InjectMocks private BomIngestionOrchestrator orchestrator;

    @ParameterizedTest
    @ValueSource(strings = {"cyclonedx", "spdx", "xml"})
    void exactCeilingIsCompleteAndOneMoreIsRejectedWithoutWrites(String format) throws Exception {
        assertEquals(100_000, extract(format, 100_000).size());
        InvocationTargetException failure = assertThrows(InvocationTargetException.class,
                () -> extract(format, 100_001));
        org.junit.jupiter.api.Assertions.assertInstanceOf(IOException.class, failure.getCause());
        verifyNoInteractions(components);
    }

    private List<?> extract(String format, int count) throws Exception {
        if ("xml".equals(format)) {
            String xml = "<bom><components>" + "<component><name>a</name></component>".repeat(count)
                    + "</components></bom>";
            var method = BomIngestionOrchestrator.class.getDeclaredMethod("extractAndCategorizeXmlComponents",
                    byte[].class, Tenant.class, BomType.class, String.class);
            method.setAccessible(true);
            return (List<?>) method.invoke(orchestrator, xml.getBytes(StandardCharsets.UTF_8),
                    new Tenant(), BomType.SBOM, null);
        }
        var root = objectMapper.createObjectNode();
        var array = root.putArray("spdx".equals(format) ? "packages" : "components");
        for (int i = 0; i < count; i++) {
            array.addObject().put("name", "a");
        }
        var method = BomIngestionOrchestrator.class.getDeclaredMethod("extractAndCategorizeComponents",
                JsonNode.class, Tenant.class, BomType.class, String.class);
        method.setAccessible(true);
        return (List<?>) method.invoke(orchestrator, root, new Tenant(), BomType.SBOM, null);
    }
}
