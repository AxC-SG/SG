package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.BomComponent;
import com.prototype.vulnwatch.domain.BomComponentRelationship;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomComponentRelationshipRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.test.util.ReflectionTestUtils;

class BomRelationshipParsingServiceTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private BomComponentRelationshipRepository relationshipRepository;
    private BomRelationshipParsingService service;
    private BomIngestionRecord record;

    @BeforeEach
    void setUp() {
        relationshipRepository = mock(BomComponentRelationshipRepository.class);
        service = new BomRelationshipParsingService(relationshipRepository);
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        record = new BomIngestionRecord();
        record.setTenant(tenant);
        ReflectionTestUtils.setField(record, "id", UUID.randomUUID());
    }

    private JsonNode json(String raw) throws Exception {
        return objectMapper.readTree(raw);
    }

    private BomComponent component(String bomRef) {
        BomComponent component = new BomComponent();
        component.setBomRef(bomRef);
        ReflectionTestUtils.setField(component, "id", UUID.randomUUID());
        return component;
    }

    @SuppressWarnings("unchecked")
    private List<BomComponentRelationship> saved() {
        ArgumentCaptor<List<BomComponentRelationship>> captor = ArgumentCaptor.forClass(List.class);
        verify(relationshipRepository).saveAll(captor.capture());
        return captor.getValue();
    }

    @Test
    void recordsDependencyEdgesAndResolvesThemToComponents() throws Exception {
        JsonNode root = json("""
                {"dependencies":[{"ref":"app","dependsOn":["lib-a","lib-b"]}]}
                """);
        BomComponent app = component("app");
        BomComponent libA = component("lib-a");

        assertEquals(2, service.recordRelationships(record, root, List.of(app, libA)));

        List<BomComponentRelationship> edges = saved();
        assertTrue(edges.stream().allMatch(e -> "DEPENDS_ON".equals(e.getRelationshipType())));
        BomComponentRelationship toLibA = edges.stream()
                .filter(e -> "lib-a".equals(e.getTargetRef())).findFirst().orElseThrow();
        assertEquals(app.getId(), toLibA.getSourceComponentId());
        assertEquals(libA.getId(), toLibA.getTargetComponentId());
    }

    /**
     * The point of this class. A dependsOn edge between a model and a dataset says the model
     * depends on it -- not that it was trained on it, nor that the dataset is served at
     * inference. Inventing that distinction would hand policy a provenance claim the document
     * never made.
     */
    @Test
    void aModelToDatasetEdgeIsRecordedAsAPlainDependencyNotTraining() throws Exception {
        JsonNode root = json("""
                {"dependencies":[{"ref":"llama-3","dependsOn":["training-corpus"]}]}
                """);

        service.recordRelationships(record, root, List.of());

        List<BomComponentRelationship> edges = saved();
        assertEquals(1, edges.size());
        assertEquals("DEPENDS_ON", edges.get(0).getRelationshipType(),
                "no training or serving semantics may be inferred from a generic edge");
    }

    /**
     * A document may point at a bom-ref it never defines. The edge is still structure the
     * customer declared, so it is kept with an unresolved component id rather than dropped.
     */
    @Test
    void anEdgeToAnUndefinedRefIsKeptUnresolved() throws Exception {
        JsonNode root = json("""
                {"dependencies":[{"ref":"app","dependsOn":["never-declared"]}]}
                """);

        service.recordRelationships(record, root, List.of(component("app")));

        BomComponentRelationship edge = saved().get(0);
        assertEquals("never-declared", edge.getTargetRef());
        assertNull(edge.getTargetComponentId());
    }

    @Test
    void nestedComponentsBecomeCompositionEdgesAtEveryDepth() throws Exception {
        JsonNode root = json("""
                {"components":[{"bom-ref":"outer","components":[
                    {"bom-ref":"middle","components":[{"bom-ref":"inner"}]}]}]}
                """);

        assertEquals(2, service.recordRelationships(record, root, List.of()));
        assertTrue(saved().stream().allMatch(e -> "COMPOSED_OF".equals(e.getRelationshipType())));
    }

    @Test
    void deepCompositionTraversalDoesNotUseTheJavaCallStack() {
        var root = objectMapper.createObjectNode();
        var current = root.putArray("components").addObject().put("bom-ref", "0");
        for (int i = 1; i <= 10_000; i++) {
            current = current.putArray("components").addObject().put("bom-ref", Integer.toString(i));
        }
        assertEquals(10_000, service.recordRelationships(record, root, List.of()));
    }

    @Test
    void duplicateAndSelfEdgesAreDiscarded() throws Exception {
        JsonNode root = json("""
                {"dependencies":[
                    {"ref":"app","dependsOn":["lib","lib"]},
                    {"ref":"app","dependsOn":["app"]}]}
                """);

        assertEquals(1, service.recordRelationships(record, root, List.of()));
    }

    // Re-ingesting one document version must not accumulate edges.
    @Test
    void existingEdgesForTheDocumentAreClearedFirst() throws Exception {
        JsonNode root = json("""
                {"dependencies":[{"ref":"app","dependsOn":["lib"]}]}
                """);

        service.recordRelationships(record, root, List.of());

        verify(relationshipRepository).deleteByBomId(record.getId());
    }

    @Test
    void aDocumentWithNoStructureWritesNothing() throws Exception {
        assertEquals(0, service.recordRelationships(record, json("{}"), List.of()));
        verify(relationshipRepository, never()).saveAll(any());
    }
}
