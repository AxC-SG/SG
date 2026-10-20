package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.prototype.vulnwatch.domain.BomComponent;
import com.prototype.vulnwatch.domain.BomComponentRelationship;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.repo.BomComponentRelationshipRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.ArrayDeque;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * Records the dependency and composition edges a BOM declares between its own components.
 *
 * <p>Edges are stored as the document expressed them and are not interpreted. A CycloneDX
 * dependsOn edge states that one component depends on another. It does not state that a model
 * was trained on a dataset, nor that a dataset is served at inference time. Deriving training
 * or serving usage from a generic edge would manufacture provenance the document never
 * asserted, and that fabricated provenance would then feed policy decisions about the AI
 * system. So only DEPENDS_ON and COMPOSED_OF are recorded, and semantic AI relationships are
 * left to evidence that actually states them.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class BomRelationshipParsingService {

    private static final String DEPENDS_ON = "DEPENDS_ON";
    private static final String COMPOSED_OF = "COMPOSED_OF";
    /** Guards against a pathological document declaring an enormous edge set. */
    private static final int MAX_EDGES = 50_000;

    private final BomComponentRelationshipRepository relationshipRepository;

    public int recordRelationships(
            BomIngestionRecord record, JsonNode root, List<BomComponent> components) {
        if (record == null || record.getId() == null || root == null || root.isMissingNode()) {
            return 0;
        }
        UUID tenantId = record.getTenant() == null ? null : record.getTenant().getId();
        if (tenantId == null) {
            return 0;
        }

        Map<String, UUID> componentIdByRef = new LinkedHashMap<>();
        if (components != null) {
            for (BomComponent component : components) {
                if (component.getBomRef() != null && !component.getBomRef().isBlank()
                        && component.getId() != null) {
                    componentIdByRef.putIfAbsent(component.getBomRef().trim(), component.getId());
                }
            }
        }

        // Re-ingesting the same document version must not accumulate duplicate edges.
        relationshipRepository.deleteByBomId(record.getId());

        Set<String> seen = new LinkedHashSet<>();
        List<BomComponentRelationship> edges = new ArrayList<>();
        collectDependencies(root, record, tenantId, componentIdByRef, seen, edges);
        collectCompositions(root.path("components"), record, tenantId, componentIdByRef, seen, edges);

        if (edges.isEmpty()) {
            return 0;
        }
        relationshipRepository.saveAll(edges);
        return edges.size();
    }

    private void collectDependencies(
            JsonNode root, BomIngestionRecord record, UUID tenantId,
            Map<String, UUID> componentIdByRef, Set<String> seen,
            List<BomComponentRelationship> edges) {
        JsonNode dependencies = root.path("dependencies");
        if (!dependencies.isArray()) {
            return;
        }
        for (JsonNode entry : dependencies) {
            String sourceRef = text(entry.path("ref"));
            if (sourceRef == null) {
                continue;
            }
            for (JsonNode target : entry.path("dependsOn")) {
                String targetRef = text(target);
                if (targetRef != null) {
                    add(edges, seen, record, tenantId, componentIdByRef, sourceRef, targetRef, DEPENDS_ON);
                }
            }
        }
    }

    /** CycloneDX expresses composition by nesting components inside a parent component. */
    private void collectCompositions(
            JsonNode components, BomIngestionRecord record, UUID tenantId,
            Map<String, UUID> componentIdByRef, Set<String> seen,
            List<BomComponentRelationship> edges) {
        if (!components.isArray()) {
            return;
        }
        // Use explicit iterators rather than Java recursion. Serialized JSON keeps the
        // mapper's existing nesting constraints; traversal itself cannot overflow the stack.
        ArrayDeque<Iterator<JsonNode>> pending = new ArrayDeque<>();
        pending.push(components.elements());
        while (!pending.isEmpty() && edges.size() < MAX_EDGES) {
            Iterator<JsonNode> siblings = pending.peek();
            if (!siblings.hasNext()) {
                pending.pop();
                continue;
            }
            JsonNode component = siblings.next();
            String parentRef = text(component.path("bom-ref"));
            JsonNode nested = component.path("components");
            if (!nested.isArray()) {
                continue;
            }
            for (JsonNode child : nested) {
                String childRef = text(child.path("bom-ref"));
                if (parentRef != null && childRef != null) {
                    add(edges, seen, record, tenantId, componentIdByRef, parentRef, childRef, COMPOSED_OF);
                }
                if (edges.size() >= MAX_EDGES) {
                    return;
                }
            }
            pending.push(nested.elements());
        }
    }

    private void add(
            List<BomComponentRelationship> edges, Set<String> seen, BomIngestionRecord record,
            UUID tenantId, Map<String, UUID> componentIdByRef,
            String sourceRef, String targetRef, String type) {
        if (edges.size() >= MAX_EDGES) {
            return;
        }
        if (sourceRef.equals(targetRef)) {
            // A self-edge carries no information and would survive the unique constraint.
            return;
        }
        if (!seen.add(type + " " + sourceRef + " " + targetRef)) {
            return;
        }
        BomComponentRelationship edge = new BomComponentRelationship();
        edge.setTenantId(tenantId);
        edge.setBomId(record.getId());
        edge.setSourceRef(sourceRef);
        edge.setTargetRef(targetRef);
        // Null when the document references a ref it never defines. The edge is still kept:
        // discarding it would silently lose structure the customer declared.
        edge.setSourceComponentId(componentIdByRef.get(sourceRef));
        edge.setTargetComponentId(componentIdByRef.get(targetRef));
        edge.setRelationshipType(type);
        edges.add(edge);
    }

    private static String text(JsonNode node) {
        if (node == null || node.isMissingNode() || node.isNull()) {
            return null;
        }
        String value = node.asText(null);
        return value == null || value.isBlank() ? null : value.trim();
    }
}
