package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.CbomRelationship;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CbomGraphResponse;
import com.prototype.vulnwatch.repo.CbomRelationshipRepository;
import java.time.Instant;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CbomGraphService {
    private final CbomRelationshipRepository relationships;
    private org.springframework.jdbc.core.JdbcTemplate jdbc;
    public CbomGraphService(CbomRelationshipRepository relationships){this.relationships=relationships;}
    @org.springframework.beans.factory.annotation.Autowired(required=false)
    public void setJdbcTemplate(org.springframework.jdbc.core.JdbcTemplate value){this.jdbc=value;}

    @Transactional(readOnly = true)
    public CbomGraphResponse traverse(Tenant tenant, String startType, UUID startId, int depth,
                                      String relationshipType, int limit) {
        if (tenant == null || tenant.getId() == null) throw new IllegalArgumentException("Tenant is required");
        if (startType == null || startType.isBlank()) throw new IllegalArgumentException("startType is required");
        if (depth < 1 || depth > 3) throw new IllegalArgumentException("depth must be between 1 and 3");
        if (limit < 1 || limit > 500) throw new IllegalArgumentException("limit must be between 1 and 500");
        String filter = relationshipType == null || relationshipType.isBlank() ? null : relationshipType.trim();
        record Key(String type, UUID id) {}
        LinkedHashMap<Key,Integer> nodes = new LinkedHashMap<>();
        LinkedHashMap<UUID,CbomRelationship> edges = new LinkedHashMap<>();
        Key start = new Key(startType.trim().toUpperCase(), startId);
        nodes.put(start, 0);
        Set<Key> frontier = Set.of(start);
        boolean truncated = false;
        for (int distance = 1; distance <= depth && !frontier.isEmpty(); distance++) {
            List<CbomRelationship> adjacent = relationships.findAdjacent(tenant.getId(),
                    frontier.stream().map(Key::id).toList(), filter);
            Set<Key> next = new LinkedHashSet<>();
            for (CbomRelationship edge : adjacent) {
                Key source = new Key(edge.getSourceType(), edge.getSourceId());
                Key target = new Key(edge.getTargetType(), edge.getTargetId());
                if (!frontier.contains(source) && !frontier.contains(target)) continue;
                Key other = frontier.contains(source) ? target : source;
                if (!nodes.containsKey(other) && nodes.size() >= limit) { truncated = true; continue; }
                edges.putIfAbsent(edge.getId(), edge);
                if (!nodes.containsKey(other)) { nodes.put(other, distance); next.add(other); }
            }
            frontier = next;
        }
        Map<UUID,Object[]> details = describe(tenant.getId(), nodes.keySet().stream().map(Key::id).toList());
        List<CbomGraphResponse.Node> responseNodes = nodes.entrySet().stream().map(v -> {
            Object[] d = details.get(v.getKey().id());
            return d == null ? new CbomGraphResponse.Node(v.getKey().type(), v.getKey().id(), v.getValue())
                    : new CbomGraphResponse.Node(v.getKey().type(), v.getKey().id(), v.getValue(), (String) d[0], (String) d[1], (Integer) d[2], (String) d[3]);
        }).toList();
        Instant now = Instant.now();
        List<CbomGraphResponse.Edge> responseEdges = edges.values().stream().map(v -> new CbomGraphResponse.Edge(
                v.getId(), v.getSourceType(), v.getSourceId(), v.getTargetType(), v.getTargetId(),
                v.getRelationshipType(), v.getEvidenceKind(), v.getConfidence(), v.getEvidenceSummary(),
                v.getValidUntil(), v.getValidUntil() != null && v.getValidUntil().isBefore(now))).toList();
        return new CbomGraphResponse(responseNodes, responseEdges, truncated, depth);
    }

    /** Blast radius: undirected bounded traversal from a component, summarised by affected applications and open findings. */
    @Transactional(readOnly = true)
    public CbomGraphResponse.BlastRadius blastRadius(Tenant tenant, UUID componentId, int depth, int limit) {
        CbomGraphResponse graph = traverse(tenant, "COMPONENT", componentId, depth, null, limit);
        List<CbomGraphResponse.AffectedApplication> applications = new ArrayList<>();
        Map<UUID,Integer> assetDistance = new LinkedHashMap<>();
        graph.nodes().stream().filter(n -> "ASSET".equals(n.type())).forEach(n -> assetDistance.put(n.id(), n.distance()));
        if (jdbc != null && !assetDistance.isEmpty()) {
            jdbc.query("SELECT id, name, environment FROM assets WHERE id = ANY(?)", rs -> {
                UUID id = rs.getObject(1, UUID.class);
                applications.add(new CbomGraphResponse.AffectedApplication(id, rs.getString(2), rs.getString(3), assetDistance.get(id)));
            }, (Object) assetDistance.keySet().toArray(new UUID[0]));
        }
        applications.sort(Comparator.comparingInt(CbomGraphResponse.AffectedApplication::distance).thenComparing(a -> Objects.toString(a.name(), "")));
        Map<String,Integer> bySeverity = new TreeMap<>();
        int open = 0, components = 0;
        for (CbomGraphResponse.Node node : graph.nodes()) {
            if (!"COMPONENT".equals(node.type())) continue;
            components++;
            open += node.openFindings();
        }
        if (jdbc != null) {
            List<UUID> ids = graph.nodes().stream().filter(n -> "COMPONENT".equals(n.type())).map(CbomGraphResponse.Node::id).toList();
            if (!ids.isEmpty()) jdbc.query("""
                    SELECT severity, count(*) FROM cbom_risk_findings WHERE cbom_component_id = ANY(?) AND status = 'OPEN'
                       AND evidence_state <> 'WITHDRAWN' GROUP BY severity
                    """, rs -> { bySeverity.put(rs.getString(1), rs.getInt(2)); }, (Object) ids.toArray(new UUID[0]));
        }
        return new CbomGraphResponse.BlastRadius(componentId, graph, applications, components, open, bySeverity);
    }

    /** id -> {label, kind, openFindings, highestSeverity} for component and asset nodes in this tenant. */
    private Map<UUID,Object[]> describe(UUID tenantId, List<UUID> ids) {
        Map<UUID,Object[]> out = new HashMap<>();
        if (jdbc == null || ids.isEmpty()) return out;
        UUID[] array = ids.toArray(new UUID[0]);
        jdbc.query("""
                SELECT c.id, c.name, c.asset_type,
                       (SELECT count(*) FROM cbom_risk_findings r WHERE r.cbom_component_id = c.id AND r.status = 'OPEN' AND r.evidence_state <> 'WITHDRAWN'),
                       (SELECT r.severity FROM cbom_risk_findings r WHERE r.cbom_component_id = c.id AND r.status = 'OPEN' AND r.evidence_state <> 'WITHDRAWN'
                         ORDER BY CASE r.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 3 ELSE 4 END LIMIT 1)
                  FROM cbom_components c WHERE c.tenant_id = ? AND c.id = ANY(?)
                """, rs -> { out.put(rs.getObject(1, UUID.class), new Object[] {rs.getString(2), rs.getString(3), rs.getInt(4), rs.getString(5)}); }, tenantId, array);
        jdbc.query("SELECT id, name, type FROM assets WHERE tenant_id = ? AND id = ANY(?)",
                rs -> { out.put(rs.getObject(1, UUID.class), new Object[] {rs.getString(2), rs.getString(3), 0, null}); }, tenantId, array);
        return out;
    }
}
