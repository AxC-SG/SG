package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.service.TenantContext;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * The only writer of {@code ownership_subject} and {@code ownership_subject_edge} (plan §7.2). Topology writes take a
 * tenant-scoped advisory lock and reject cycles and chains longer than {@link #MAX_HOPS}, so the read view's cycle and
 * depth guards are defence in depth rather than the normal path.
 */
@Service
public class OwnershipSubjectService {

    public record Subject(UUID id, String subjectType, String sourceObjectId, String contextKey, int generation, String lifecycleStatus) { }

    public static final int MAX_HOPS = 6;
    static final Set<String> TYPES = Set.of("APPLICATION", "HOST", "CONTAINER_IMAGE", "CLOUD_ACCOUNT", "CLOUD_RESOURCE",
            "COMPONENT_OCCURRENCE", "AI_SYSTEM", "AI_ARTIFACT");
    private static final String LOCK_SCOPE = "ownership.topology";

    private final JdbcTemplate jdbc;
    private final OwnershipEvents events;
    private final OwnershipEffectiveCacheService cache;

    public OwnershipSubjectService(JdbcTemplate jdbc, OwnershipEvents events, OwnershipEffectiveCacheService cache) {
        this.jdbc = jdbc;
        this.events = events;
        this.cache = cache;
    }

    /** Returns the live subject for this contextual identity, creating generation 1 when none exists. */
    @Transactional
    public Subject register(String subjectType, String sourceObjectId, String contextKey) {
        if (!TYPES.contains(subjectType)) throw bad("Unknown subject type");
        if (sourceObjectId == null || sourceObjectId.isBlank()) throw bad("A source object id is required");
        String context = contextKey == null ? "" : contextKey;
        UUID candidate = UUID.randomUUID();
        int inserted = jdbc.update("""
                INSERT INTO ownership_subject (id, subject_type, source_object_id, context_key, generation)
                VALUES (?, ?, ?, ?, COALESCE((SELECT max(generation) + 1 FROM ownership_subject
                                               WHERE subject_type = ? AND source_object_id = ? AND context_key = ?), 1))
                ON CONFLICT (tenant_id, subject_type, source_object_id, context_key) WHERE lifecycle_status = 'ACTIVE' DO NOTHING
                """, candidate, subjectType, sourceObjectId, context, subjectType, sourceObjectId, context);
        if (inserted == 1) cache.enqueue(candidate, "SUBJECT_REGISTERED");
        return jdbc.query("""
                SELECT id, subject_type, source_object_id, context_key, generation, lifecycle_status FROM ownership_subject
                 WHERE subject_type = ? AND source_object_id = ? AND context_key = ? AND lifecycle_status = 'ACTIVE'
                """, (rs, row) -> new Subject(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4),
                rs.getInt(5), rs.getString(6)), subjectType, sourceObjectId, context).get(0);
    }

    /**
     * Registers subjects for up to {@code limit} assets that have none yet (populate step, plan §15.2). Set-based
     * and idempotent; the asset type is the subject type and the asset ID is the source object ID.
     */
    @Transactional
    public int registerUnlinkedAssets(int limit) {
        List<UUID> created = jdbc.queryForList("""
                INSERT INTO ownership_subject (id, subject_type, source_object_id)
                SELECT gen_random_uuid(), a.type, a.id::text FROM assets a
                 WHERE a.ownership_subject_id IS NULL AND a.type IN ('APPLICATION','HOST','CONTAINER_IMAGE','CLOUD_RESOURCE')
                 ORDER BY a.id LIMIT ?
                ON CONFLICT (tenant_id, subject_type, source_object_id, context_key) WHERE lifecycle_status = 'ACTIVE' DO NOTHING
                RETURNING id
                """, UUID.class, limit);
        cache.enqueueAll(created, "SUBJECT_REGISTERED");
        return created.size();
    }

    /** The live subject for a contextual identity, without creating one. */
    @Transactional(readOnly = true)
    public Optional<Subject> find(String subjectType, String sourceObjectId, String contextKey) {
        return jdbc.query("""
                SELECT id, subject_type, source_object_id, context_key, generation, lifecycle_status FROM ownership_subject
                 WHERE subject_type = ? AND source_object_id = ? AND context_key = ? AND lifecycle_status = 'ACTIVE'
                """, (rs, row) -> new Subject(rs.getObject(1, UUID.class), rs.getString(2), rs.getString(3), rs.getString(4),
                rs.getInt(5), rs.getString(6)), subjectType, sourceObjectId, contextKey == null ? "" : contextKey).stream().findFirst();
    }

    /** Sets the single OWNERSHIP_PARENT of {@code childId}. Setting the current parent again is a no-op. */
    @Transactional
    public void setParent(UUID childId, UUID parentId, String actor) {
        lock();
        requireActive(childId);
        requireActive(parentId);
        if (childId.equals(parentId)) throw bad("A subject cannot be its own ownership parent");
        Optional<UUID> current = currentParent(childId);
        if (current.isPresent() && current.get().equals(parentId)) return;
        List<UUID> ancestors = ancestors(parentId);
        if (ancestors.contains(childId)) throw bad("This parent would create an ownership cycle");
        int above = ancestors.size() - 1;          // hops from the new parent to its root
        int below = descendantDepth(childId);      // hops from the child to its deepest descendant
        if (below + 1 + above > MAX_HOPS) throw bad("Ownership chains are limited to " + MAX_HOPS + " parent hops");
        retireEdge(childId);
        UUID edgeId = UUID.randomUUID();
        jdbc.update("INSERT INTO ownership_subject_edge (id, child_subject_id, parent_subject_id, created_by) VALUES (?, ?, ?, ?)",
                edgeId, childId, parentId, actor);
        cache.enqueue(childId, "TOPOLOGY_CHANGED");
        events.record("TOPOLOGY_CHANGED", childId, null, null, actor, "edgeId", edgeId, "fromParentId", current.orElse(null),
                "toParentId", parentId);
    }

    @Transactional
    public void clearParent(UUID childId, String actor) {
        lock();
        Optional<UUID> current = currentParent(childId);
        if (current.isEmpty()) return;
        retireEdge(childId);
        cache.enqueue(childId, "TOPOLOGY_CHANGED");
        events.record("TOPOLOGY_CHANGED", childId, null, null, actor, "fromParentId", current.get(), "toParentId", null);
    }

    @Transactional(readOnly = true)
    public Optional<UUID> currentParent(UUID childId) {
        return jdbc.queryForList("""
                SELECT parent_subject_id FROM ownership_subject_edge
                 WHERE child_subject_id = ? AND edge_type = 'OWNERSHIP_PARENT' AND status = 'ACTIVE'
                """, UUID.class, childId).stream().findFirst();
    }

    /** {@code start} followed by its ancestors, nearest first, bounded one past the hop limit. */
    private List<UUID> ancestors(UUID start) {
        return jdbc.queryForList("""
                WITH RECURSIVE up AS (
                    SELECT ?::uuid AS id, 0 AS depth
                    UNION ALL
                    SELECT e.parent_subject_id, up.depth + 1 FROM up
                      JOIN ownership_subject_edge e ON e.child_subject_id = up.id AND e.edge_type = 'OWNERSHIP_PARENT' AND e.status = 'ACTIVE'
                     WHERE up.depth <= ?
                ) SELECT id FROM up ORDER BY depth
                """, UUID.class, start, MAX_HOPS);
    }

    private int descendantDepth(UUID start) {
        Integer depth = jdbc.queryForObject("""
                WITH RECURSIVE down AS (
                    SELECT ?::uuid AS id, 0 AS depth
                    UNION ALL
                    SELECT e.child_subject_id, down.depth + 1 FROM down
                      JOIN ownership_subject_edge e ON e.parent_subject_id = down.id AND e.edge_type = 'OWNERSHIP_PARENT' AND e.status = 'ACTIVE'
                     WHERE down.depth <= ?
                ) SELECT max(depth) FROM down
                """, Integer.class, start, MAX_HOPS);
        return depth == null ? 0 : depth;
    }

    private void retireEdge(UUID childId) {
        jdbc.update("""
                UPDATE ownership_subject_edge SET status = 'RETIRED', retired_at = now()
                 WHERE child_subject_id = ? AND edge_type = 'OWNERSHIP_PARENT' AND status = 'ACTIVE'
                """, childId);
    }

    private void requireActive(UUID subjectId) {
        List<String> status = jdbc.queryForList("SELECT lifecycle_status FROM ownership_subject WHERE id = ?", String.class, subjectId);
        if (status.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Ownership subject not found");
        if (!"ACTIVE".equals(status.get(0))) throw bad("Ownership subject is retired");
    }

    private void lock() {
        UUID tenantId = TenantContext.getCurrentTenantId();
        if (tenantId == null) throw new IllegalStateException("Ownership topology writes require a tenant context");
        jdbc.query("SELECT pg_advisory_xact_lock(hashtextextended(?, 0))", rs -> null, tenantId + "|" + LOCK_SCOPE);
    }

    private static ResponseStatusException bad(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
