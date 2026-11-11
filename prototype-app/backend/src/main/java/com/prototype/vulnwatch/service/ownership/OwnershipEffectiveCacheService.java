package com.prototype.vulnwatch.service.ownership;

import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * The only writer of {@code ownership_effective_cache} and {@code ownership_cache_invalidation} (plan §7.5, design §7).
 *
 * <p>The cache holds each subject's effective result as stable IDs plus the inheritance path the walk visited. Writers
 * of assignments and topology only {@link #enqueue enqueue} the subject they changed; {@link #expandBatch} turns a
 * queued subject into invalidations of exactly the rows whose path contains it, and {@link #refreshBatch} recomputes
 * invalidated rows from the live {@code ownership_effective_for} walk. Both run in bounded batches from the maintenance
 * job, so a parent change never rewrites descendants in one transaction.
 *
 * <p>Only list filters and coverage counts read the cache, and only when {@link #enabled()}; they may show a row's
 * previous result until it refreshes. Detail reads, impact previews, ticket routing and owner snapshots always use
 * the live view. Team names are never cached, so a rename touches nothing here.
 */
@Service
public class OwnershipEffectiveCacheService {

    public record Backlog(long queuedSubjects, long invalidatedRows, long missingRows) {
        public long total() {
            return queuedSubjects + invalidatedRows + missingRows;
        }
    }

    private static final String COMPUTED_COLUMNS = """
            e.ownership_status, CASE WHEN e.ownership_status = 'OWNED' THEN e.owner_team_id END, e.ownership_origin_subject_id,
            e.ownership_assignment_id, a.version, e.inheritance_path, e.inheritance_depth""";

    private final JdbcTemplate jdbc;
    private final boolean enabled;

    public OwnershipEffectiveCacheService(JdbcTemplate jdbc,
                                          @Value("${app.ownership.effective-cache.enabled:false}") boolean enabled) {
        this.jdbc = jdbc;
        this.enabled = enabled;
    }

    /** True when list filters and coverage read the cache and the maintenance job keeps it current. */
    public boolean enabled() {
        return enabled;
    }

    /**
     * Records that {@code subjectId}'s effective result, or that of anything inheriting through it, may have changed.
     * Always recorded (one keyed upsert), so enabling the cache later starts from a complete backlog.
     */
    @Transactional
    public void enqueue(UUID subjectId, String reason) {
        enqueueAll(List.of(subjectId), reason);
    }

    @Transactional
    public void enqueueAll(Collection<UUID> subjectIds, String reason) {
        if (subjectIds.isEmpty()) return;
        jdbc.update("""
                INSERT INTO ownership_cache_invalidation (tenant_id, subject_id, reason)
                SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, id, ? FROM unnest(?::uuid[]) AS id
                ON CONFLICT (tenant_id, subject_id) DO UPDATE SET reason = EXCLUDED.reason, enqueued_at = clock_timestamp()
                """, reason, array(subjectIds));
    }

    /**
     * Expands queued subjects, oldest first, spending at most {@code limit} units of work (one per row created or
     * marked, and at least one per subject). For each subject: create its own row if it has none, then mark the rows
     * whose path contains it and that were last refreshed before it was queued. A subject leaves the queue once
     * nothing is left to mark, unless it was re-queued meanwhile. A return value below {@code limit} means the queue
     * was drained.
     */
    @Transactional
    public int expandBatch(int limit) {
        int work = 0;
        List<UUID> visited = new java.util.ArrayList<>();
        while (work < limit) {
            List<Map.Entry<UUID, OffsetDateTime>> head = jdbc.query("""
                    SELECT subject_id, enqueued_at FROM ownership_cache_invalidation WHERE subject_id <> ALL (?::uuid[])
                     ORDER BY enqueued_at, subject_id LIMIT 1 FOR UPDATE SKIP LOCKED
                    """, (rs, row) -> Map.entry(rs.getObject(1, UUID.class), rs.getObject(2, OffsetDateTime.class)), array(visited));
            if (head.isEmpty()) break;
            UUID root = head.get(0).getKey();
            OffsetDateTime queuedAt = head.get(0).getValue();
            visited.add(root);
            int budget = limit - work;
            int created = insertMissing(List.of(root));
            int marked = jdbc.update("""
                    UPDATE ownership_effective_cache c SET invalidated_at = clock_timestamp()
                     WHERE c.subject_id IN (SELECT subject_id FROM ownership_effective_cache
                                             WHERE inheritance_path @> ARRAY[?::uuid] AND invalidated_at IS NULL AND refreshed_at < ?
                                             LIMIT ?)
                       AND c.role = 'TECHNICAL_OWNER'
                    """, root, queuedAt, budget);
            if (marked < budget) {
                jdbc.update("DELETE FROM ownership_cache_invalidation WHERE subject_id = ? AND enqueued_at = ?", root, queuedAt);
            }
            work += Math.max(1, created + marked);
        }
        return work;
    }

    /** Recomputes up to {@code limit} invalidated rows, oldest first, from the live effective walk. */
    @Transactional
    public int refreshBatch(int limit) {
        return jdbc.update("""
                WITH pick AS (
                    SELECT subject_id FROM ownership_effective_cache WHERE invalidated_at IS NOT NULL AND role = 'TECHNICAL_OWNER'
                     ORDER BY invalidated_at, subject_id LIMIT ? FOR UPDATE SKIP LOCKED
                ), computed AS (
                    SELECT p.subject_id, """ + COMPUTED_COLUMNS + """

                      FROM pick p CROSS JOIN LATERAL ownership_effective_for(p.subject_id) e
                      LEFT JOIN ownership_assignment a ON a.id = e.ownership_assignment_id
                )
                UPDATE ownership_effective_cache c
                   SET ownership_status = x.ownership_status, owner_team_id = x.owner_team_id,
                       origin_subject_id = x.ownership_origin_subject_id, assignment_id = x.ownership_assignment_id,
                       origin_assignment_version = x.version, inheritance_path = x.inheritance_path,
                       inheritance_depth = x.inheritance_depth, refreshed_at = clock_timestamp(), invalidated_at = NULL
                  FROM computed x (subject_id, ownership_status, owner_team_id, ownership_origin_subject_id, ownership_assignment_id,
                                   version, inheritance_path, inheritance_depth)
                 WHERE c.subject_id = x.subject_id AND c.role = 'TECHNICAL_OWNER'
                """, limit);
    }

    /**
     * Reconciliation (plan §12.4): queues up to {@code limit} active subjects that have no cache row, e.g. subjects
     * created before the cache was enabled. Returns how many were queued.
     */
    @Transactional
    public int reconcileMissing(int limit) {
        return jdbc.update("""
                INSERT INTO ownership_cache_invalidation (tenant_id, subject_id, reason)
                SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, s.id, 'REBUILD' FROM ownership_subject s
                 WHERE s.lifecycle_status = 'ACTIVE'
                   AND NOT EXISTS (SELECT 1 FROM ownership_effective_cache c WHERE c.subject_id = s.id AND c.role = 'TECHNICAL_OWNER')
                   AND NOT EXISTS (SELECT 1 FROM ownership_cache_invalidation q WHERE q.subject_id = s.id)
                 LIMIT ?
                ON CONFLICT (tenant_id, subject_id) DO NOTHING
                """, limit);
    }

    /** Outstanding work; zero means every active subject's cached result reflects all recorded changes. */
    @Transactional(readOnly = true)
    public Backlog backlog() {
        Map<String, Object> row = jdbc.queryForMap("""
                SELECT (SELECT count(*) FROM ownership_cache_invalidation) AS queued,
                       (SELECT count(*) FROM ownership_effective_cache WHERE invalidated_at IS NOT NULL) AS invalidated,
                       (SELECT count(*) FROM ownership_subject s WHERE s.lifecycle_status = 'ACTIVE'
                           AND NOT EXISTS (SELECT 1 FROM ownership_effective_cache c
                                            WHERE c.subject_id = s.id AND c.role = 'TECHNICAL_OWNER')) AS missing
                """);
        return new Backlog(num(row.get("queued")), num(row.get("invalidated")), num(row.get("missing")));
    }

    private int insertMissing(List<UUID> subjectIds) {
        return jdbc.update("""
                INSERT INTO ownership_effective_cache (tenant_id, subject_id, ownership_status, owner_team_id, origin_subject_id, assignment_id,
                    origin_assignment_version, inheritance_path, inheritance_depth, refreshed_at)
                SELECT NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, s.id, """ + COMPUTED_COLUMNS + """
                , clock_timestamp()
                  FROM ownership_subject s CROSS JOIN LATERAL ownership_effective_for(s.id) e
                  LEFT JOIN ownership_assignment a ON a.id = e.ownership_assignment_id
                 WHERE s.id = ANY (?::uuid[])
                ON CONFLICT (tenant_id, subject_id, role) DO NOTHING
                """, array(subjectIds));
    }

    private static String array(Collection<UUID> ids) {
        return "{" + ids.stream().map(UUID::toString).collect(Collectors.joining(",")) + "}";
    }

    private static long num(Object value) {
        return value == null ? 0 : ((Number) value).longValue();
    }
}
