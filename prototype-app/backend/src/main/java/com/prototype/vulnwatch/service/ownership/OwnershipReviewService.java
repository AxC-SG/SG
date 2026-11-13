package com.prototype.vulnwatch.service.ownership;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * The only writer of {@code ownership_review_item}. Raising an item that is already open for the same
 * dedupe key increments its count instead of creating a duplicate.
 */
@Service
public class OwnershipReviewService {

    public record ReviewItem(UUID id, String itemType, UUID subjectId, String sourceKind, String details, String state,
                             int occurrenceCount, Instant firstSeenAt, Instant lastSeenAt, Instant resolvedAt, String resolvedBy) { }

    static final Set<String> TYPES = Set.of("UNMAPPED_VALUE", "AMBIGUOUS_IDENTITY", "CONFLICT", "INACTIVE_OWNER",
            "INHERITANCE_ERROR", "PRODUCER_ANOMALY");

    private final JdbcTemplate jdbc;

    public OwnershipReviewService(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** Opens or re-counts a review item. {@code details} must hold IDs and codes only, never PII. */
    public UUID raise(String itemType, String dedupeKey, UUID subjectId, String sourceKind, Map<String, ?> details) {
        if (!TYPES.contains(itemType)) throw new IllegalArgumentException("Unknown review item type");
        return jdbc.queryForObject("""
                INSERT INTO ownership_review_item (tenant_id, id, item_type, dedupe_key, subject_id, source_kind, details)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, ?::jsonb)
                ON CONFLICT (tenant_id, dedupe_key) WHERE state = 'OPEN'
                DO UPDATE SET occurrence_count = ownership_review_item.occurrence_count + 1,
                              last_seen_at = now(), details = EXCLUDED.details
                RETURNING id
                """, UUID.class, UUID.randomUUID(), itemType, dedupeKey, subjectId, sourceKind, OwnershipEvents.json(details));
    }

    /**
     * Like {@link #raise} but also stores the unresolved source value as tenant ciphertext with its blind index, so
     * an admin can see what to map. The dedupe key must already be derived from the blind index, never the value.
     */
    public UUID raiseWithValue(String itemType, String dedupeKey, UUID subjectId, String sourceKind, String valueCiphertext,
                               byte[] valueIndex, Map<String, ?> details) {
        if (!TYPES.contains(itemType)) throw new IllegalArgumentException("Unknown review item type");
        return jdbc.queryForObject("""
                INSERT INTO ownership_review_item (tenant_id, id, item_type, dedupe_key, subject_id, source_kind, unresolved_value_enc,
                                                   unresolved_value_index, details)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, ?, ?, ?::jsonb)
                ON CONFLICT (tenant_id, dedupe_key) WHERE state = 'OPEN'
                DO UPDATE SET occurrence_count = ownership_review_item.occurrence_count + 1,
                              last_seen_at = now(), details = EXCLUDED.details
                RETURNING id
                """, UUID.class, UUID.randomUUID(), itemType, dedupeKey, subjectId, sourceKind, valueCiphertext, valueIndex,
                OwnershipEvents.json(details));
    }

    /** Bounded page of review items, newest activity first. Details hold IDs and codes only. */
    @Transactional(readOnly = true)
    public List<ReviewItem> list(String state, String itemType, int limit, int offset) {
        return jdbc.query("""
                SELECT id, item_type, subject_id, source_kind, details::text, state, occurrence_count, first_seen_at, last_seen_at,
                       resolved_at, resolved_by
                  FROM ownership_review_item WHERE state = ? AND (?::text IS NULL OR item_type = ?)
                 ORDER BY last_seen_at DESC, id LIMIT ? OFFSET ?
                """, (rs, row) -> new ReviewItem(rs.getObject(1, UUID.class), rs.getString(2), rs.getObject(3, UUID.class), rs.getString(4),
                rs.getString(5), rs.getString(6), rs.getInt(7), rs.getTimestamp(8).toInstant(), rs.getTimestamp(9).toInstant(),
                rs.getTimestamp(10) == null ? null : rs.getTimestamp(10).toInstant(), rs.getString(11)),
                state == null ? "OPEN" : state, itemType, itemType, Math.max(1, Math.min(limit, 200)), Math.max(0, offset));
    }

    /** Closes an open item as RESOLVED or DISMISSED. A later recurrence opens a fresh item. */
    @Transactional
    public void close(UUID id, String state, String note, String actor) {
        if (!Set.of("RESOLVED", "DISMISSED").contains(state)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Unknown review state");
        int changed = jdbc.update("""
                UPDATE ownership_review_item SET state = ?, resolved_at = now(), resolved_by = ?, resolution_note = ?
                 WHERE id = ? AND state = 'OPEN'
                """, state, actor, note == null || note.isBlank() ? null : note.strip(), id);
        if (changed != 1) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Open review item not found");
    }
}
