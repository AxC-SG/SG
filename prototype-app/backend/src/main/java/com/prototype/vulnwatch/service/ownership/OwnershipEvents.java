package com.prototype.vulnwatch.service.ownership;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * The only writer of the append-only {@code ownership_event} table. Details must carry stable IDs and
 * action metadata only — never team names, person names, emails or unresolved source values.
 */
@Component
public class OwnershipEvents {

    private static final ObjectMapper JSON = new ObjectMapper();

    private final JdbcTemplate jdbc;

    public OwnershipEvents(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    public void record(String eventType, UUID subjectId, UUID assignmentId, UUID claimId, String actor, Object... detailPairs) {
        Map<String, Object> details = new LinkedHashMap<>();
        for (int i = 0; i < detailPairs.length; i += 2) details.put((String) detailPairs[i], detailPairs[i + 1]);
        jdbc.update("""
                INSERT INTO ownership_event (tenant_id, id, event_type, subject_id, assignment_id, claim_id, actor, details)
                VALUES (NULLIF(current_setting('app.current_tenant_id', true), '')::uuid, ?, ?, ?, ?, ?, ?, ?::jsonb)
                """, UUID.randomUUID(), eventType, subjectId, assignmentId, claimId, actor, json(details));
    }

    static String json(Map<String, ?> map) {
        try {
            return JSON.writeValueAsString(map);
        } catch (JsonProcessingException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
