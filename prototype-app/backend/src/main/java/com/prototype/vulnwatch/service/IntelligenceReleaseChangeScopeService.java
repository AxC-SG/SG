package com.prototype.vulnwatch.service;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Read-only journal diagnostic. Unresolved rows prohibit selective routing. */
@Service
public class IntelligenceReleaseChangeScopeService {
    public record Change(long id, String tableSchema, String tableName, UUID rowId,
                         List<UUID> directVulnerabilityIds, List<String> directProductKeys,
                         boolean unresolved) {}
    public record Page(UUID releaseId, List<Change> changes, Long nextAfterId,
                       boolean complete, boolean routingReady) {}

    private final JdbcTemplate jdbc;
    public IntelligenceReleaseChangeScopeService(JdbcTemplate jdbc) { this.jdbc=jdbc; }

    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional(readOnly=true, isolation=Isolation.REPEATABLE_READ, timeout=15)
    public Page inspect(UUID releaseId, Long afterId) {
        if (releaseId==null || (afterId!=null && afterId<0))
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Release and non-negative cursor are required");
        boolean published=Boolean.TRUE.equals(jdbc.queryForObject(
                "select exists(select 1 from platform.intelligence_releases where id=? and status='PUBLISHED')",
                Boolean.class,releaseId));
        if (!published) throw new ResponseStatusException(HttpStatus.NOT_FOUND,"Published release not found");
        var rows=jdbc.query("""
                select id,table_schema,table_name,row_id,
                       previous_value->>'vulnerability_id' previous_vulnerability_id,
                       new_value->>'vulnerability_id' new_vulnerability_id,
                       previous_value->>'canonical_id' previous_canonical_id,
                       new_value->>'canonical_id' new_canonical_id,
                       previous_value->>'normalized_target_key' previous_target_key,
                       new_value->>'normalized_target_key' new_target_key,
                       previous_value->>'normalized_product_key' previous_product_key,
                       new_value->>'normalized_product_key' new_product_key
                from platform.intelligence_release_changes
                where release_id=? and id>? order by id limit 101
                """,(rs,n)->{
            String schema=rs.getString("table_schema");
            String table=rs.getString("table_name");
            UUID rowId=rs.getObject("row_id",UUID.class);
            var ids=new LinkedHashSet<UUID>();
            if ("platform".equals(schema) && ("vulnerabilities".equals(table)
                    || "intelligence_canonical_redirects".equals(table))) ids.add(rowId);
            boolean malformed=!addId(ids,rs.getString("previous_vulnerability_id"));
            malformed|=!addId(ids,rs.getString("new_vulnerability_id"));
            if ("platform".equals(schema) && ("intelligence_canonical_redirects".equals(table)
                    || "intelligence_identifiers".equals(table))) {
                malformed|=!addId(ids,rs.getString("previous_canonical_id"));
                malformed|=!addId(ids,rs.getString("new_canonical_id"));
            }
            var productKeys=new LinkedHashSet<String>();
            if ("platform".equals(schema) && "vulnerability_targets".equals(table)) {
                addKey(productKeys,rs.getString("previous_target_key"));
                addKey(productKeys,rs.getString("new_target_key"));
            } else if ("platform".equals(schema) && "vex_assertions".equals(table)) {
                addKey(productKeys,rs.getString("previous_product_key"));
                addKey(productKeys,rs.getString("new_product_key"));
            }
            return new Change(rs.getLong("id"),schema,table,rowId,List.copyOf(ids),
                    List.copyOf(productKeys),ids.isEmpty() || malformed);
        },releaseId,afterId==null?0L:afterId);
        boolean complete=rows.size()<=100;
        var page=new ArrayList<>(rows.subList(0,Math.min(100,rows.size())));
        // Even directly mapped rows do not capture product keys or prove that other
        // journal rows are complete. No selective fanout consumes this endpoint.
        return new Page(releaseId,List.copyOf(page),complete || page.isEmpty()?null:page.get(page.size()-1).id(),complete,false);
    }

    private static boolean addId(LinkedHashSet<UUID> ids,String value) {
        if(value==null) return true;
        if(value.isBlank()) return false;
        try {
            ids.add(UUID.fromString(value));
            return true;
        } catch (IllegalArgumentException invalid) {
            return false;
        }
    }

    private static void addKey(LinkedHashSet<String> keys,String value) {
        if(value!=null && !value.isBlank()) keys.add(value);
    }
}
