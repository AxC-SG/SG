package com.prototype.vulnwatch.service.patch;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;

/**
 * Resolves Microsoft KB articles to CVEs from the Microsoft CSAF data the platform already
 * ingests (the KB appears in the CSAF remediation statement stored on vulnerability targets).
 *
 * <p>Reads shared, read-only platform reference data; it never reads or writes tenant data.
 */
@Component
public class KbCveResolver {

    private final JdbcTemplate jdbc;

    public KbCveResolver(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    /** A per-sync memo, so each KB is looked up once per run. */
    public Lookup newLookup() {
        return new Lookup();
    }

    public final class Lookup {
        private final Map<String, List<String>> cache = new HashMap<>();

        public List<String> cvesFor(String kbArticle) {
            if (kbArticle == null || !kbArticle.matches("\\d{6,8}")) {
                return List.of();
            }
            return cache.computeIfAbsent(kbArticle, kb -> jdbc.queryForList("""
                    select distinct v.external_id
                      from platform.vulnerability_targets t
                      join platform.vulnerabilities v on v.id = t.vulnerability_id
                     where t.qualifiers_json is not null
                       and t.qualifiers_json like '%actionStatement%'
                       and (t.qualifiers_json::jsonb ->> 'actionStatement') ~ ('(^|[^0-9])(KB)?' || ? || '([^0-9]|$)')
                       and v.external_id like 'CVE-%'
                     limit 500
                    """, String.class, kb));
        }
    }
}
