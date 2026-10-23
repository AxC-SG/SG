package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

/** Locks release and tenant input revisions for each bounded evaluation transaction. */
@Service
public class IntelligenceEvaluationFence {
    private record Revision(UUID release,long revision) { }
    private final ThreadLocal<Revision> current=new ThreadLocal<>();
    private final JdbcTemplate jdbc;
    public IntelligenceEvaluationFence(JdbcTemplate jdbc) { this.jdbc=jdbc; }
    public Scope open(UUID tenant) {
        var release=jdbc.queryForMap("select release_id,generation from platform.intelligence_active_state where singleton=true for share");
        var row=jdbc.queryForMap("select required_revision from platform.tenant_intelligence_processing where tenant_id=? for update",tenant);
        Revision previous=current.get();
        current.set(new Revision((UUID)release.get("release_id"),((Number)row.get("required_revision")).longValue()));
        String include=jdbc.queryForObject("select current_setting('app.include_ineligible_intelligence',true)",String.class);
        jdbc.queryForObject("select set_config('app.include_ineligible_intelligence','true',true)",String.class);
        return () -> {
            current.set(previous);
            jdbc.queryForObject("select set_config('app.include_ineligible_intelligence',?,true)",String.class,include==null ? "" : include);
        };
    }
    public void stamp(Finding finding) {
        Revision revision=current.get();
        if(revision==null) throw new IllegalStateException("Finding evaluation has no revision fence");
        finding.setIntelligenceReleaseId(revision.release());finding.setIntelligenceRevision(revision.revision());
    }
    public UUID canonical(UUID id) {
        java.util.Set<UUID> seen=new java.util.HashSet<>();
        while(seen.add(id)) {
            var next=jdbc.queryForList("select canonical_id from platform.intelligence_canonical_redirects where id=?",UUID.class,id);
            if(next.isEmpty()) return id;id=next.get(0);
        }
        throw new IllegalStateException("Canonical redirect cycle");
    }
    public boolean hasApprovedApplicability(UUID vulnerability) {
        return Boolean.TRUE.equals(jdbc.queryForObject("select exists(select 1 from platform.vulnerability_targets where vulnerability_id=?)",Boolean.class,vulnerability));
    }
    public interface Scope extends AutoCloseable { @Override void close(); }
}
