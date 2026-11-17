package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.dto.CatalogPolicy;
import com.prototype.vulnwatch.dto.CatalogPolicyPreview.Request;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/** Durable shadow membership only. No active pointer or finding mutation is exposed. */
@Service
public class CatalogBuildService {
    public static class BatchFailure extends RuntimeException {
        private final UUID buildId;
        private final Instant checkpoint;
        BatchFailure(UUID buildId, Instant checkpoint, RuntimeException cause) {
            super("Catalog batch failed",cause); this.buildId=buildId; this.checkpoint=checkpoint;
        }
        public UUID buildId() { return buildId; }
        public Instant checkpoint() { return checkpoint; }
    }
    public record Build(UUID id, long policyVersion, long generation, String status, long scanned, long matched,
                        String lastError, Instant createdAt, Instant updatedAt) {}
    public record Member(UUID vulnerabilityId, String externalId, String reason, boolean withdrawn) {}
    public record FindingComparison(UUID buildId, long selectedRecords, long existingFindingRows,
                                    long unlinkedFindingRows,
                                    long findingRowsOutsideSelection, long distinctRecordsOutsideSelection,
                                    long openOutsideSelection, long suppressedOutsideSelection,
                                    long resolvedOutsideSelection, long autoClosedOutsideSelection) {}
    public record InputStatus(UUID buildId, boolean current, String reason,
                              long policyVersion, long latestPolicyVersion, boolean latestPolicy) {}
    public record OrgCveComparison(UUID buildId, long selectedRecords, long existingOrgCveRecords,
                                   long overlappingRecords, long orgCveRecordsOutsideSelection,
                                   long selectedWithoutOrgCveRecord) {}
    public enum DifferenceDirection { ORG_OUTSIDE_SELECTION, SELECTED_WITHOUT_ORG }
    public record Difference(UUID vulnerabilityId, String externalId) {}
    public record DifferencePage(DifferenceDirection direction, List<Difference> records,
                                 UUID nextAfterId, boolean complete) {}
    private final WorkspaceService workspace;
    private final NamedParameterJdbcTemplate jdbc;
    private final CatalogPolicyPreviewService preview;
    private final ObjectMapper mapper;
    private final AuditEventService audit;
    public CatalogBuildService(WorkspaceService workspace, NamedParameterJdbcTemplate jdbc,
            CatalogPolicyPreviewService preview, ObjectMapper mapper, AuditEventService audit) {
        this.workspace=workspace; this.jdbc=jdbc; this.preview=preview; this.mapper=mapper; this.audit=audit;
    }

    // Read committed refreshes visibility after waiting for the creation lock, so duplicate requests
    // see the winning insert. The worker independently verifies all recorded inputs in repeatable read.
    @Transactional(isolation=Isolation.READ_COMMITTED, timeout=15)
    public Build create(UUID id, long policyVersion) {
        UUID tenant = tenant();
        if (id == null || policyVersion < 1) throw error(HttpStatus.BAD_REQUEST,"Request ID and saved policy version are required");
        jdbc.getJdbcTemplate().query("select pg_advisory_xact_lock(hashtext(?))", rs -> null, "catalog-build:"+tenant);
        var existing = jdbc.query("select * from intelligence_catalog_builds where tenant_id=:tenant and id=:id",
                Map.of("tenant",tenant,"id",id), this::mapBuild);
        if (!existing.isEmpty()) {
            if (existing.get(0).policyVersion()!=policyVersion) throw error(HttpStatus.CONFLICT,"Request ID already belongs to another policy");
            return existing.get(0);
        }
        if (Boolean.TRUE.equals(jdbc.queryForObject("select exists(select 1 from intelligence_catalog_builds where tenant_id=:tenant and status in ('QUEUED','BUILDING'))",
                Map.of("tenant",tenant), Boolean.class))) throw error(HttpStatus.CONFLICT,"A catalog build is already in progress");
        var state = preview.snapshot(policy(tenant,policyVersion));
        jdbc.update("""
                insert into intelligence_catalog_builds(tenant_id,id,policy_version,generation,override_state,source_state,status)
                values(:tenant,:id,:version,:generation,:overrides,:sources,'QUEUED')
                """, new MapSqlParameterSource("tenant",tenant).addValue("id",id).addValue("version",policyVersion)
                    .addValue("generation",state.generation()).addValue("overrides",state.overrideState()).addValue("sources",state.sourceState()));
        jdbc.update("""
                insert into platform.tenant_catalog_build_queue(tenant_id,build_id,status)
                values(:tenant,:id,'PENDING')
                on conflict(tenant_id) do update set build_id=excluded.build_id,status='PENDING',available_at=now(),updated_at=now()
                """,Map.of("tenant",tenant,"id",id));
        audit.record("tenant.intelligence_catalog_build.requested","catalog_build",id.toString(),"{\"policyVersion\":"+policyVersion+"}");
        return get(id);
    }

    @Transactional(readOnly=true)
    public List<Build> list() {
        return jdbc.query("select * from intelligence_catalog_builds where tenant_id=:tenant order by created_at desc,id limit 50",
                Map.of("tenant",tenant()), this::mapBuild);
    }
    @Transactional(readOnly=true)
    public Build get(UUID id) {
        var rows=jdbc.query("select * from intelligence_catalog_builds where tenant_id=:tenant and id=:id",
                Map.of("tenant",tenant(),"id",id), this::mapBuild);
        if(rows.isEmpty()) throw error(HttpStatus.NOT_FOUND,"Catalog build not found");
        return rows.get(0);
    }
    @Transactional(readOnly=true)
    public List<Member> members(UUID id, UUID after) {
        UUID tenant=tenant(); get(id);
        return jdbc.query("""
                select m.vulnerability_id,v.external_id,m.reason,v.intelligence_withdrawn
                from intelligence_catalog_members m join platform.vulnerabilities v on v.id=m.vulnerability_id
                where m.tenant_id=:tenant and m.build_id=:id and (cast(:after as uuid) is null or m.vulnerability_id>cast(:after as uuid))
                order by m.vulnerability_id limit 100
                """,new MapSqlParameterSource("tenant",tenant).addValue("id",id).addValue("after",after),
                (rs,n)->new Member(rs.getObject(1,UUID.class),rs.getString(2),rs.getString(3),rs.getBoolean(4)));
    }

    /** Review-only input check. It is not activation approval or historical-source certification. */
    @Transactional(readOnly=true, isolation=Isolation.REPEATABLE_READ, timeout=15)
    public InputStatus inputStatus(UUID id) {
        UUID tenant=tenant();
        var rows=jdbc.queryForList("select status,policy_version,generation,override_state,source_state from intelligence_catalog_builds where tenant_id=:tenant and id=:id",
                Map.of("tenant",tenant,"id",id));
        if(rows.isEmpty()) throw error(HttpStatus.NOT_FOUND,"Catalog build not found");
        var row=rows.get(0);
        long policyVersion=((Number)row.get("policy_version")).longValue();
        Long latest=jdbc.queryForObject("select max(version) from intelligence_catalog_policy_versions where tenant_id=:tenant",
                Map.of("tenant",tenant),Long.class);
        long latestVersion=latest==null?policyVersion:latest;
        boolean latestPolicy=policyVersion==latestVersion;
        if(!"READY".equals(row.get("status")))
            return new InputStatus(id,false,"BUILD_NOT_READY",policyVersion,latestVersion,latestPolicy);
        com.prototype.vulnwatch.dto.CatalogPolicyPreview.Snapshot now;
        try {
            now=preview.snapshot(policy(tenant,policyVersion));
        } catch(ResponseStatusException changed) {
            if(changed.getStatusCode().value()!=400 && changed.getStatusCode().value()!=409) throw changed;
            return new InputStatus(id,false,"INPUTS_CHANGED",policyVersion,latestVersion,latestPolicy);
        }
        boolean current=now.generation()==((Number)row.get("generation")).longValue()
                && now.overrideState().equals(row.get("override_state"))
                && now.sourceState().equals(row.get("source_state"));
        return new InputStatus(id,current,current?"INPUTS_MATCH":"INPUTS_CHANGED",
                policyVersion,latestVersion,latestPolicy);
    }

    /** Review-only comparison. Existing findings and their history remain untouched. */
    @Transactional(readOnly=true, isolation=Isolation.REPEATABLE_READ, timeout=15)
    public FindingComparison compareFindings(UUID id) {
        UUID tenant=tenant();
        var rows=jdbc.queryForList("select * from intelligence_catalog_builds where tenant_id=:tenant and id=:id",
                Map.of("tenant",tenant,"id",id));
        if(rows.isEmpty()) throw error(HttpStatus.NOT_FOUND,"Catalog build not found");
        var row=rows.get(0);
        if(!"READY".equals(row.get("status"))) throw error(HttpStatus.CONFLICT,"Only completed builds can be compared");
        var now=preview.snapshot(policy(tenant,((Number)row.get("policy_version")).longValue()));
        if(now.generation()!=((Number)row.get("generation")).longValue()
                || !now.overrideState().equals(row.get("override_state")) || !now.sourceState().equals(row.get("source_state")))
            throw error(HttpStatus.CONFLICT,"Build inputs changed; start a new review build");
        String old=jdbc.getJdbcTemplate().queryForObject("select current_setting('app.include_ineligible_intelligence',true)",String.class);
        jdbc.getJdbcTemplate().queryForObject("select set_config('app.include_ineligible_intelligence','true',true)",String.class);
        try {
            var counts=jdbc.queryForMap("""
                    select count(*) filter(where f.vulnerability_id is not null) as existing,
                      count(*) filter(where f.vulnerability_id is null) as unlinked,
                      count(*) filter(where f.vulnerability_id is not null and m.vulnerability_id is null) as outside,
                      count(distinct f.vulnerability_id) filter(where m.vulnerability_id is null) as outside_distinct,
                      count(*) filter(where f.vulnerability_id is not null and m.vulnerability_id is null and f.status='OPEN') as outside_open,
                      count(*) filter(where f.vulnerability_id is not null and m.vulnerability_id is null and f.status='SUPPRESSED') as outside_suppressed,
                      count(*) filter(where f.vulnerability_id is not null and m.vulnerability_id is null and f.status='RESOLVED') as outside_resolved,
                      count(*) filter(where f.vulnerability_id is not null and m.vulnerability_id is null and f.status='AUTO_CLOSED') as outside_auto_closed
                    from findings f left join intelligence_catalog_members m
                      on m.tenant_id=f.tenant_id and m.build_id=:id and m.vulnerability_id=f.vulnerability_id
                    where f.tenant_id=:tenant
                    """,Map.of("tenant",tenant,"id",id));
            return new FindingComparison(id,((Number)row.get("matched")).longValue(),
                    ((Number)counts.get("existing")).longValue(),((Number)counts.get("unlinked")).longValue(),
                    ((Number)counts.get("outside")).longValue(),
                    ((Number)counts.get("outside_distinct")).longValue(),
                    ((Number)counts.get("outside_open")).longValue(),((Number)counts.get("outside_suppressed")).longValue(),
                    ((Number)counts.get("outside_resolved")).longValue(),((Number)counts.get("outside_auto_closed")).longValue());
        } finally {
            jdbc.getJdbcTemplate().queryForObject("select set_config('app.include_ineligible_intelligence',?,true)",String.class,
                    old==null?"":old);
        }
    }

    /** Observed organization CVE rows are not a complete legacy-eligibility oracle. */
    @Transactional(readOnly=true, isolation=Isolation.REPEATABLE_READ, timeout=15)
    public OrgCveComparison compareOrgCveRecords(UUID id) {
        var status=inputStatus(id);
        if(!status.current()) throw error(HttpStatus.CONFLICT,
                "Only a current completed build can be compared; start a new review build");
        UUID tenant=tenant();
        long selected=get(id).matched();
        var counts=jdbc.queryForMap("""
                select count(*) as existing,
                  count(*) filter(where m.vulnerability_id is not null) as overlap,
                  count(*) filter(where m.vulnerability_id is null) as outside
                from org_cve_records o left join intelligence_catalog_members m
                  on m.tenant_id=o.tenant_id and m.build_id=:id and m.vulnerability_id=o.vulnerability_id
                where o.tenant_id=:tenant
                """,Map.of("tenant",tenant,"id",id));
        long overlap=((Number)counts.get("overlap")).longValue();
        return new OrgCveComparison(id,selected,((Number)counts.get("existing")).longValue(),overlap,
                ((Number)counts.get("outside")).longValue(),Math.max(0,selected-overlap));
    }

    /** Bounded record-level review, not a complete legacy eligibility comparison. */
    @Transactional(readOnly=true, isolation=Isolation.REPEATABLE_READ, timeout=15)
    public DifferencePage orgCveDifferences(UUID id, DifferenceDirection direction, UUID after) {
        if(direction==null) throw error(HttpStatus.BAD_REQUEST,"Difference direction is required");
        if(!inputStatus(id).current()) throw error(HttpStatus.CONFLICT,
                "Only a current completed build can be compared; start a new review build");
        UUID tenant=tenant();
        var params=new MapSqlParameterSource("tenant",tenant).addValue("id",id).addValue("after",after);
        String sql=direction==DifferenceDirection.ORG_OUTSIDE_SELECTION ? """
                select o.vulnerability_id,o.external_id from org_cve_records o
                where o.tenant_id=:tenant and (cast(:after as uuid) is null or o.vulnerability_id>cast(:after as uuid))
                  and not exists (select 1 from intelligence_catalog_members m
                                  where m.tenant_id=o.tenant_id and m.build_id=:id and m.vulnerability_id=o.vulnerability_id)
                order by o.vulnerability_id limit 51
                """ : """
                select m.vulnerability_id,v.external_id from intelligence_catalog_members m
                join platform.vulnerabilities v on v.id=m.vulnerability_id
                where m.tenant_id=:tenant and m.build_id=:id
                  and (cast(:after as uuid) is null or m.vulnerability_id>cast(:after as uuid))
                  and not exists (select 1 from org_cve_records o
                                  where o.tenant_id=m.tenant_id and o.vulnerability_id=m.vulnerability_id)
                order by m.vulnerability_id limit 51
                """;
        var rows=jdbc.query(sql,params,(rs,n)->new Difference(rs.getObject(1,UUID.class),rs.getString(2)));
        var page=rows.stream().limit(50).toList();
        boolean complete=rows.size()<=50;
        return new DifferencePage(direction,page,complete || page.isEmpty()?null:page.get(page.size()-1).vulnerabilityId(),complete);
    }
    @Transactional(timeout=15)
    public Build cancel(UUID id) {
        UUID tenant=tenant();
        var rows=jdbc.query("select * from intelligence_catalog_builds where tenant_id=:tenant and id=:id for update",
                Map.of("tenant",tenant,"id",id),this::mapBuild);
        if(rows.isEmpty()) throw error(HttpStatus.NOT_FOUND,"Catalog build not found");
        if(List.of("QUEUED","BUILDING").contains(rows.get(0).status())) {
            jdbc.update("update intelligence_catalog_builds set status='CANCELLED',updated_at=now() where tenant_id=:tenant and id=:id",Map.of("tenant",tenant,"id",id));
            jdbc.update("update platform.tenant_catalog_build_queue set status='CANCELLED',updated_at=now() where tenant_id=:tenant and build_id=:id",
                    Map.of("tenant",tenant,"id",id));
            audit.record("tenant.intelligence_catalog_build.cancelled","catalog_build",id.toString(),"{}");
        }
        return get(id);
    }

    /** A row lock and batch transaction are the lease: crashes release it and roll back the checkpoint. */
    @Transactional(isolation=Isolation.REPEATABLE_READ, timeout=20)
    public boolean processNext() {
        UUID tenant=tenant();
        var rows=jdbc.queryForList("""
                select * from intelligence_catalog_builds where tenant_id=:tenant and status in ('QUEUED','BUILDING')
                  and (last_error is null or updated_at < now()-interval '30 seconds')
                order by created_at,id for update skip locked limit 1
                """,Map.of("tenant",tenant));
        if(rows.isEmpty()) return false;
        var row=rows.get(0); UUID id=(UUID)row.get("id");
        Map<String,Object> key=Map.of("tenant",tenant,"id",id);
        try {
            var batch=preview.preview(new Request(policy(tenant,((Number)row.get("policy_version")).longValue()),
                    (UUID)row.get("after_id"),((Number)row.get("generation")).longValue(),
                    (String)row.get("override_state"),(String)row.get("source_state")));
            for(var match:batch.matches()) jdbc.update("""
                    insert into intelligence_catalog_members(tenant_id,build_id,vulnerability_id,reason)
                    values(:tenant,:id,:vulnerability,:reason) on conflict do nothing
                    """,new MapSqlParameterSource("tenant",tenant).addValue("id",id).addValue("vulnerability",match.id()).addValue("reason",match.reason()));
            jdbc.update("""
                    update intelligence_catalog_builds set status=:status,after_id=:after,scanned=scanned+:scanned,
                    matched=matched+:matched,last_error=null,attempts=0,updated_at=now() where tenant_id=:tenant and id=:id
                    """,new MapSqlParameterSource("tenant",tenant).addValue("id",id).addValue("status",batch.complete()?"READY":"BUILDING")
                        .addValue("after",batch.nextAfterId()).addValue("scanned",batch.scanned()).addValue("matched",batch.matched()));
            jdbc.update("update platform.tenant_catalog_build_queue set status=:status,available_at=now(),updated_at=now() where tenant_id=:tenant and build_id=:id",
                    new MapSqlParameterSource("tenant",tenant).addValue("id",id).addValue("status",batch.complete()?"READY":"PENDING"));
        } catch(ResponseStatusException stale) {
            // Only validation failures are caught here; database failures must roll the whole batch back.
            if(stale.getStatusCode().value()!=400 && stale.getStatusCode().value()!=409) throw stale;
            jdbc.update("update intelligence_catalog_builds set status='STALE',last_error='INPUTS_CHANGED',updated_at=now() where tenant_id=:tenant and id=:id",key);
            jdbc.update("update platform.tenant_catalog_build_queue set status='STALE',updated_at=now() where tenant_id=:tenant and build_id=:id",key);
        } catch(RuntimeException failure) {
            throw new BatchFailure(id,((java.sql.Timestamp)row.get("updated_at")).toInstant(),failure);
        }
        return true;
    }

    @Transactional(timeout=15)
    public void recordWorkerFailure(UUID id, Instant checkpoint) {
        int changed=jdbc.update("""
                update intelligence_catalog_builds set attempts=attempts+1,last_error='BATCH_RETRY_REQUIRED',
                status=case when attempts>=2 then 'FAILED' else status end,updated_at=now()
                where tenant_id=:tenant and id=:id and updated_at=:checkpoint and status in ('QUEUED','BUILDING')
                """,Map.of("tenant",tenant(),"id",id,"checkpoint",java.sql.Timestamp.from(checkpoint)));
        if(changed==0) return; // A newer checkpoint or cancellation won the race.
        jdbc.update("""
                update platform.tenant_catalog_build_queue q set status=case when b.status='FAILED' then 'FAILED' else 'PENDING' end,
                available_at=case when b.status='FAILED' then now() else now()+interval '30 seconds' end,updated_at=now()
                from intelligence_catalog_builds b
                where q.tenant_id=:tenant and q.build_id=:id and q.status='PENDING'
                  and b.tenant_id=q.tenant_id and b.id=q.build_id
                """,Map.of("tenant",tenant(),"id",id));
    }
    private UUID tenant() {
        UUID id=TenantContext.getCurrentTenantId();
        if(id==null || TenantContext.isPlatformContext()) throw error(HttpStatus.FORBIDDEN,"An active tenant context is required");
        if(!id.equals(workspace.getWorkspace().getId())) throw error(HttpStatus.FORBIDDEN,"Tenant context mismatch");
        return id;
    }
    private CatalogPolicy policy(UUID tenant,long version) {
        var rows=jdbc.queryForList("select policy_json::text from intelligence_catalog_policy_versions where tenant_id=:tenant and version=:version",
                Map.of("tenant",tenant,"version",version),String.class);
        if(rows.isEmpty()) throw error(HttpStatus.NOT_FOUND,"Saved policy version not found");
        try { return mapper.readValue(rows.get(0),CatalogPolicy.class); }
        catch(com.fasterxml.jackson.core.JsonProcessingException failure) { throw new IllegalStateException("Invalid stored catalog policy",failure); }
    }
    private Build mapBuild(ResultSet rs,int row) throws SQLException {
        return new Build(rs.getObject("id",UUID.class),rs.getLong("policy_version"),rs.getLong("generation"),rs.getString("status"),
                rs.getLong("scanned"),rs.getLong("matched"),rs.getString("last_error"),rs.getTimestamp("created_at").toInstant(),rs.getTimestamp("updated_at").toInstant());
    }
    private static ResponseStatusException error(HttpStatus status,String message) { return new ResponseStatusException(status,message); }
}
