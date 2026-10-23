package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import jakarta.persistence.EntityManager;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.Array;
import java.util.*;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/** Immutable review evidence and PostgreSQL-owned, atomic asynchronous publication. */
@Service
public class IntelligencePublicationService {
    private static final Map<String,String> ARTIFACT_TABLES=Map.of(
            "TARGET","platform.vulnerability_targets","RULE","platform.vulnerability_rules","CONFIG","platform.vulnerability_config_expr","OSV","platform.osv_advisories","EQUIVALENCE","platform.advisory_equivalences");
    private static final Set<String> RESTORABLE=Set.of("platform.vulnerabilities","platform.vulnerability_targets","platform.vulnerability_rules",
            "platform.vulnerability_config_expr","platform.vulnerability_intel_observations","platform.vulnerability_intel_summary",
            "platform.vulnerability_intel_summary_sources","platform.vulnerability_intel_relations","platform.vex_assertions",
            "public.github_security_advisories","platform.osv_advisories","platform.advisory_equivalences","platform.intelligence_canonical_redirects","platform.intelligence_identifiers");
    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final ObservationIngestionService observations;
    private final VexAssertionService vex;
    private final EntityManager entities;
    private final BackgroundTaskExecutionPolicy background;
    private final TransactionTemplate transactions;

    public IntelligencePublicationService(JdbcTemplate jdbc,ObjectMapper mapper,ObservationIngestionService observations,
            VexAssertionService vex,EntityManager entities,BackgroundTaskExecutionPolicy background,PlatformTransactionManager manager) {
        this.jdbc=jdbc;this.mapper=mapper;this.observations=observations;this.vex=vex;this.entities=entities;this.background=background;
        transactions=new TransactionTemplate(manager);
        transactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        transactions.setIsolationLevel(TransactionDefinition.ISOLATION_REPEATABLE_READ);
    }

    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional
    public Map<String,Object> createCandidate(List<UUID> runs,String actor) {
        if(runs==null || runs.isEmpty() || runs.size()>200 || runs.stream().anyMatch(Objects::isNull)) throw bad("Select between one and 200 completed feed runs");
        for(UUID run:runs) {
            if(!Boolean.TRUE.equals(jdbc.queryForObject("select exists(select 1 from platform.sync_runs where id=? and run_scope='PLATFORM_VULNERABILITY' and tenant_id is null and lower(status) in ('completed','success') and sync_type not like 'EOL_%')",Boolean.class,run))) throw bad("Select successful completed intelligence runs");
        }
        UUID id=UUID.randomUUID();
        UUID base=activeRelease();
        jdbc.update(connection -> {
            var statement=connection.prepareStatement("insert into platform.intelligence_candidates(id,base_release_id,selected_run_ids,normalization_policy,created_by) values(?,?,?,?,?)");
            statement.setObject(1,id);statement.setObject(2,base);statement.setArray(3,connection.createArrayOf("uuid",runs.toArray()));
            statement.setString(4,IntelligenceStagingService.POLICY_VERSION);statement.setString(5,actor);return statement;
        });
        enqueue("BUILD",id,null,null,null,base,actor);
        audit("CANDIDATE_CREATED",actor,id,null,"{}");
        return candidate(id);
    }

    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional(readOnly=true,isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
    public Map<String,Object> candidate(UUID id) {
        var rows=jdbc.queryForList("select * from platform.intelligence_candidates where id=?",id);
        if(rows.isEmpty()) throw missing();
        return apiRow(rows.get(0));
    }
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional(readOnly=true,isolation=org.springframework.transaction.annotation.Isolation.REPEATABLE_READ)
    public List<Map<String,Object>> records(UUID id,int page,int size) {
        int bounded=Math.max(1,Math.min(200,size));
        return jdbc.queryForList("select id,sync_run_id,kind,external_id,canonical_id,source_system,payload,validation from platform.intelligence_candidate_records where candidate_id=? order by id limit ? offset ?",id,bounded,(long)Math.max(0,page)*bounded).stream().map(this::apiRow).toList();
    }
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional(readOnly=true)
    public List<Map<String,Object>> releases(int page,int size) {
        int bounded=Math.max(1,Math.min(200,size));
        return jdbc.queryForList("select * from platform.intelligence_releases where status='PUBLISHED' order by generation desc limit ? offset ?",bounded,(long)Math.max(0,page)*bounded).stream().map(this::apiRow).toList();
    }
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional
    public Map<String,Object> publish(UUID candidate,String digest,UUID base,String key,String actor) {
        if(key==null || key.isBlank() || key.length()>200 || digest==null || !digest.matches("[a-f0-9]{64}")) throw bad("Reviewed digest and idempotency key are required");
        jdbc.queryForObject("select pg_advisory_xact_lock(hashtextextended(?,72839))",Object.class,key);
        var existing=jdbc.queryForList("select * from platform.intelligence_publication_outbox where idempotency_key=?",key);
        if(!existing.isEmpty()) {
            var job=existing.get(0);
            if(!candidate.equals(job.get("candidate_id")) || !Objects.equals(digest,job.get("expected_digest")) || !Objects.equals(base,job.get("expected_base_release")))
                throw conflict("Idempotency key belongs to a different approval");
            return apiRow(job);
        }
        var row=lockedCandidate(candidate);
        if(!"READY".equals(row.get("status"))) throw conflict("Candidate is not ready for publication");
        if(!Objects.equals(digest,row.get("digest")) || !Objects.equals(base,row.get("base_release_id")) || !Objects.equals(base,activeRelease()))
            throw conflict("Candidate digest or base release changed; rebuild and review the candidate");
        UUID job=enqueue("PUBLISH",candidate,null,key,digest,base,actor);
        jdbc.update("update platform.intelligence_candidates set status='PUBLICATION_QUEUED' where id=?",candidate);
        audit("PUBLICATION_QUEUED",actor,candidate,null,"{}");
        return apiRow(jdbc.queryForMap("select * from platform.intelligence_publication_outbox where id=?",job));
    }
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional
    public Map<String,Object> reject(UUID candidate,String reason,String actor) {
        if(reason==null || reason.isBlank() || reason.length()>2000) throw bad("A rejection reason is required");
        var row=lockedCandidate(candidate);
        if(!Set.of("READY","BUILDING","FAILED").contains(row.get("status"))) throw conflict("Candidate cannot be rejected in its current state");
        jdbc.update("update platform.intelligence_candidates set status='REJECTED',rejection_reason=? where id=?",reason,candidate);
        audit("CANDIDATE_REJECTED",actor,candidate,null,json(Map.of("reason",reason)));
        return candidate(candidate);
    }
    @PreAuthorize("hasRole('PLATFORM_OWNER')")
    @Transactional
    public Map<String,Object> withdraw(UUID release,String key,String actor) {
        if(key==null || key.isBlank() || key.length()>200) throw bad("An idempotency key is required");
        jdbc.queryForObject("select pg_advisory_xact_lock(hashtextextended(?,72839))",Object.class,key);
        var existing=jdbc.queryForList("select * from platform.intelligence_publication_outbox where idempotency_key=?",key);
        if(!existing.isEmpty()) {
            if(!release.equals(existing.get(0).get("release_id")) || !"WITHDRAW".equals(existing.get(0).get("kind"))) throw conflict("Idempotency key belongs to another request");
            return apiRow(existing.get(0));
        }
        if(!release.equals(activeRelease())) throw conflict("Only the active release can be withdrawn");
        UUID id=enqueue("WITHDRAW",null,release,key,null,release,actor);
        return apiRow(jdbc.queryForMap("select * from platform.intelligence_publication_outbox where id=?",id));
    }

    @Scheduled(fixedDelayString="${app.intelligence.publication-poll-ms:3000}")
    public void poll() {
        if(!background.allowsBackgroundTask("intelligence.publication")) return;
        TenantContext.runAsPlatform(() -> {
            // The row lock is the durable ownership fence. A process crash rolls the
            // publication and job acknowledgement back together, leaving PENDING work.
            for(int i=0;i<3;i++) {
                UUID job=transactions.execute(status -> jdbc.query("select id from platform.intelligence_publication_outbox where status='PENDING' and kind<>'FANOUT' and visible_at<=now() order by created_at,id for update skip locked limit 1",(rs,row)->rs.getObject(1,UUID.class)).stream().findFirst().orElse(null));
                if(job==null) break;
                try { transactions.executeWithoutResult(status -> process(job)); }
                catch(RuntimeException failure) {
                    transactions.executeWithoutResult(status -> {
                        boolean terminal=failure instanceof ResponseStatusException;
                        jdbc.update("update platform.intelligence_publication_outbox set attempt_count=attempt_count+1,status=case when ? or attempt_count>=2 then 'FAILED' else 'PENDING' end,visible_at=now()+interval '30 seconds',last_error=? where id=? and status='PENDING'",terminal,safeError(failure),job);
                        jdbc.update("update platform.intelligence_candidates set error_code=?,status=case when (select status from platform.intelligence_publication_outbox where id=?)='FAILED' then 'FAILED' else status end where id=(select candidate_id from platform.intelligence_publication_outbox where id=?)",safeError(failure),job,job);
                    });
                }
            }
        });
    }

    private void process(UUID id) {
        var jobs=jdbc.queryForList("select * from platform.intelligence_publication_outbox where id=? and status='PENDING' for update skip locked",id);
        if(jobs.isEmpty()) return;
        var job=jobs.get(0);
        if("BUILD".equals(job.get("kind"))) build((UUID)job.get("candidate_id"));
        else apply(job);
        jdbc.update("update platform.intelligence_publication_outbox set status='COMPLETED',completed_at=now(),last_error=null where id=?",id);
    }

    private void build(UUID id) {
        var candidate=lockedCandidate(id);
        if(!"BUILDING".equals(candidate.get("status"))) return;
        if(!Objects.equals(candidate.get("base_release_id"),activeRelease())) throw conflict("STALE_BASE_RELEASE");
        UUID[] selected=uuidArray(candidate.get("selected_run_ids"));
        for(UUID run:selected) {
            Boolean valid=jdbc.queryForObject("select exists(select 1 from platform.sync_runs where id=? and lower(status) in ('completed','success') and run_scope='PLATFORM_VULNERABILITY' and tenant_id is null and sync_type not like 'EOL_%')",Boolean.class,run);
            if(!Boolean.TRUE.equals(valid)) throw bad("Candidate selection contains an incomplete, failed, or unsupported run");
        }
        // Continuity is conservative: include all successful unpublished predecessors
        // for selected sources. Absence from any incremental run never deletes data.
        jdbc.update("""
                insert into platform.intelligence_candidate_records(candidate_id,staged_record_id,sync_run_id,kind,external_id,canonical_id,source_system,payload,validation)
                select ?,s.id,s.sync_run_id,s.kind,s.external_id,s.canonical_id,s.source_system,s.payload,case when s.validation='VALID' and exists(
                     select 1 from platform.intelligence_staged_records invalid where invalid.sync_run_id=s.sync_run_id
                      and invalid.canonical_id=s.canonical_id and invalid.kind='OBSERVATION' and invalid.validation<>'VALID')
                     then 'INVALID_CANONICAL_RECORD' else s.validation end
                from platform.intelligence_staged_records s join platform.sync_runs r on r.id=s.sync_run_id
                where lower(r.status) in ('completed','success') and r.run_scope='PLATFORM_VULNERABILITY' and r.tenant_id is null
                  and not exists(select 1 from platform.intelligence_published_runs p where p.sync_run_id=r.id)
                  and exists(select 1 from platform.sync_runs chosen where chosen.id=any(?) and
                    replace(chosen.sync_type,'_FULL','')=replace(r.sync_type,'_FULL','') and r.started_at<=chosen.started_at)
                order by r.started_at,r.id,s.id
                """,id,candidate.get("selected_run_ids"));
        jdbc.update("""
                update platform.intelligence_candidates set expanded_run_ids=coalesce(
                 (select array_agg(r.id order by r.id) from platform.sync_runs r
                  where lower(r.status) in ('completed','success') and r.run_scope='PLATFORM_VULNERABILITY' and r.tenant_id is null
                   and not exists(select 1 from platform.intelligence_published_runs p where p.sync_run_id=r.id)
                   and exists(select 1 from platform.sync_runs chosen where chosen.id=any(?) and
                     replace(chosen.sync_type,'_FULL','')=replace(r.sync_type,'_FULL','') and r.started_at<=chosen.started_at)),'{}') where id=?
                """,candidate.get("selected_run_ids"),id);
        var report=jdbc.queryForMap("""
                select count(*) records,count(distinct canonical_id) canonical_records,
                 count(*) filter(where validation<>'VALID') exclusions,
                 count(*) filter(where kind='TARGET') affected_product_rules,
                 count(*) filter(where kind='OBSERVATION') observations,
                 count(*) filter(where kind='WITHDRAW_SOURCE') withdrawals,
                 count(*) filter(where kind='OBSERVATION')-count(distinct (canonical_id,source_system)) filter(where kind='OBSERVATION') merged_observations
                from platform.intelligence_candidate_records where candidate_id=?
                """,id);
        report=new LinkedHashMap<>(report);
        report.putAll(jdbc.queryForMap("""
                select count(distinct c.canonical_id) filter(where v.id is null or v.intelligence_withdrawn) canonical_additions,
                 count(distinct c.canonical_id) filter(where v.id is not null and not v.intelligence_withdrawn) canonical_changes,
                 count(*) filter(where c.kind='TARGET' and c.payload->>'constraint_type'='NONE') rules_without_version_constraints,
                 count(*) filter(where c.kind='ALIAS' and c.validation='VALID') verified_aliases,
                 count(*) filter(where c.validation='AMBIGUOUS_ALIAS') quarantined_aliases
                from platform.intelligence_candidate_records c left join platform.vulnerabilities v on v.id=c.canonical_id where c.candidate_id=?
                """,id));
        for(var source:jdbc.queryForList("select c.source_system,max(r.completed_at)::text fetched_at from platform.intelligence_candidate_records c join platform.sync_runs r on r.id=c.sync_run_id where c.candidate_id=? and c.kind='OBSERVATION' group by c.source_system",id))
            report.put("source_freshness."+source.get("source_system"),source.get("fetched_at"));
        String digest=digest(id);
        jdbc.update("update platform.intelligence_candidates set digest=?,quality_report=?::jsonb,status='READY',error_code=null where id=?",digest,json(report),id);
    }

    private void apply(Map<String,Object> job) {
        var state=jdbc.queryForMap("select release_id,generation from platform.intelligence_active_state where singleton=true for update");
        UUID base=(UUID)state.get("release_id");
        if(!Objects.equals(base,job.get("expected_base_release"))) throw conflict("STALE_BASE_RELEASE");
        UUID candidate=(UUID)job.get("candidate_id");
        boolean withdrawal="WITHDRAW".equals(job.get("kind"));
        String digest;
        if(!withdrawal) {
            var row=lockedCandidate(candidate);
            digest=digest(candidate);
            if(!"PUBLICATION_QUEUED".equals(row.get("status")) || !Objects.equals(job.get("expected_digest"),digest)
                    || !Objects.equals(row.get("digest"),digest) || !IntelligenceStagingService.POLICY_VERSION.equals(row.get("normalization_policy"))) throw conflict("REVIEWED_CONTENT_CHANGED");
        } else digest=hex(("withdraw:"+base).getBytes(StandardCharsets.UTF_8));
        UUID release=UUID.randomUUID();
        long generation=((Number)state.get("generation")).longValue()+1;
        UUID restores=withdrawal ? jdbc.queryForObject("select predecessor_id from platform.intelligence_releases where id=?",UUID.class,base) : null;
        jdbc.update("insert into platform.intelligence_releases(id,candidate_id,predecessor_id,restores_release_id,generation,digest,actor,kind) values(?,?,?,?,?,?,?,?)",
                release,candidate,base,restores,generation,digest,job.get("actor"),withdrawal ? "WITHDRAWAL" : "PUBLICATION");
        jdbc.queryForObject("select set_config('app.intelligence_release_id',?,true)",String.class,release.toString());
        try(var scope=IntelligenceWriteContext.publication()) {
            if(withdrawal) restore(base);
            else applyRecords(candidate);
            entities.flush();
            entities.clear();
        }
        jdbc.update("update platform.intelligence_releases set status='PUBLISHED' where id=?",release);
        jdbc.update("update platform.intelligence_active_state set release_id=?,generation=? where singleton=true",release,generation);
        if(!withdrawal) {
            jdbc.update("insert into platform.intelligence_published_runs(sync_run_id,release_id) select unnest(expanded_run_ids),? from platform.intelligence_candidates where id=? on conflict do nothing",release,candidate);
            jdbc.update("update platform.intelligence_candidates set status='PUBLISHED',published_release_id=?,error_code=null where id=?",release,candidate);
        }
        enqueue("FANOUT",candidate,release,"fanout:"+release,null,null,(String)job.get("actor"));
        audit(withdrawal ? "RELEASE_WITHDRAWN" : "RELEASE_PUBLISHED",(String)job.get("actor"),candidate,release,"{}");
        jdbc.update("update platform.intelligence_publication_outbox set result_release_id=? where id=?",release,job.get("id"));
    }

    private void applyRecords(UUID candidate) {
        long after=0;
        while(true) {
            var rows=jdbc.queryForList("select * from platform.intelligence_candidate_records where candidate_id=? and id>? and validation='VALID' order by id limit 100",candidate,after);
            if(rows.isEmpty()) break;
            for(var row:rows) {
                after=((Number)row.get("id")).longValue();
                applyRecord(row);
                entities.flush();
                entities.clear();
            }
        }
        UUID afterVulnerability=null;
        while(true) {
            var ids=jdbc.queryForList("select distinct canonical_id from platform.intelligence_candidate_records where candidate_id=? and canonical_id is not null and (?::uuid is null or canonical_id>?::uuid) order by canonical_id limit 100",UUID.class,candidate,afterVulnerability,afterVulnerability);
            if(ids.isEmpty()) break;
            vex.refreshAssertionsForVulnerabilityIdsDetailed(ids);
            afterVulnerability=ids.get(ids.size()-1);entities.flush();entities.clear();
        }
        if(Boolean.TRUE.equals(jdbc.queryForObject("select exists(select 1 from platform.intelligence_candidate_records where candidate_id=? and kind='VEX_REBUILD')",Boolean.class,candidate))) {
            afterVulnerability=null;
            while(true) {
                var ids=jdbc.queryForList("select distinct vulnerability_id from platform.vulnerability_targets where (?::uuid is null or vulnerability_id>?::uuid) order by vulnerability_id limit 100",UUID.class,afterVulnerability,afterVulnerability);
                if(ids.isEmpty()) break;
                vex.refreshAssertionsForVulnerabilityIdsDetailed(ids);afterVulnerability=ids.get(ids.size()-1);entities.flush();entities.clear();
            }
        }
    }

    private void applyRecord(Map<String,Object> row) {
        String kind=(String)row.get("kind");
        UUID canonical=resolveCanonical((UUID)row.get("canonical_id"));
        JsonNode payload=parse(row.get("payload"));
        if(canonical!=null && payload.isObject() && payload.has("vulnerability_id")) ((com.fasterxml.jackson.databind.node.ObjectNode)payload).put("vulnerability_id",canonical.toString());
        if(ARTIFACT_TABLES.containsKey(kind)) { upsert(ARTIFACT_TABLES.get(kind),payload); return; }
        switch(kind) {
            case "OBSERVATION" -> {
                Vulnerability initial=new Vulnerability();initial.setId(canonical);initial.setExternalId((String)row.get("external_id"));
                if(!Objects.equals(canonical,row.get("canonical_id"))) initial.setExternalId(jdbc.queryForObject("select external_id from platform.vulnerabilities where id=?",String.class,canonical));
                initial.setSource(VulnerabilitySource.NVD);initial.setTitle(initial.getExternalId());initial.setSeverity("UNKNOWN");
                insertCanonical(initial);
                jdbc.update("update platform.vulnerabilities set intelligence_withdrawn=false where id=?",canonical);
                ((com.fasterxml.jackson.databind.node.ObjectNode)payload).put("externalId",initial.getExternalId());
                try { observations.upsertObservation(mapper.treeToValue(payload,VulnerabilityIntelligenceService.ObservationUpsertRequest.class)); }
                catch(java.io.IOException failure) { throw new IllegalStateException("Invalid prepared observation",failure); }
            }
            case "REPLACE_TARGETS" -> {
                JsonNode sources=payload.isArray() ? payload : payload.path("sources");
                String sourceRecord=payload.isArray() ? null : payload.path("sourceRecordId").asText(null);
                for(JsonNode source:sources) {
                    jdbc.update("delete from platform.vex_assertions where target_id in (select id from platform.vulnerability_targets where vulnerability_id=? and source=? and (?::text is null or source_record_id=?))",canonical,source.asText(),sourceRecord,sourceRecord);
                    jdbc.update("delete from platform.vulnerability_targets where vulnerability_id=? and source=? and (?::text is null or source_record_id=?)",canonical,source.asText(),sourceRecord,sourceRecord);
                }
            }
            case "REPLACE_RULES" -> jdbc.update("delete from platform.vulnerability_rules where vulnerability_id=?",canonical);
            case "REPLACE_CONFIG" -> jdbc.update("delete from platform.vulnerability_config_expr where vulnerability_id=?",canonical);
            case "METADATA" -> {
                if(!payload.isObject()) throw new IllegalStateException("Invalid metadata row");
                payload.fieldNames().forEachRemaining(column -> {
                    if(!column.matches("[a-z_]+")) throw new IllegalStateException("Invalid prepared column");
                    jdbc.update("update platform.vulnerabilities set "+column+"=(jsonb_populate_record(null::platform.vulnerabilities,?::jsonb))."+column+" where id=?",payload.toString(),canonical);
                });
            }
            case "ALIAS" -> consolidateAlias(canonical,payload.path("identifier").asText());
            case "ALIAS_RELATIONSHIP" -> { /* One advisory may support multiple distinct CVEs. */ }
            case "WITHDRAW_SOURCE" -> withdrawSource(canonical,payload.path("source").asText(),payload.path("sourceRecordId").asText());
            case "VEX_REBUILD" -> { /* Rebuilt once from the fully prepared approved targets below. */ }
            default -> throw new IllegalStateException("Unsupported staged artefact: "+kind);
        }
    }
    private UUID resolveCanonical(UUID id) {
        if(id==null) return null;
        var seen=new HashSet<UUID>();
        while(seen.add(id)) {
            var next=jdbc.queryForList("select canonical_id from platform.intelligence_canonical_redirects where id=?",UUID.class,id);
            if(next.isEmpty()) return id;id=next.get(0);
        }
        throw new IllegalStateException("Canonical redirect cycle");
    }
    private void consolidateAlias(UUID canonical,String identifier) {
        var previous=jdbc.queryForList("select canonical_id from platform.intelligence_identifiers where identifier=?",UUID.class,identifier);
        for(UUID old:previous) {
            old=resolveCanonical(old);
            if(old.equals(canonical)) continue;
            var external=jdbc.queryForList("select external_id from platform.vulnerabilities where id=?",String.class,old);
            if(external.stream().anyMatch(value -> value.startsWith("CVE-"))) throw conflict("AMBIGUOUS_ALIAS");
            jdbc.update("delete from platform.vex_assertions where vulnerability_id=?",old);
            jdbc.update("delete from platform.vulnerability_intel_relations where from_observation_id in (select b.id from platform.vulnerability_intel_observations b join platform.vulnerability_intel_observations a on a.vulnerability_id=? and a.source_system=b.source_system and a.source_record_id=b.source_record_id where b.vulnerability_id=?) or to_observation_id in (select b.id from platform.vulnerability_intel_observations b join platform.vulnerability_intel_observations a on a.vulnerability_id=? and a.source_system=b.source_system and a.source_record_id=b.source_record_id where b.vulnerability_id=?)",canonical,old,canonical,old);
            jdbc.update("delete from platform.vulnerability_intel_observations b using platform.vulnerability_intel_observations a where a.vulnerability_id=? and b.vulnerability_id=? and a.source_system=b.source_system and a.source_record_id=b.source_record_id",canonical,old);
            for(String table:List.of("vulnerability_intel_observations","vulnerability_targets","vulnerability_rules","vulnerability_config_expr"))
                jdbc.update("update platform."+table+" set vulnerability_id=? where vulnerability_id=?",canonical,old);
            jdbc.update("delete from platform.vulnerability_intel_summary_sources where vulnerability_id=?",old);
            jdbc.update("delete from platform.vulnerability_intel_summary where vulnerability_id=?",old);
            jdbc.update("update platform.vulnerabilities set intelligence_withdrawn=true where id=?",old);
            UUID release=jdbc.queryForObject("select current_setting('app.intelligence_release_id')::uuid",UUID.class);
            jdbc.update("insert into platform.intelligence_canonical_redirects(id,canonical_id,release_id) values(?,?,?) on conflict(id) do update set canonical_id=excluded.canonical_id,release_id=excluded.release_id",old,canonical,release);
            jdbc.update("update platform.intelligence_identifiers set canonical_id=? where canonical_id=?",canonical,old);
        }
        jdbc.update("insert into platform.intelligence_identifiers(identifier,canonical_id) values(?,?) on conflict(identifier) do update set canonical_id=excluded.canonical_id",identifier,canonical);
        entities.clear();summaryRefresh(canonical);
    }

    private void withdrawSource(UUID canonical,String source,String sourceRecord) {
        jdbc.update("delete from platform.vex_assertions where observation_id in (select id from platform.vulnerability_intel_observations where vulnerability_id=? and source_system=? and source_record_id=?) or target_id in (select id from platform.vulnerability_targets where vulnerability_id=? and source=? and source_record_id=?)",canonical,source,sourceRecord,canonical,source,sourceRecord);
        jdbc.update("delete from platform.vulnerability_intel_relations where from_observation_id in (select id from platform.vulnerability_intel_observations where vulnerability_id=? and source_system=? and source_record_id=?) or to_observation_id in (select id from platform.vulnerability_intel_observations where vulnerability_id=? and source_system=? and source_record_id=?)",canonical,source,sourceRecord,canonical,source,sourceRecord);
        jdbc.update("delete from platform.vulnerability_intel_observations where vulnerability_id=? and source_system=? and source_record_id=?",canonical,source,sourceRecord);
        jdbc.update("delete from platform.vulnerability_targets where vulnerability_id=? and source=? and source_record_id=?",canonical,source,sourceRecord);
        jdbc.update("delete from platform.vulnerability_intel_summary_sources where vulnerability_id=?",canonical);
        jdbc.update("delete from platform.vulnerability_intel_summary where vulnerability_id=?",canonical);
        entities.clear();
        var remaining=jdbc.queryForObject("select count(*) from platform.vulnerability_intel_observations where vulnerability_id=?",Integer.class,canonical);
        if(remaining==0) jdbc.update("update platform.vulnerabilities set intelligence_withdrawn=true where id=?",canonical);
        else summaryRefresh(canonical);
    }
    @org.springframework.beans.factory.annotation.Autowired
    private VulnerabilityIntelSummaryService summaries;
    private void summaryRefresh(UUID canonical) {
        Vulnerability value=entities.find(Vulnerability.class,canonical);
        if(value!=null) summaries.mergeCanonicalAndRefresh(value);
    }

    private void insertCanonical(Vulnerability vulnerability) {
        String row=json(IntelligenceEntityCodec.row(vulnerability));
        jdbc.update("insert into platform.vulnerabilities select (jsonb_populate_record(null::platform.vulnerabilities,?::jsonb)).* on conflict(id) do nothing",row);
    }
    private void restore(UUID withdrawn) {
        long before=Long.MAX_VALUE;
        while(true) {
            var rows=jdbc.queryForList("select * from platform.intelligence_release_changes where release_id=? and id<? order by id desc limit 100",withdrawn,before);
            if(rows.isEmpty()) break;
            for(var row:rows) {
                before=((Number)row.get("id")).longValue();
                String table=row.get("table_schema")+"."+row.get("table_name");
                if(!RESTORABLE.contains(table)) throw new IllegalStateException("Unrecognized release artefact");
                if("platform.intelligence_identifiers".equals(table)) {
                    if(row.get("previous_value")==null) jdbc.update("delete from platform.intelligence_identifiers where identifier=?",parse(row.get("new_value")).path("identifier").asText());
                    else upsert(table,parse(row.get("previous_value")));
                }
                else if(row.get("previous_value")==null && "platform.vulnerabilities".equals(table))
                    jdbc.update("update platform.vulnerabilities set intelligence_withdrawn=true where id=?",row.get("row_id"));
                else if(row.get("previous_value")==null) jdbc.update("delete from "+table+" where id=?",row.get("row_id"));
                else upsert(table,parse(row.get("previous_value")));
            }
        }
    }
    private void upsert(String table,JsonNode row) {
        if(!RESTORABLE.contains(table)) throw new IllegalStateException("Unrecognized intelligence artefact");
        String key="platform.intelligence_identifiers".equals(table) ? "identifier" : "id";
        var fields=new ArrayList<String>();row.fieldNames().forEachRemaining(column -> {
            if(!column.matches("[a-z_]+")) throw new IllegalStateException("Invalid prepared column");
            if(!key.equals(column)) fields.add("\""+column+"\"=excluded.\""+column+"\"");
        });
        jdbc.update("insert into "+table+" select (jsonb_populate_record(null::"+table+",?::jsonb)).* on conflict("+key+") do update set "+String.join(",",fields),row.toString());
    }

    private String digest(UUID candidate) {
        MessageDigest hash;
        try { hash=MessageDigest.getInstance("SHA-256"); } catch(java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException(failure); }
        hash.update(IntelligenceStagingService.POLICY_VERSION.getBytes(StandardCharsets.UTF_8));
        var header=jdbc.queryForMap("select base_release_id,expanded_run_ids from platform.intelligence_candidates where id=?",candidate);
        hash.update(String.valueOf(header.get("base_release_id")).getBytes(StandardCharsets.UTF_8));
        for(UUID run:uuidArray(header.get("expanded_run_ids"))) hash.update(run.toString().getBytes(StandardCharsets.UTF_8));
        jdbc.query(connection -> {
            var statement=connection.prepareStatement("select sync_run_id,kind,external_id,canonical_id,source_system,payload::text,validation from platform.intelligence_candidate_records where candidate_id=? order by id");
            statement.setObject(1,candidate);statement.setFetchSize(100);return statement;
        },(org.springframework.jdbc.core.RowCallbackHandler) row -> {
            for(int i=1;i<=7;i++) { byte[] value=String.valueOf(row.getObject(i)).getBytes(StandardCharsets.UTF_8);hash.update(java.nio.ByteBuffer.allocate(4).putInt(value.length).array());hash.update(value); }
        });
        return HexFormat.of().formatHex(hash.digest());
    }
    private UUID activeRelease() { return jdbc.queryForObject("select release_id from platform.intelligence_active_state where singleton=true",UUID.class); }
    private Map<String,Object> lockedCandidate(UUID id) {
        var rows=jdbc.queryForList("select * from platform.intelligence_candidates where id=? for update",id);
        if(rows.isEmpty()) throw missing();return rows.get(0);
    }
    private UUID enqueue(String kind,UUID candidate,UUID release,String key,String digest,UUID base,String actor) {
        UUID id=UUID.randomUUID();
        jdbc.update("insert into platform.intelligence_publication_outbox(id,kind,candidate_id,release_id,idempotency_key,expected_digest,expected_base_release,actor) values(?,?,?,?,?,?,?,?)",id,kind,candidate,release,key,digest,base,actor);return id;
    }
    private void audit(String action,String actor,UUID candidate,UUID release,String detail) {
        jdbc.update("insert into platform.intelligence_audit_events(id,action,actor,candidate_id,release_id,detail) values(?,?,?,?,?,?::jsonb)",UUID.randomUUID(),action,actor,candidate,release,detail);
    }
    private Map<String,Object> apiRow(Map<String,Object> row) {
        Map<String,Object> result=new LinkedHashMap<>();row.forEach((key,value) -> {
            if(value instanceof Array array) { try { value=array.getArray(); } catch(java.sql.SQLException failure) { throw new IllegalStateException(failure); } }
            else if(value!=null && value.getClass().getName().equals("org.postgresql.util.PGobject")) value=parse(value);
            result.put(key,value);
        });return result;
    }
    private UUID[] uuidArray(Object value) {
        try { return (UUID[])((Array)value).getArray(); } catch(java.sql.SQLException failure) { throw new IllegalStateException(failure); }
    }
    private JsonNode parse(Object value) {
        try { return mapper.readTree(value.toString()); } catch(java.io.IOException failure) { throw new IllegalStateException("Invalid intelligence evidence",failure); }
    }
    private String json(Object value) {
        try { return mapper.writeValueAsString(value); } catch(java.io.IOException failure) { throw new IllegalStateException("Invalid intelligence evidence",failure); }
    }
    private static String hex(byte[] value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value)); }
        catch(java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException(failure); }
    }
    private static String safeError(RuntimeException failure) { return failure instanceof ResponseStatusException status ? status.getReason() : "PUBLICATION_RETRY_REQUIRED"; }
    private static ResponseStatusException conflict(String message) { return new ResponseStatusException(HttpStatus.CONFLICT,message); }
    private static ResponseStatusException bad(String message) { return new ResponseStatusException(HttpStatus.BAD_REQUEST,message); }
    private static ResponseStatusException missing() { return new ResponseStatusException(HttpStatus.NOT_FOUND,"Intelligence candidate not found"); }
}
