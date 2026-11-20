package com.prototype.vulnwatch.service;

import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.TransactionDefinition;

/** Source-evidence projection only; never writes legacy catalog artifacts. */
@Service
@ConditionalOnProperty(name="app.intelligence.isolated-catalog.enabled",havingValue="true")
public class CandidateProjectionBuilder {
 private final JdbcTemplate jdbc;
 private final IsolatedCatalogVersionService versions;
 private final TransactionTemplate tx;
 public CandidateProjectionBuilder(JdbcTemplate jdbc,IsolatedCatalogVersionService versions,PlatformTransactionManager manager){
  this.jdbc=jdbc;this.versions=versions;tx=new TransactionTemplate(manager);
  tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
 }
 public UUID start(UUID candidate) {
  return tx.execute(s->{
   var c=jdbc.queryForMap("select status from platform.intelligence_candidates where id=? for share",candidate);
   if(!Set.of("READY","PUBLICATION_QUEUED","PUBLISHED").contains(c.get("status"))) throw new IllegalStateException("Candidate is not immutable and ready");
   jdbc.queryForMap("select * from platform.catalog_projection_active where singleton for update");
   var existing=jdbc.queryForList("select id from platform.catalog_projection_versions where candidate_id=?",UUID.class,candidate);
   if(!existing.isEmpty()) return existing.get(0);
   UUID id=UUID.randomUUID();
   jdbc.update("""
    insert into platform.catalog_projection_versions(id,candidate_id,base_version,expected_count)
    select ?,?,a.version_id,(select count(*) from (
     select canonical_id from platform.intelligence_candidate_records where candidate_id=? and validation='VALID' and kind='OBSERVATION' and canonical_id is not null
     union select canonical_id from platform.catalog_projection_records where version_id=a.version_id) ids)
    from platform.catalog_projection_active a where singleton
    """,id,candidate,candidate);
   return id;
  });
 }
 /** One bounded durable batch per invocation; callers repeat until READY. */
 public Map<String,Object> step(UUID id) {
  long token=versions.claim(id);
  var v=status(id);long cursor=((Number)v.get("cursor_id")).longValue();
  UUID after=jdbc.query("select canonical_id from platform.catalog_projection_records where version_id=? and ordinal=?",rs->rs.next()?(UUID)rs.getObject(1):null,id,cursor);
  var ids=jdbc.queryForList("""
   select canonical_id from (
    select canonical_id from platform.intelligence_candidate_records where candidate_id=? and validation='VALID' and kind='OBSERVATION' and canonical_id is not null
    union select canonical_id from platform.catalog_projection_records where version_id=?) x
   where (cast(? as uuid) is null or canonical_id>cast(? as uuid)) order by canonical_id limit 100
   """,UUID.class,v.get("candidate_id"),v.get("base_version"),after,after);
  List<IsolatedCatalogVersionService.Row> rows=new ArrayList<>();
  for(UUID canonical:ids){
   String payload=jdbc.queryForObject("""
    select jsonb_build_object('canonical_id',cast(? as text),'projection_kind','SOURCE_EVIDENCE',
     'evidence',coalesce(jsonb_agg(payload order by source_system),'[]'::jsonb))::text from (
      select distinct on(source_system) source_system,payload from (
       select e->>'source_system' source_system,e payload,0 priority,0::bigint ordering
       from platform.catalog_projection_records p cross join lateral jsonb_array_elements(p.payload->'evidence') e
       where p.version_id=? and p.canonical_id=?
       union all
       select source_system,jsonb_build_object('source_system',source_system,'payload',payload),1,id
       from platform.intelligence_candidate_records where candidate_id=? and canonical_id=? and kind='OBSERVATION' and validation='VALID'
      ) combined order by source_system,priority desc,ordering desc
     ) latest
    """,String.class,canonical.toString(),v.get("base_version"),canonical,v.get("candidate_id"),canonical);
   rows.add(new IsolatedCatalogVersionService.Row(++cursor,canonical,payload));
  }
  versions.append(id,token,((Number)v.get("cursor_id")).longValue(),rows);
  if(ids.size()<100) versions.ready(id,token);
  return status(id);
 }
 public Map<String,Object> status(UUID id){
  var result=new LinkedHashMap<>(jdbc.queryForMap("select * from platform.catalog_projection_versions where id=?",id));
  result.put("scope","CANONICAL_SOURCE_EVIDENCE_ONLY");result.put("legacyCatalogRouting",false);return result;
 }
 public List<Map<String,Object>> browse(UUID id,long after,int limit){
  if(after<0||limit<1||limit>1000)throw new IllegalArgumentException("Invalid page");
  return jdbc.queryForList("select * from platform.catalog_projection_records where version_id=? and ordinal>? order by ordinal limit ?",id,after,limit);
 }
}
