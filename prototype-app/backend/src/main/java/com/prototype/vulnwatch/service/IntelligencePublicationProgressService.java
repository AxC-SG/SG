package com.prototype.vulnwatch.service;

import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.http.HttpStatus;

/** Telemetry commits independently; cursors describe observed work, never resumable commits. */
@Service
public class IntelligencePublicationProgressService {
 private final JdbcTemplate jdbc;
 private final TransactionTemplate tx;
 public IntelligencePublicationProgressService(JdbcTemplate jdbc, PlatformTransactionManager manager) {
  this.jdbc=jdbc; tx=new TransactionTemplate(manager);
  tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
 }
 public static class ControlInterrupt extends RuntimeException { }
 /** Durable preparation only. The legacy catalog application still restarts atomically. */
 public void materialize(UUID id) {
  while(true) {
   if(held(id)) throw new ControlInterrupt();
   int copied=tx.execute(s -> {
    jdbc.update("insert into platform.intelligence_candidate_versions(candidate_id) values(?) on conflict do nothing",id);
    var version=jdbc.queryForMap("select * from platform.intelligence_candidate_versions where candidate_id=? for update",id);
    if(Boolean.TRUE.equals(version.get("complete"))) return 0;
    long cursor=((Number)version.get("cursor_id")).longValue();
    int count=jdbc.update("insert into platform.intelligence_candidate_version_records select candidate_id,id,to_jsonb(r) from platform.intelligence_candidate_records r where candidate_id=? and id>? order by id limit 1000 on conflict do nothing",id,cursor);
    jdbc.update("update platform.intelligence_candidate_versions set cursor_id=coalesce((select max(record_id) from platform.intelligence_candidate_version_records where candidate_id=?),0),processed=processed+?,complete=? where candidate_id=?",id,count,count==0,id);
    return count;
   });
   if(copied==0) return;
  }
 }
 public void activationFence(UUID id) {
  jdbc.queryForObject("select pg_advisory_xact_lock(hashtextextended(?,23901))",Object.class,id.toString());
  if(held(id)) throw new ControlInterrupt();
 }
 public void update(UUID id,String phase,long processed,long total,long cursor) {
  if(id==null) return;
  String action=tx.execute(s -> {
   jdbc.update("insert into platform.intelligence_publication_progress(candidate_id) values(?) on conflict do nothing",id);
   var row=jdbc.queryForMap("select * from platform.intelligence_publication_progress where candidate_id=? for update",id);
   jdbc.update("update platform.intelligence_publication_progress set attempt_count=coalesce((select max(attempt_count) from platform.intelligence_publication_outbox where candidate_id=? and kind='PUBLISH'),0) where candidate_id=?",id,id);
   jdbc.update("update platform.intelligence_publication_progress set phase=?,processed=?,total=?,heartbeat_at=clock_timestamp(),started_at=coalesce(started_at,clock_timestamp()),checkpoint=jsonb_build_object('observed_cursor',?,'resumable',false) where candidate_id=?",phase,processed,total,cursor,id);
   if(!phase.equals(row.get("phase"))) event(id,"INFO",phase);
   return (String)row.get("requested_action");
  });
  if(Set.of("PAUSE","CANCEL").contains(action==null?"":action)) throw new ControlInterrupt();
 }
 public void event(UUID id,String level,String message) {
  if(id!=null) tx.executeWithoutResult(s -> jdbc.update("insert into platform.intelligence_publication_events(candidate_id,level,message) values(?,?,?)",id,level,message));
 }
 public boolean held(UUID id) {
  return id!=null && Boolean.TRUE.equals(jdbc.queryForObject("select exists(select 1 from platform.intelligence_publication_progress where candidate_id=? and requested_action in ('PAUSE','CANCEL'))",Boolean.class,id));
 }
 public Map<String,Object> get(UUID id) {
  var candidates=jdbc.queryForList("select status from platform.intelligence_candidates where id=?",id);
  if(candidates.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
  Map<String,Object> result=new LinkedHashMap<>(); result.put("status",candidates.get(0).get("status"));
  result.put("phase","QUEUED"); result.put("processed",0);result.put("total",0);
  result.put("heartbeat_at",null);result.put("started_at",null);result.put("checkpoint",Map.of("resumable",false));result.put("attempt_count",0);
  var rows=jdbc.queryForList("select phase,processed,total,heartbeat_at,started_at,checkpoint,attempt_count,requested_action from platform.intelligence_publication_progress where candidate_id=?",id);
  if(!rows.isEmpty()) result.putAll(rows.get(0));
  Object action=result.get("requested_action");
  if("PAUSE".equals(action)) result.put("status","PAUSED");
  if("CANCEL".equals(action)) result.put("status","CANCELLED");
  var versions=jdbc.queryForList("select cursor_id,processed,complete from platform.intelligence_candidate_versions where candidate_id=?",id);
  if(!versions.isEmpty()) result.put("materialization",versions.get(0));
  if(Set.of("PUBLISHED","FAILED","PAUSED","CANCELLED").contains(result.get("status"))) result.put("phase",result.get("status"));
  result.put("events",jdbc.queryForList("select id,level,message,created_at from platform.intelligence_publication_events where candidate_id=? order by id desc limit 100",id));return result;
 }
 public Map<String,Object> control(UUID id,String action,String actor) {
  if(action==null || !Set.of("PAUSE","RESUME","RETRY","CANCEL").contains(action)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Invalid action");
  get(id);
  tx.executeWithoutResult(s -> {
   jdbc.queryForObject("select pg_advisory_xact_lock(hashtextextended(?,23901))",Object.class,id.toString());
   jdbc.update("insert into platform.intelligence_publication_progress(candidate_id) values(?) on conflict do nothing",id);
   jdbc.queryForMap("select * from platform.intelligence_publication_progress where candidate_id=? for update",id);
   if(Boolean.TRUE.equals(jdbc.queryForObject("select requested_action='CANCEL' from platform.intelligence_publication_progress where candidate_id=?",Boolean.class,id))) throw new ResponseStatusException(HttpStatus.CONFLICT,"Cancelled candidate cannot resume; create a new candidate");
   if(Boolean.TRUE.equals(jdbc.queryForObject("select status='PUBLISHED' from platform.intelligence_candidates where id=?",Boolean.class,id))) throw new ResponseStatusException(HttpStatus.CONFLICT,"Already published");
   if("RETRY".equals(action)) {
    int changed=jdbc.update("update platform.intelligence_publication_outbox set status='PENDING',attempt_count=0,visible_at=now() where candidate_id=? and kind='PUBLISH' and status='FAILED'",id);
    if(changed==0) throw new ResponseStatusException(HttpStatus.CONFLICT,"No failed publication to retry");
    jdbc.update("update platform.intelligence_candidates set status='PUBLICATION_QUEUED',error_code=null where id=? and status='FAILED'",id);
   }
   jdbc.update("update platform.intelligence_publication_progress set requested_action=? where candidate_id=?",Set.of("PAUSE","CANCEL").contains(action)?action:null,id);
   jdbc.update("insert into platform.intelligence_publication_events(candidate_id,level,message) values(?,'WARNING',?)",id,actor+" requested "+action+"; pause/cancel rolls back this attempt; resume restarts it");
  });return get(id);
 }
}
