package com.prototype.vulnwatch.service;

import java.util.*;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Opt-in canonical projection store; does not activate legacy artifacts or tenant data. */
@Service
@ConditionalOnProperty(name="app.intelligence.isolated-catalog.enabled", havingValue="true")
public class IsolatedCatalogVersionService {
 private final JdbcTemplate jdbc;
 private final TransactionTemplate tx;
 public record Row(long ordinal, UUID canonicalId, String payload) {}
 public IsolatedCatalogVersionService(JdbcTemplate jdbc, PlatformTransactionManager manager) {
  this.jdbc=jdbc; tx=new TransactionTemplate(manager);
  tx.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
 }
 public void create(UUID id,long count) {
  if(count<0) throw new IllegalArgumentException("Negative count");
  tx.executeWithoutResult(s -> jdbc.update("insert into platform.catalog_projection_versions(id,expected_count,base_version) select ?,?,version_id from platform.catalog_projection_active where singleton",id,count));
 }
 /** Acquiring ownership invalidates every previously issued worker token. */
 public long claim(UUID id) {
  return tx.execute(s -> {
   var v=lock(id); require(v,"BUILDING");
   return jdbc.queryForObject("update platform.catalog_projection_versions set fence=fence+1 where id=? returning fence",Long.class,id);
  });
 }
 static void validateBatch(long cursor,List<Row> rows) {
  if(rows.size()>1000) throw new IllegalArgumentException("Maximum batch size is 1000");
  Set<UUID> ids=new HashSet<>();
  for(Row row:rows) {
   if(row.ordinal()!=++cursor || row.canonicalId()==null || row.payload()==null || !ids.add(row.canonicalId()))
    throw new IllegalArgumentException("Batch must contain contiguous unique canonical projections");
  }
 }
 /** Rows and checkpoint commit together. Replayed batches must match byte-equivalent JSONB. */
 public long append(UUID id,long token,long expectedCursor,List<Row> rows) {
  validateBatch(expectedCursor,rows);
  return tx.execute(s -> {
   var v=lock(id); require(v,"BUILDING"); fence(v,token);
   long current=((Number)v.get("cursor_id")).longValue();
   long end=expectedCursor+rows.size();
   if(current!=expectedCursor && current<end) throw new IllegalStateException("Checkpoint conflict");
   if(end>((Number)v.get("expected_count")).longValue()) throw new IllegalStateException("Count exceeded");
   for(Row row:rows) {
    if(current==expectedCursor) jdbc.update("insert into platform.catalog_projection_records values(?,?,?,cast(? as jsonb))",id,row.ordinal(),row.canonicalId(),row.payload());
    else if(!Boolean.TRUE.equals(jdbc.queryForObject("select exists(select 1 from platform.catalog_projection_records where version_id=? and ordinal=? and canonical_id=? and payload=cast(? as jsonb))",Boolean.class,id,row.ordinal(),row.canonicalId(),row.payload()))) throw new IllegalStateException("Replay differs");
   }
   if(current==expectedCursor) jdbc.update("update platform.catalog_projection_versions set cursor_id=?,processed=? where id=?",end,end,id);
   return Math.max(current,end);
  });
 }
 public void ready(UUID id,long token) {
  tx.executeWithoutResult(s -> {
   var v=lock(id); require(v,"BUILDING"); fence(v,token);
   if(!v.get("processed").equals(v.get("expected_count"))) throw new IllegalStateException("Incomplete version");
   jdbc.update("update platform.catalog_projection_versions set state='READY',fence=fence+1 where id=?",id);
  });
 }
 public void activate(UUID id) {
  tx.executeWithoutResult(s -> {
   var active=jdbc.queryForMap("select version_id from platform.catalog_projection_active where singleton for update");
   var v=lock(id); require(v,"READY");
   if(!Objects.equals(active.get("version_id"),v.get("base_version"))) throw new IllegalStateException("Stale base version");
   jdbc.update("update platform.catalog_projection_versions set state='RETIRED' where id=?",active.get("version_id"));
   jdbc.update("update platform.catalog_projection_versions set state='ACTIVE' where id=?",id);
   jdbc.update("update platform.catalog_projection_active set version_id=? where singleton",id);
  });
 }
 public void cancel(UUID id) {
  tx.executeWithoutResult(s -> {
   var v=lock(id);
   if(!Set.of("BUILDING","READY").contains(v.get("state"))) throw new IllegalStateException("Cannot cancel active version");
   jdbc.update("update platform.catalog_projection_versions set state='CANCELLED',fence=fence+1 where id=?",id);
  });
 }
 /** One statement pins the active pointer for a consistent snapshot. */
 public List<Map<String,Object>> readActive(long after,int limit) {
  if(limit<1 || limit>1000) throw new IllegalArgumentException("Invalid page size");
  return jdbc.queryForList("select r.* from platform.catalog_projection_records r join platform.catalog_projection_active a on a.version_id=r.version_id where a.singleton and r.ordinal>? order by r.ordinal limit ?",after,limit);
 }
 private Map<String,Object> lock(UUID id) { return jdbc.queryForMap("select * from platform.catalog_projection_versions where id=? for update",id); }
 private static void require(Map<String,Object> v,String state) { if(!state.equals(v.get("state"))) throw new IllegalStateException("Invalid version state"); }
 private static void fence(Map<String,Object> v,long token) { if(((Number)v.get("fence")).longValue()!=token) throw new IllegalStateException("Worker ownership expired"); }
}
