package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import java.util.UUID;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;

class PublicationProgressDatabaseTest {
 @Test void telemetryDoesNotBlockOnCandidateAndControlsAreVisible() throws Exception {
  var db=LocalPostgresTestDatabase.provision("progress_controls_isolated");
  var ds=new DriverManagerDataSource(db.url(),db.username(),db.password());
  var jdbc=new JdbcTemplate(ds);
  jdbc.execute("create schema platform");
  jdbc.execute("create table platform.intelligence_candidates(id uuid primary key,status text)");
  jdbc.execute("create table platform.intelligence_publication_outbox(candidate_id uuid,kind text,status text,attempt_count integer,visible_at timestamptz)");
  var script=new org.springframework.jdbc.datasource.init.ResourceDatabasePopulator(new org.springframework.core.io.ClassPathResource("db/migration/postgres_reset/V23__publication_progress.sql"));
  script.execute(ds);
  var manager=new DataSourceTransactionManager(ds);
  var service=new IntelligencePublicationProgressService(jdbc,manager);
  UUID id=UUID.randomUUID();jdbc.update("insert into platform.intelligence_candidates values(?,'PUBLICATION_QUEUED')",id);
  var executor=Executors.newSingleThreadExecutor();
  try {
   new TransactionTemplate(manager).executeWithoutResult(s -> {
    jdbc.queryForMap("select * from platform.intelligence_candidates where id=? for update",id);
    try {executor.submit(() -> service.update(id,"APPLYING_RECORDS",100,1000,100)).get(3,TimeUnit.SECONDS);}
    catch(Exception e){throw new RuntimeException(e);}
   });
   assertEquals(100L,((Number)service.get(id).get("processed")).longValue());
   assertEquals("PAUSED",service.control(id,"PAUSE","owner").get("status"));
   assertThrows(IntelligencePublicationProgressService.ControlInterrupt.class,()->service.update(id,"APPLYING_RECORDS",200,1000,200));
   service.control(id,"RESUME","owner");assertFalse(service.held(id));
   assertEquals("CANCELLED",service.control(id,"CANCEL","owner").get("status"));
  } finally {executor.shutdownNow();}
 }
}
