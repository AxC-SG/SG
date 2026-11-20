package com.prototype.vulnwatch.service;
import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.core.io.ClassPathResource;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
@org.junit.jupiter.api.condition.EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class CandidateProjectionBuilderPostgresIntegrationTest {
 @Test void candidateEvidenceCarriesForwardAndReplacesOnlySameSource() {
  var db=LocalPostgresTestDatabase.provision("candidate_projection_builder");
  var ds=new DriverManagerDataSource(db.url(),db.username(),db.password());var jdbc=new JdbcTemplate(ds);
  jdbc.execute("create schema platform");
  new ResourceDatabasePopulator(new ClassPathResource("db/migration/postgres_reset/V25__isolated_catalog_versions.sql"),new ClassPathResource("db/migration/postgres_reset/V27__projection_candidate_builder.sql")).execute(ds);
  jdbc.execute("create table platform.intelligence_candidates(id uuid primary key,status text)");
  jdbc.execute("create table platform.intelligence_candidate_records(id bigserial primary key,candidate_id uuid,canonical_id uuid,validation text,kind text,source_system text,payload jsonb)");
  var manager=new DataSourceTransactionManager(ds);var versions=new IsolatedCatalogVersionService(jdbc,manager);
  var builder=new CandidateProjectionBuilder(jdbc,versions,manager);UUID canonical=UUID.randomUUID();
  UUID first=UUID.randomUUID();jdbc.update("insert into platform.intelligence_candidates values(?,'READY')",first);
  for(String source:List.of("nvd","kev"))jdbc.update("insert into platform.intelligence_candidate_records(candidate_id,canonical_id,validation,kind,source_system,payload) values(?,?,'VALID','OBSERVATION',?,cast(? as jsonb))",first,canonical,source,"{\"revision\":1}");
  UUID v1=builder.start(first);assertEquals(v1,builder.start(first));assertEquals("READY",builder.step(v1).get("state"));assertTrue(versions.readActive(0,100).isEmpty());versions.activate(v1);
  UUID second=UUID.randomUUID();jdbc.update("insert into platform.intelligence_candidates values(?,'READY')",second);
  jdbc.update("insert into platform.intelligence_candidate_records(candidate_id,canonical_id,validation,kind,source_system,payload) values(?,?,'VALID','OBSERVATION','nvd','{\"revision\":2}')",second,canonical);
  UUID v2=builder.start(second);builder.step(v2);
  assertEquals(v1,versions.readActive(0,100).get(0).get("version_id"));versions.activate(v2);
  String payload=builder.browse(v2,0,100).get(0).get("payload").toString();
  assertTrue(payload.contains("kev"));assertTrue(payload.contains("nvd"));assertTrue(payload.contains("2"));
  assertEquals(2,jdbc.queryForObject("select jsonb_array_length(payload->'evidence') from platform.catalog_projection_records where version_id=?",Integer.class,v2));
 }
}
