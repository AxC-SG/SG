package com.prototype.vulnwatch.service;
import static org.junit.jupiter.api.Assertions.*;
import java.util.*;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.*;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.core.io.ClassPathResource;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
class IsolatedCatalogVersionPostgresTest {
 @Test void durableResumeFencingReplayAndAtomicActivation() {
  var db=LocalPostgresTestDatabase.provision("isolated_catalog_v25");
  var ds=new DriverManagerDataSource(db.url(),db.username(),db.password());
  var jdbc=new JdbcTemplate(ds);jdbc.execute("create schema platform");
  new ResourceDatabasePopulator(new ClassPathResource("db/migration/postgres_reset/V25__isolated_catalog_versions.sql")).execute(ds);
  var service=new IsolatedCatalogVersionService(jdbc,new DataSourceTransactionManager(ds));
  UUID id=UUID.randomUUID(),canonical=UUID.randomUUID();service.create(id,2);
  long old=service.claim(id),token=service.claim(id);
  var batch=List.of(new IsolatedCatalogVersionService.Row(1,canonical,"{\"name\":\"a\"}"));
  assertThrows(IllegalStateException.class,()->service.append(id,old,0,batch));
  service.append(id,token,0,batch);assertEquals(1,service.append(id,token,0,batch));
  assertNull(jdbc.queryForObject("select version_id from platform.catalog_projection_active",UUID.class));
  assertThrows(IllegalStateException.class,()->service.ready(id,token));
  var restarted=new IsolatedCatalogVersionService(jdbc,new DataSourceTransactionManager(ds));
  long resumed=restarted.claim(id);
  restarted.append(id,resumed,1,List.of(new IsolatedCatalogVersionService.Row(2,UUID.randomUUID(),"{}")));
  restarted.ready(id,resumed);restarted.activate(id);
  assertEquals(id,jdbc.queryForObject("select version_id from platform.catalog_projection_active",UUID.class));
  UUID a=UUID.randomUUID(),b=UUID.randomUUID();service.create(a,0);service.create(b,0);
  service.ready(a,service.claim(a));service.ready(b,service.claim(b));service.activate(a);
  assertThrows(IllegalStateException.class,()->service.activate(b));
  assertEquals(a,jdbc.queryForObject("select version_id from platform.catalog_projection_active",UUID.class));
  assertThrows(IllegalStateException.class,()->service.cancel(a));
 }
}
