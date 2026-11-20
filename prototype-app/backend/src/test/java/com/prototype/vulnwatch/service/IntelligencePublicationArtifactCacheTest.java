package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.EntityManager;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.PlatformTransactionManager;

class IntelligencePublicationArtifactCacheTest {
    private static final String PAGE="select * from platform.intelligence_candidate_records where candidate_id=? and id>? and validation='VALID' order by id limit 100";
    private static final String REDIRECT="select canonical_id from platform.intelligence_canonical_redirects where id=?";
    private final UUID candidate=UUID.randomUUID(), original=UUID.randomUUID(), canonical=UUID.randomUUID();
    private final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    private final EntityManager entities=mock(EntityManager.class);
    private final IntelligencePublicationService service=new IntelligencePublicationService(jdbc,new ObjectMapper(),
            mock(ObservationIngestionService.class),mock(VexAssertionService.class),entities,
            BackgroundTaskExecutionPolicy.allowAll(),mock(PlatformTransactionManager.class));

    @Test void consecutiveArtifactKindsShareResolutionAndKeepEveryOrderedWriteAndFlush() {
        when(jdbc.queryForList(REDIRECT,UUID.class,original)).thenReturn(List.of(canonical));
        var kinds=List.of("TARGET","RULE","CONFIG","OSV","EQUIVALENCE");
        var rows=new ArrayList<Map<String,Object>>();
        for(int i=0;i<kinds.size();i++) rows.add(row(i+1,kinds.get(i),original));
        page(0,rows);apply();
        verify(jdbc).queryForList(REDIRECT,UUID.class,original);
        verify(jdbc).queryForList(REDIRECT,UUID.class,canonical);
        var order=inOrder(jdbc,entities);
        for(String table:List.of("vulnerability_targets","vulnerability_rules","vulnerability_config_expr","osv_advisories","advisory_equivalences")) {
            order.verify(jdbc).update(startsWith("insert into platform."+table+" "),contains(canonical.toString()));
            order.verify(entities).flush();order.verify(entities).clear();
        }
    }
    @Test void aliasBoundaryInvalidatesEarlierResolution() {
        UUID later=UUID.randomUUID();
        when(jdbc.queryForList(REDIRECT,UUID.class,original)).thenReturn(List.of(canonical),List.of(canonical),List.of(later));
        page(0,List.of(row(1,"TARGET",original),row(2,"ALIAS",original),row(3,"RULE",original)));apply();
        verify(jdbc,times(3)).queryForList(REDIRECT,UUID.class,original);
        verify(jdbc).update(startsWith("insert into platform.vulnerability_targets "),contains(canonical.toString()));
        verify(jdbc).update(startsWith("insert into platform.vulnerability_rules "),contains(later.toString()));
    }
    @Test void cacheDoesNotSurvivePagesOrPublications() {
        page(0,List.of(row(1,"TARGET",original)));page(1,List.of(row(2,"RULE",original)));
        apply();apply();
        verify(jdbc,times(4)).queryForList(REDIRECT,UUID.class,original);
    }
    @Test void cyclesStillFailBeforeWriting() {
        when(jdbc.queryForList(REDIRECT,UUID.class,original)).thenReturn(List.of(canonical));
        when(jdbc.queryForList(REDIRECT,UUID.class,canonical)).thenReturn(List.of(original));
        page(0,List.of(row(1,"TARGET",original)));
        assertThrows(IllegalStateException.class,this::apply);
        verify(jdbc,never()).update(anyString(),any(Object.class));verify(entities,never()).flush();
    }
    @Test void nullCanonicalStillWritesUnchangedPayloadWithoutLookup() {
        page(0,List.of(row(1,"OSV",null)));apply();
        verify(jdbc,never()).queryForList(eq(REDIRECT),eq(UUID.class),any());
        verify(jdbc).update(startsWith("insert into platform.osv_advisories "),contains("\"vulnerability_id\":\"unchanged\""));
    }
    @Test void invalidColumnsStillFailBeforeWriting() {
        var row=row(1,"TARGET",original);row.put("payload","{\"bad-column\":1}");page(0,List.of(row));
        assertThrows(IllegalStateException.class,this::apply);
        verify(jdbc,never()).update(anyString(),any(Object.class));
    }
    private Map<String,Object> row(long id,String kind,UUID canonicalId) {
        Map<String,Object> row=new HashMap<>();row.put("id",id);row.put("kind",kind);row.put("canonical_id",canonicalId);
        row.put("payload","{\"id\":\""+UUID.randomUUID()+"\",\"vulnerability_id\":\"unchanged\",\"identifier\":\"alias\"}");return row;
    }
    private void page(long after,List<Map<String,Object>> rows) { when(jdbc.queryForList(PAGE,candidate,after)).thenReturn(rows); }
    private void apply() { ReflectionTestUtils.invokeMethod(service,"applyRecords",candidate); }
}
