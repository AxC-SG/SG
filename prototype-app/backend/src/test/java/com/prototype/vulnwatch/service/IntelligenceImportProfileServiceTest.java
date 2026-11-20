package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.mockito.ArgumentMatchers.*;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SyncRun;
import com.prototype.vulnwatch.service.vulningestion.VulnerabilitySyncRunService;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.web.server.ResponseStatusException;

class IntelligenceImportProfileServiceTest {
    final JdbcTemplate jdbc=mock(JdbcTemplate.class);
    final VulnerabilitySyncRunService runs=mock(VulnerabilitySyncRunService.class);
    final ObjectMapper mapper=new ObjectMapper();
    final IntelligenceImportProfileService service=new IntelligenceImportProfileService(jdbc,mapper,runs);
    IntelligenceImportProfileService.Profile profile(UUID id) {
        return new IntelligenceImportProfileService.Profile(id,"Year scope",Set.of("NVD"),2025,2025,7d,10d,Set.of("HIGH","CRITICAL"),true);
    }
    @Test void savePersistsNewImmutableRevisionWithCamelCaseSnapshot() throws Exception {
        UUID old=UUID.randomUUID();
        var saved=service.save(profile(old));
        assertNotEquals(old,saved.id());
        var json=ArgumentCaptor.forClass(String.class);
        verify(jdbc).update(eq("insert into platform.intelligence_import_profiles(id,name,profile) values(?,?,?::jsonb)"),eq(saved.id()),eq(saved.name()),json.capture());
        var tree=mapper.readTree(json.getValue());
        assertEquals(2025,tree.path("publicationYearFrom").asInt());
        assertEquals(saved.id().toString(),tree.path("id").asText());
        assertTrue(tree.path("includeUnknownScores").asBoolean());
    }
    @Test void runCarriesImmutableProfileScopeAndManualPublicationMetadata() {
        UUID id=UUID.randomUUID(); var p=profile(id);
        when(jdbc.query(anyString(),org.mockito.ArgumentMatchers.<RowMapper<IntelligenceImportProfileService.Profile>>any(),eq(id))).thenReturn(List.of(p));
        when(runs.prepareQueuedRun(eq("NVD_FULL"),eq(List.of("NVD","NVD_FULL")),anyMap()))
                .thenReturn(new VulnerabilitySyncRunService.TriggerDecision(new SyncRun(),true));
        service.run(id);
        ArgumentCaptor<Map<String,Object>> metadata=ArgumentCaptor.forClass(Map.class);
        verify(runs).prepareQueuedRun(eq("NVD_FULL"),eq(List.of("NVD","NVD_FULL")),metadata.capture());
        assertEquals(p,metadata.getValue().get("importProfile"));
        assertEquals("profile:"+id,metadata.getValue().get("importScopeKey"));
        assertEquals("MANUAL",metadata.getValue().get("publicationMode"));
    }
    @Test void activeRunIsConflictRatherThanFalseProfileSuccess() {
        UUID id=UUID.randomUUID();
        when(jdbc.query(anyString(),org.mockito.ArgumentMatchers.<RowMapper<IntelligenceImportProfileService.Profile>>any(),eq(id))).thenReturn(List.of(profile(id)));
        when(runs.prepareQueuedRun(anyString(),anyList(),anyMap())).thenReturn(new VulnerabilitySyncRunService.TriggerDecision(new SyncRun(),false));
        assertEquals(409,assertThrows(ResponseStatusException.class,()->service.run(id)).getStatusCode().value());
    }
    @Test void scheduleReadHydratesEnabledAndInterval() {
        org.springframework.test.util.ReflectionTestUtils.setField(service, "scheduledProfilesEnabled", true);
        UUID id=UUID.randomUUID();
        when(jdbc.queryForList(anyString(),eq(UUID.class),eq(id))).thenReturn(List.of(id));
        when(jdbc.queryForList(anyString(),eq(id))).thenReturn(List.of(Map.of("enabled",true,"interval_hours",12)));
        assertEquals(Map.of("id",id,"enabled",true,"intervalHours",12),service.schedule(id));
    }
    @Test void unboundProfileScheduleReadsDisabled() {
        UUID id=UUID.randomUUID();
        when(jdbc.queryForList(anyString(),eq(UUID.class),eq(id))).thenReturn(List.of(id));
        assertEquals(Map.of("id",id,"enabled",false,"intervalHours",24),service.schedule(id));
    }

    @Test void profileSchedulingRequiresExplicitEnablement() {
        UUID id = UUID.randomUUID();
        when(jdbc.query(anyString(), org.mockito.ArgumentMatchers.<RowMapper<IntelligenceImportProfileService.Profile>>any(), eq(id)))
                .thenReturn(List.of(profile(id)));

        assertEquals(409, assertThrows(ResponseStatusException.class, () -> service.schedule(id, true, 24))
                .getStatusCode().value());
        verify(jdbc, never()).update(anyString(), any(), any(), any(), any());
    }
}
