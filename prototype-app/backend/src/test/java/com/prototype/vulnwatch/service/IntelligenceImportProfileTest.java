package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;

class IntelligenceImportProfileTest {
    private VulnerabilityIntelligenceService.ObservationUpsertRequest observation(Double score,String severity,String date) {
        return new VulnerabilityIntelligenceService.ObservationUpsertRequest("CVE-1999-12345","nvd","CVE-1999-12345",null,null,null,severity,score,null,null,null,null,null,null,null,date==null?null:Instant.parse(date),null,null);
    }
    @Test void wildcardIncludesMissingScoresAndDates() {
        var p=new IntelligenceImportProfile(UUID.randomUUID(),"All",List.of("NVD"),null,null,null,null,Set.of(),false);
        assertTrue(p.matches(observation(null,null,null)));
    }
    @Test void yearUsesPublicationDateAndScoreBoundsAreInclusive() {
        var p=new IntelligenceImportProfile(UUID.randomUUID(),"2025 high",List.of("NVD"),2025,2025,7d,9d,Set.of("HIGH"),false);
        assertTrue(p.matches(observation(7d,"HIGH","2025-01-01T00:00:00Z")));
        assertFalse(p.matches(observation(7d,"HIGH","2024-12-31T23:59:59Z")));
        assertFalse(p.matches(observation(null,"HIGH","2025-01-01T00:00:00Z")));
    }
    @Test void unsupportedSourcesAreRejectedExplicitly() {
        assertThrows(org.springframework.web.server.ResponseStatusException.class,()->IntelligenceImportProfileService.validate(
            new IntelligenceImportProfileService.Profile(null,"OSV",Set.of("OSV"),null,null,null,null,Set.of(),true)));
    }
}
