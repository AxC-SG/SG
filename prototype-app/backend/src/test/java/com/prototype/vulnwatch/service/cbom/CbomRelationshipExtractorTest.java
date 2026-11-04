package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class CbomRelationshipExtractorTest {
    @Test void extractsCycloneDxDeclaredDependencies(){
        String json="{\"dependencies\":[{\"ref\":\"crypto:key\",\"dependsOn\":[\"crypto:algorithm\"]}]}";
        assertThat(new CbomRelationshipExtractor(new ObjectMapper()).extract(json.getBytes(StandardCharsets.UTF_8)))
                .containsExactly(new CbomRelationshipExtractor.DeclaredRelationship("crypto:key","crypto:algorithm"));
    }
}
