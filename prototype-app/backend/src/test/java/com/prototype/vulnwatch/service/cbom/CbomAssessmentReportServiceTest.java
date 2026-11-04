package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CbomAssessmentResponse;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CbomAssessmentReportServiceTest {
    @Mock CbomAssessmentService assessments;

    @Test
    void htmlIsSelfContainedEscapedAndClearlyUnsigned() {
        Tenant tenant = new Tenant();
        UUID runId = UUID.randomUUID();
        when(assessments.get(tenant, runId)).thenReturn(response(runId));

        var report = new CbomAssessmentReportService(assessments, new ObjectMapper().findAndRegisterModules())
                .generate(tenant, runId, "html");
        String html = new String(report.content(), StandardCharsets.UTF_8);

        assertThat(report.contentType()).startsWith("text/html");
        assertThat(report.checksum()).hasSize(64);
        assertThat(html).contains("Unsigned report", "&lt;script&gt;alert(1)&lt;/script&gt;");
        assertThat(html).doesNotContain("<script>", "http://", "https://");
    }

    @Test
    void jsonCarriesVersionSignatureLimitationAndChecksum() {
        Tenant tenant = new Tenant();
        UUID runId = UUID.randomUUID();
        when(assessments.get(tenant, runId)).thenReturn(response(runId));

        var report = new CbomAssessmentReportService(assessments, new ObjectMapper().findAndRegisterModules())
                .generate(tenant, runId, "json");
        String json = new String(report.content(), StandardCharsets.UTF_8);

        assertThat(json).contains("\"schemaVersion\" : \"1.0\"", "\"signatureStatus\" : \"UNSIGNED\"",
                "\"checksumSha256\"");
    }

    private CbomAssessmentResponse response(UUID id) {
        return new CbomAssessmentResponse(id, UUID.randomUUID(), null, "sha256:artifact", "baseline", "1.0.0",
                "sha256:rules", "1.0", "SUCCEEDED", "VALID_WITH_WARNINGS", 1, 1,
                new BigDecimal("0.75"), new BigDecimal("0.50"), Instant.now(), Instant.now(),
                List.of(new CbomAssessmentResponse.ValidationIssue(UUID.randomUUID(), "UNTRUSTED_TEXT", "WARNING",
                        "/components/0/name", "<script>alert(1)</script>")), List.of());
    }
}
