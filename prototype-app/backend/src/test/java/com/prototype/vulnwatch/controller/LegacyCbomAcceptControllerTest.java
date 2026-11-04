package com.prototype.vulnwatch.controller;

import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.prototype.vulnwatch.service.AuditEventService;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

@ExtendWith(MockitoExtension.class)
class LegacyCbomAcceptControllerTest {
    @Mock AuditEventService auditEventService;

    @Test
    void removedRouteReturnsAuditedGoneResponse() throws Exception {
        UUID findingId = UUID.randomUUID();
        MockMvc mvc = MockMvcBuilders.standaloneSetup(new LegacyCbomAcceptController(auditEventService)).build();

        mvc.perform(post("/api/bom/cbom/findings/{findingId}/accept", findingId))
                .andExpect(status().isGone())
                .andExpect(header().string("Deprecation", "true"))
                .andExpect(jsonPath("$.code").value("LEGACY_CBOM_ACCEPT_REMOVED"));

        verify(auditEventService).record("cbom.legacy_accept.removed_call", "cbom_finding", findingId.toString(),
                "{\"replacement\":\"/api/findings/{canonicalFindingId}/suppression-requests\"}", "DENIED");
    }
}
