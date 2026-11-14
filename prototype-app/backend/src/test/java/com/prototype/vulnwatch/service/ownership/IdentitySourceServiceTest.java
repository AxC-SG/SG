package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.ServiceNowDirectoryClient;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.security.tenantkey.TenantDataCipher;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.ownership.IdentitySourceService.ServiceNowSourceRequest;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.server.ResponseStatusException;

class IdentitySourceServiceTest {

    private final JdbcTemplate jdbc = mock(JdbcTemplate.class);
    private final ServiceNowDirectoryClient client = mock(ServiceNowDirectoryClient.class);
    private final DirectoryService directory = mock(DirectoryService.class);
    private final IdentitySourceService off = new IdentitySourceService(jdbc, directory, mock(TenantDataCipher.class), mock(AuditEventService.class),
            OutboundHostPolicy.forTests(), client, mock(OwnershipClaimService.class), new ObjectMapper(), false);

    @Test
    void configuringTestingAndResumingAreRefusedWhileTheSwitchIsOff() {
        ServiceNowSourceRequest req = new ServiceNowSourceRequest("Acme", "https://acme.service-now.com", "BASIC", "svc", "s", null, null, 0L);
        UUID id = UUID.randomUUID();

        assertConflict(() -> off.create(req, "admin"));
        assertConflict(() -> off.update(id, req, "admin"));
        assertConflict(() -> off.testConnection(id, "admin"));
        assertConflict(() -> off.resume(id, "admin"));
        verifyNoInteractions(jdbc, directory, client);
    }

    @Test
    void filtersAreValidatedPerContractTableAndBlankFiltersDropped() {
        assertThat(IdentitySourceService.filters(Map.of("sys_user", " active=true ", "sys_user_group", "  ")))
                .isEqualTo(Map.of("sys_user", "active=true"));
        assertThatThrownBy(() -> IdentitySourceService.filters(Map.of("sys_user", "x^NQy")))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(400));
        assertThatThrownBy(() -> IdentitySourceService.filters(Map.of("cmdb_ci", "active=true")))
                .isInstanceOfSatisfying(ResponseStatusException.class, ex -> assertThat(ex.getStatusCode().value()).isEqualTo(400));
    }

    private static void assertConflict(Runnable action) {
        assertThatThrownBy(action::run).isInstanceOfSatisfying(ResponseStatusException.class,
                ex -> assertThat(ex.getStatusCode().value()).isEqualTo(409));
    }
}
