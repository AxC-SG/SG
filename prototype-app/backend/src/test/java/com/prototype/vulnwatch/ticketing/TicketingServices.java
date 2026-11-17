package com.prototype.vulnwatch.ticketing;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.repo.FindingRepository;
import java.util.List;
import java.util.Map;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;

/** Unit-test wiring for {@link TicketingService} on the legacy routing path (Phase 0B §4.9: read wave off). */
final class TicketingServices {

    private TicketingServices() { }

    static TicketingService legacy(TicketingProviderRegistry registry, FindingRepository findings) {
        TicketingService service = new TicketingService(registry, findings);
        TicketRoutingService routing = mock(TicketRoutingService.class);
        when(routing.plan(any(), any(), any())).thenReturn(new TicketRoutingService.Plan(
                new TicketRoutingService.Preview(false, List.of(), List.of(), List.of(), null, null, null), Map.of()));
        PlatformTransactionManager transactions = mock(PlatformTransactionManager.class);
        when(transactions.getTransaction(any())).thenReturn(mock(TransactionStatus.class));
        service.configure(routing, mock(JdbcTemplate.class), transactions);
        return service;
    }
}
