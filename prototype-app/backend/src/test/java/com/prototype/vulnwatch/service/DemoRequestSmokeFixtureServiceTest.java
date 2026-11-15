package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.DemoRequest;
import com.prototype.vulnwatch.repo.DemoRequestRepository;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

class DemoRequestSmokeFixtureServiceTest {

    private final DemoRequestRepository requests = mock(DemoRequestRepository.class);
    private final AuditEventService audit = mock(AuditEventService.class);

    @Test
    void isNotFoundUnlessEnabled() {
        var service = new DemoRequestSmokeFixtureService(false, requests, audit);

        assertThatThrownBy(service::create).isInstanceOfSatisfying(ResponseStatusException.class,
                failure -> assertThat(failure.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND));
        verify(requests, never()).saveAndFlush(any());
    }

    @Test
    void createsAnUndeliverablePendingRequestAndAuditsIt() {
        when(requests.saveAndFlush(any(DemoRequest.class))).thenAnswer(call -> {
            DemoRequest saved = call.getArgument(0);
            org.springframework.test.util.ReflectionTestUtils.setField(saved, "id", java.util.UUID.randomUUID());
            return saved;
        });

        DemoRequest fixture = new DemoRequestSmokeFixtureService(true, requests, audit).create();

        assertThat(fixture.getEmail()).endsWith("@release-smoke.invalid");
        assertThat(fixture.getCompany()).isEqualTo(DemoRequestSmokeFixtureService.COMPANY);
        assertThat(fixture.getStatus()).isEqualTo("PENDING");
        verify(audit).record("demo.request.smoke_fixture_created", "demo_request", fixture.getId().toString(), null);
    }

    @Test
    void refusesMoreThanTheCapOfPendingFixtures() {
        when(requests.countByCompanyAndStatus(DemoRequestSmokeFixtureService.COMPANY, "PENDING"))
                .thenReturn((long) DemoRequestSmokeFixtureService.MAX_OPEN);

        assertThatThrownBy(new DemoRequestSmokeFixtureService(true, requests, audit)::create)
                .isInstanceOfSatisfying(ResponseStatusException.class,
                        failure -> assertThat(failure.getStatusCode()).isEqualTo(HttpStatus.CONFLICT));
    }
}
