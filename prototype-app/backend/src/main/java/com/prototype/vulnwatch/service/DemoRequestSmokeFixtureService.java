package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.DemoRequest;
import com.prototype.vulnwatch.repo.DemoRequestRepository;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

/**
 * Disposable demo requests for the lab's signed-in release smoke, so it can exercise the
 * platform-scope reject and delete writes without the public, Turnstile-protected form.
 *
 * <p>Off unless {@code app.demo.smoke-fixtures-enabled} is set; Terraform refuses that for
 * production. Fixtures use a reserved {@code .invalid} address, so nothing can ever be delivered
 * to them, and at most {@link #MAX_OPEN} can be pending at once.
 */
@Service
public class DemoRequestSmokeFixtureService {

    public static final String COMPANY = "Release smoke fixture";
    public static final String EMAIL_DOMAIN = "release-smoke.invalid";
    static final int MAX_OPEN = 5;

    private final boolean enabled;
    private final DemoRequestRepository requests;
    private final AuditEventService audit;

    public DemoRequestSmokeFixtureService(
            @Value("${app.demo.smoke-fixtures-enabled:false}") boolean enabled,
            DemoRequestRepository requests,
            AuditEventService audit
    ) {
        this.enabled = enabled;
        this.requests = requests;
        this.audit = audit;
    }

    @Transactional
    public DemoRequest create() {
        if (!enabled) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        if (requests.countByCompanyAndStatus(COMPANY, "PENDING") >= MAX_OPEN) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Too many pending smoke fixtures; reject or delete them first");
        }
        DemoRequest request = new DemoRequest();
        String label = UUID.randomUUID().toString();
        request.setEmail("smoke-" + label + "@" + EMAIL_DOMAIN);
        request.setFullName("Release smoke");
        request.setCompany(COMPANY);
        DemoRequest saved = requests.saveAndFlush(request);
        audit.record("demo.request.smoke_fixture_created", "demo_request", saved.getId().toString(), null);
        return saved;
    }
}
