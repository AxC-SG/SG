package com.prototype.vulnwatch.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class PublicEndpointRateLimiterIsolationTest {
    private final AtomicLong clock = new AtomicLong(1_000_000);
    private PublicEndpointRateLimiter limiter() {
        return new PublicEndpointRateLimiter(true, true, "10.9.0.0/24,2001:db8:ffff::/48", clock::get);
    }
    private MockHttpServletRequest trustedRequest(String address) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.9.0.5");
        request.addHeader("X-Forwarded-For", address);
        return request;
    }
    @Test
    void ignoresForgedHeadersOnDirectIngressAndStopsAtFirstUntrustedHop() {
        PublicEndpointRateLimiter limiter = limiter();
        MockHttpServletRequest request = trustedRequest("192.0.2.8, 198.51.100.7, 10.9.0.6");
        request.addHeader("CF-Connecting-IP", "192.0.2.200");
        request.addHeader("Forwarded", "for=192.0.2.201");
        assertThat(limiter.clientIp(request)).isEqualTo("198.51.100.7");
        request.setRemoteAddr("203.0.113.10");
        assertThat(limiter.clientIp(request)).isEqualTo("203.0.113.10");
        assertThat(limiter.clientIp(trustedRequest("198.51.100.7, malformed"))).isEqualTo("10.9.0.5");
        assertThat(limiter.clientIp(trustedRequest("2001:db8::1"))).isEqualTo("2001:db8:0:0:0:0:0:1");
    }
    @Test
    void registrationFloodDoesNotConsumeLoginBudgetAndIpLimitRemainsThirty() {
        PublicEndpointRateLimiter limiter = limiter();
        for (int index = 0; index < 300; index++) {
            limiter.checkRegistration(trustedRequest("198.51." + index / 250 + "." + (index % 250 + 1)), "register" + index + "@example.test");
        }
        assertThatThrownBy(() -> limiter.checkRegistration(trustedRequest("192.0.2.10"), "another@example.test"))
                .isInstanceOf(PublicRateLimitException.class);
        for (int index = 0; index < 30; index++) limiter.checkLogin(trustedRequest("203.0.113.2"), "login" + index + "@example.test");
        assertThatThrownBy(() -> limiter.checkLogin(trustedRequest("203.0.113.2"), "login31@example.test"))
                .isInstanceOf(PublicRateLimitException.class);
    }
    @Test
    void emailLimitIsTenAndWindowsAndProcessScopeAreExplicit() {
        PublicEndpointRateLimiter limiter = limiter();
        for (int index = 0; index < 10; index++) limiter.checkLogin(trustedRequest("203.0.113." + (index + 1)), "One@Example.test");
        assertThatThrownBy(() -> limiter.checkLogin(trustedRequest("203.0.113.20"), " one@example.test "))
                .isInstanceOf(PublicRateLimitException.class);
        limiter().checkLogin(trustedRequest("203.0.113.20"), "one@example.test");
        clock.addAndGet(15 * 60 * 1000);
        limiter.checkLogin(trustedRequest("203.0.113.20"), "one@example.test");
    }
}
