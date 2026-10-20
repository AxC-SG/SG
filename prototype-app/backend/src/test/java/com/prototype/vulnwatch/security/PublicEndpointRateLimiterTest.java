package com.prototype.vulnwatch.security;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

class PublicEndpointRateLimiterTest {

    @Test
    void limitsRepeatedRegistrationByNormalizedEmail() {
        PublicEndpointRateLimiter limiter = new PublicEndpointRateLimiter(true, false);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.10");

        limiter.checkRegistration(request, "Alex@Example.com");
        limiter.checkRegistration(request, "alex@example.com");
        limiter.checkRegistration(request, " alex@example.com ");

        assertThatThrownBy(() -> limiter.checkRegistration(request, "ALEX@example.com"))
                .isInstanceOf(PublicRateLimitException.class);
    }

    @Test
    void ignoresCloudflareAddressWithoutAnExplicitTrustedProxyChain() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.0.0.5");
        request.addHeader("CF-Connecting-IP", "198.51.100.24");

        org.assertj.core.api.Assertions.assertThat(new PublicEndpointRateLimiter(true, true).clientIp(request))
                .isEqualTo("10.0.0.5");
        org.assertj.core.api.Assertions.assertThat(new PublicEndpointRateLimiter(true, false).clientIp(request))
                .isEqualTo("10.0.0.5");
    }
}
