package com.prototype.vulnwatch.config;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.ServletException;
import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class RequestCorrelationFilterTest {

    private final RequestCorrelationFilter filter = new RequestCorrelationFilter();

    @Test
    void echoesSafeRequestIdAndClearsMdc() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/dashboard");
        request.addHeader(RequestCorrelationFilter.REQUEST_ID_HEADER, "req-123");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertEquals("req-123", response.getHeader(RequestCorrelationFilter.REQUEST_ID_HEADER));
        assertTrue(response.getHeader(RequestCorrelationFilter.SERVER_TIMING_HEADER).startsWith("app;dur="));
        assertNull(MDC.get(RequestCorrelationFilter.REQUEST_ID_MDC_KEY));
    }

    @Test
    void replacesUnsafeRequestId() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/dashboard");
        request.addHeader(RequestCorrelationFilter.REQUEST_ID_HEADER, "bad value with spaces");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        String generated = response.getHeader(RequestCorrelationFilter.REQUEST_ID_HEADER);
        assertNotEquals("bad value with spaces", generated);
        assertTrue(generated.matches("[0-9a-f-]{36}"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"=SUM(A1)", "+cmd", "-cmd", "@command", " req-123", "req-123\n", "\tformula", "request/secret=value"})
    void replacesFormulaControlAndStructuredRequestIds(String supplied) throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/dashboard");
        request.addHeader(RequestCorrelationFilter.REQUEST_ID_HEADER, supplied);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertNotEquals(supplied, response.getHeader(RequestCorrelationFilter.REQUEST_ID_HEADER));
        assertTrue(response.getHeader(RequestCorrelationFilter.REQUEST_ID_HEADER).matches("[0-9a-f-]{36}"));
    }

    @Test
    void preservesServerTimingWhenDownstreamWritesAndFlushesBody() throws ServletException, IOException {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/dashboard");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, (req, res) -> {
            res.getWriter().write("{\"status\":\"ok\"}");
            res.flushBuffer();
        });

        assertEquals("{\"status\":\"ok\"}", response.getContentAsString());
        assertTrue(response.getHeader(RequestCorrelationFilter.SERVER_TIMING_HEADER).startsWith("app;dur="));
    }
}
