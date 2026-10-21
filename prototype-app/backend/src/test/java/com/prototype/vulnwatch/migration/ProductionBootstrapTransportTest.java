package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.test.util.ReflectionTestUtils;

class ProductionBootstrapTransportTest {
    @Test void preservesTlsAndOtherOptionsWhileAddingOnlyMissingTimeouts() {
        String url = "jdbc:postgresql://localhost/fixture?sslmode=verify-full&sslrootcert=/tmp/fixture%20CA.pem&ApplicationName=closure";
        assertEquals(url + "&connectTimeout=10&socketTimeout=30", bounded(url));
        assertEquals(url + "&connectTimeout=7&socketTimeout=11", bounded(url + "&connectTimeout=7&socketTimeout=11"));
        assertEquals(url + "&connectTimeout=7&socketTimeout=30", bounded(url + "&connectTimeout=7"));
        assertEquals("jdbc:postgresql://localhost/fixture?connectTimeout=10&socketTimeout=30", bounded("jdbc:postgresql://localhost/fixture"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"connectTimeout=0", "socketTimeout=-1", "socketTimeout=invalid", "connectTimeout=2147483648",
            "connectTimeout=1&connectTimeout=2", "ConnectTimeout=5", "socketTimeout", "socketTimeout="})
    void rejectsUnboundedMalformedAndAmbiguousTimeouts(String query) {
        assertThrows(IllegalArgumentException.class, () -> bounded("jdbc:postgresql://localhost/fixture?" + query));
    }

    private String bounded(String url) { return ReflectionTestUtils.invokeMethod(ProductionBootstrapCli.class, "boundedJdbcUrl", url); }
}
