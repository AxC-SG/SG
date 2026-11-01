package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.test.util.ReflectionTestUtils;

class ResendEmailClientTest {

    @Test
    void defaultsToScoutgridSenderWhenSenderConfigurationIsEmpty() {
        ResendEmailClient client = new ResendEmailClient(
                new ObjectMapper(), "https://api.resend.com", "resend-key", "", "");

        assertEquals("Scout.ai <noreply@scoutgrid.io>",
                ReflectionTestUtils.getField(client, "fromAddress"));
    }

    @Test
    void fallsBackToVerifiedDomainSenderWhenConfiguredFromDomainDoesNotMatch() {
        ResendEmailClient client = new ResendEmailClient(
                new ObjectMapper(),
                "https://api.resend.com",
                "resend-key",
                "Scout.ai <noreply@wrong-domain.example>",
                "scoutgrid.io"
        );

        assertEquals(
                "Scout.ai <noreply@scoutgrid.io>",
                ReflectionTestUtils.getField(client, "fromAddress")
        );
    }

    @Test
    void preservesConfiguredSenderWhenItMatchesVerifiedDomain() {
        ResendEmailClient client = new ResendEmailClient(
                new ObjectMapper(),
                "https://api.resend.com",
                "resend-key",
                "Scout.ai <noreply@scoutgrid.io>",
                "scoutgrid.io"
        );

        assertEquals(
                "Scout.ai <noreply@scoutgrid.io>",
                ReflectionTestUtils.getField(client, "fromAddress")
        );
    }
}
