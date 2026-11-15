package com.prototype.vulnwatch.client;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withException;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.AwsOrganizationsClient.AwsOrganizationsException;
import com.prototype.vulnwatch.client.http.OutboundHostPolicy;
import com.prototype.vulnwatch.client.http.OutboundHttpClient;
import com.prototype.vulnwatch.client.http.OutboundPolicyDefaults;
import com.prototype.vulnwatch.client.http.OutboundPolicyFactory;
import java.net.SocketTimeoutException;
import java.util.Map;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.ExpectedCount;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestTemplate;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;

/** Contract tests for the AWS Organizations account-tag reads (Phase 0B §2.2.1). */
class AwsOrganizationsClientTest {

    private static final String ENDPOINT = "https://organizations.us-east-1.amazonaws.com/";
    private static final StaticCredentialsProvider CREDENTIALS =
            StaticCredentialsProvider.create(AwsBasicCredentials.create("AKIAEXAMPLEEXAMPLE00", "example-secret-key-for-tests-only"));
    private static final MediaType AMZ_JSON = MediaType.parseMediaType("application/x-amz-json-1.1");

    private MockRestServiceServer server;
    private AwsOrganizationsClient client;

    @BeforeEach
    void setUp() {
        RestTemplate restTemplate = new RestTemplate();
        server = MockRestServiceServer.bindTo(restTemplate).build();
        client = new AwsOrganizationsClient(new OutboundHttpClient(restTemplate, OutboundHostPolicy.forTests()),
                new OutboundPolicyFactory(new OutboundPolicyDefaults(0, 2, 1, 5, true, true)), new ObjectMapper());
    }

    @Test
    void readsEveryTagPageWithASignedJsonRequest() {
        server.expect(requestTo(ENDPOINT))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header("X-Amz-Target", "AWSOrganizationsV20161128.ListTagsForResource"))
                .andExpect(header("Authorization", Matchers.startsWith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEEXAMPLE00/")))
                .andExpect(header("Authorization", Matchers.containsString("/us-east-1/organizations/aws4_request")))
                .andExpect(content().json("{\"ResourceId\":\"111122223333\"}", true))
                .andRespond(withSuccess("{\"Tags\":[{\"Key\":\"team\",\"Value\":\"Payments\"}],\"NextToken\":\"p2\"}", AMZ_JSON));
        server.expect(requestTo(ENDPOINT))
                .andExpect(content().json("{\"ResourceId\":\"111122223333\",\"NextToken\":\"p2\"}", true))
                .andRespond(withSuccess("{\"Tags\":[{\"Key\":\"CostCentre\",\"Value\":\"42\"}]}", AMZ_JSON));
        assertEquals(Map.of("team", "Payments", "CostCentre", "42"), client.accountTags(CREDENTIALS, "111122223333"));
        server.verify();
    }

    @Test
    void accessDeniedIsFinalAndNamed() {
        server.expect(ExpectedCount.once(), requestTo(ENDPOINT))
                .andRespond(withStatus(HttpStatus.BAD_REQUEST).contentType(AMZ_JSON)
                        .body("{\"__type\":\"AccessDeniedException\",\"Message\":\"not authorized\"}"));
        AwsOrganizationsException denied = assertThrows(AwsOrganizationsException.class, () -> client.accountTags(CREDENTIALS, "111122223333"));
        assertEquals("AccessDeniedException", denied.code());
        server.verify();
    }

    @Test
    void anAccountOutsideAnOrganizationIsReported() {
        server.expect(ExpectedCount.once(), requestTo(ENDPOINT))
                .andRespond(withStatus(HttpStatus.BAD_REQUEST).contentType(AMZ_JSON)
                        .body("{\"__type\":\"com.amazonaws.organizations#AWSOrganizationsNotInUseException\",\"Message\":\"x\"}"));
        AwsOrganizationsException notInUse = assertThrows(AwsOrganizationsException.class,
                () -> client.describeAccount(CREDENTIALS, "111122223333"));
        assertEquals("AWSOrganizationsNotInUseException", notInUse.code());
    }

    @Test
    void throttlingIsRetriedWithinTheProviderBudget() {
        server.expect(requestTo(ENDPOINT))
                .andRespond(withStatus(HttpStatus.BAD_REQUEST).contentType(AMZ_JSON)
                        .body("{\"__type\":\"TooManyRequestsException\",\"Message\":\"slow down\"}"));
        server.expect(requestTo(ENDPOINT))
                .andExpect(header("X-Amz-Target", "AWSOrganizationsV20161128.DescribeAccount"))
                .andRespond(withSuccess("{\"Account\":{\"Id\":\"111122223333\",\"Name\":\"Payments prod\",\"Status\":\"ACTIVE\"}}", AMZ_JSON));
        AwsOrganizationsClient.AccountDescription account = client.describeAccount(CREDENTIALS, "111122223333");
        assertEquals("Payments prod", account.name());
        server.verify();
    }

    @Test
    void aTimeoutFailsTheRead() {
        server.expect(ExpectedCount.manyTimes(), requestTo(ENDPOINT))
                .andRespond(withException(new SocketTimeoutException("Read timed out")));
        assertThrows(RuntimeException.class, () -> client.accountTags(CREDENTIALS, "111122223333"));
    }
}
