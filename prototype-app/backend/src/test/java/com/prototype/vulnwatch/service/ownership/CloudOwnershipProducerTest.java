package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer.Provider;
import com.prototype.vulnwatch.service.ownership.CloudOwnershipProducer.Scope;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Key matching, value limits and scope coverage for the cloud ownership producer (Phase 0B §2.2, §2.4, §2.5). */
class CloudOwnershipProducerTest {

    @Test
    void awsTagKeysMatchCaseInsensitivelyAfterTrimmingAndOnlyOwnerAndTeamAreRead() {
        Map<String, String> tags = Map.of(" Owner ", "Payments", "TEAM", "Identity", "CostCentre", "Finance");
        assertThat(CloudOwnershipProducer.tagValue(Provider.AWS, tags, "owner")).isEqualTo("Payments");
        assertThat(CloudOwnershipProducer.tagValue(Provider.AWS, tags, "team")).isEqualTo("Identity");
        assertThat(CloudOwnershipProducer.KEYS).containsExactly("owner", "team");
    }

    @Test
    void gcpLabelKeysAreLowerCaseByDefinitionSoTheyMatchExactly() {
        assertThat(CloudOwnershipProducer.tagValue(Provider.GCP, Map.of("Team", "x"), "team")).isNull();
        assertThat(CloudOwnershipProducer.tagValue(Provider.GCP, Map.of("team", "payments"), "team")).isEqualTo("payments");
    }

    @Test
    void longValuesAndControlCharactersAreNeverResolved() {
        assertThat(CloudOwnershipProducer.acceptable("x".repeat(256))).isTrue();
        assertThat(CloudOwnershipProducer.acceptable("x".repeat(257))).isFalse();
        assertThat(CloudOwnershipProducer.acceptable("pay\u0000ments")).isFalse();
        assertThat(CloudOwnershipProducer.acceptable("pay\nments")).isFalse();
    }

    @Test
    void awsScopesCompareAccountTypeAndRegionAsTheConnectorDoes() {
        Scope east = new Scope("111122223333", "EC2", "us-east-1");
        assertThat(east.covers("111122223333", "ec2", " US-EAST-1 ")).isTrue();
        assertThat(east.covers("111122223333", "EC2", "eu-west-1")).isFalse();
        assertThat(east.covers("999988887777", "EC2", "us-east-1")).isFalse();
    }

    @Test
    void gcpScopesCoverEveryRegionOfTheTypeInTheProject() {
        Scope instances = new Scope("proj-1", "compute.googleapis.com/Instance", null);
        assertThat(instances.covers("proj-1", "compute.googleapis.com/Instance", "us-central1")).isTrue();
        assertThat(instances.covers("proj-2", "compute.googleapis.com/Instance", "us-central1")).isFalse();
    }

    @Test
    void connectorIntervalsMustSuitTheClaimTtls() {
        assertThat(CloudOwnershipSourceService.validInterval(14)).isFalse();
        assertThat(CloudOwnershipSourceService.validInterval(15)).isTrue();
        assertThat(CloudOwnershipSourceService.validInterval(7 * 24 * 60)).isTrue();
        assertThat(CloudOwnershipSourceService.validInterval(7 * 24 * 60 + 1)).isFalse();
    }

    @Test
    void savingAnOutOfRangeConnectorIntervalIsRejectedOnlyWhileTheProducerIsEnabled() {
        CloudOwnershipSourceService on = new CloudOwnershipSourceService(null, null, null, null, null, null, true);
        org.springframework.web.server.ResponseStatusException rejected = org.junit.jupiter.api.Assertions.assertThrows(
                org.springframework.web.server.ResponseStatusException.class, () -> on.requireValidConnectorInterval(5));
        assertThat(rejected.getStatusCode().value()).isEqualTo(400);
        on.requireValidConnectorInterval(60);
        on.requireValidConnectorInterval(null);
        new CloudOwnershipSourceService(null, null, null, null, null, null, false).requireValidConnectorInterval(5);
    }
}
