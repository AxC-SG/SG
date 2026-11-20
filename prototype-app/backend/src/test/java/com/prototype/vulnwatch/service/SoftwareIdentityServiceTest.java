package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.IdentityLink;
import com.prototype.vulnwatch.domain.IdentityMatchRule;
import com.prototype.vulnwatch.domain.IdentifierType;
import com.prototype.vulnwatch.domain.SoftwareIdentifier;
import com.prototype.vulnwatch.domain.SoftwareIdentity;
import com.prototype.vulnwatch.domain.SoftwareInstance;
import com.prototype.vulnwatch.repo.IdentityLinkRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentifierRepository;
import com.prototype.vulnwatch.repo.SoftwareIdentityRepository;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class SoftwareIdentityServiceTest {

    @Mock
    private SoftwareIdentityRepository softwareIdentityRepository;

    @Mock
    private SoftwareIdentifierRepository softwareIdentifierRepository;

    @Mock
    private IdentityLinkRepository identityLinkRepository;

    @Mock
    private IdentityGraphService identityGraphService;

    @Test
    void resolveHostSoftwareIdentityCreatesCanonicalIdentityWhenNoStrongMatchExists() {
        SoftwareIdentityService service = new SoftwareIdentityService(
                softwareIdentityRepository,
                softwareIdentifierRepository,
                identityLinkRepository,
                identityGraphService
        );
        SoftwareInstance instance = new SoftwareInstance();
        UUID instanceId = UUID.randomUUID();
        ReflectionTestUtils.setField(instance, "id", instanceId);
        instance.setVersionEvidence("plain-text");

        HostSoftwareNormalizationService.NormalizedHostSoftware normalized =
                new HostSoftwareNormalizationService.NormalizedHostSoftware(
                        "microsoft office",
                        "microsoft",
                        "16.0",
                        "microsoft",
                        "office",
                        "16.0",
                        "microsoft:office",
                        "pkg:generic/microsoft/office@16.0",
                        "plain-text",
                        false
                );

        when(softwareIdentityRepository.findByCanonicalKey("pkg:generic:microsoft:office"))
                .thenReturn(Optional.empty());
        when(softwareIdentityRepository.save(any(SoftwareIdentity.class)))
                .thenAnswer(invocation -> {
                    SoftwareIdentity identity = invocation.getArgument(0);
                    if (identity.getId() == null) {
                        ReflectionTestUtils.setField(identity, "id", UUID.randomUUID());
                    }
                    return identity;
                });
        when(identityLinkRepository.findBySourceTypeAndSourceIdAndTargetTypeAndTargetIdAndMatchRuleAndSource(
                eq("SOFTWARE_INSTANCE"),
                eq(instanceId.toString()),
                eq("SOFTWARE_IDENTITY"),
                any(String.class),
                eq(IdentityMatchRule.NORMALIZED_KEY),
                eq("servicenow")))
                .thenReturn(Optional.empty());

        SoftwareIdentityService.HostIdentityResolution resolution = service.resolveHostSoftwareIdentity(
                instance,
                null,
                normalized,
                "servicenow"
        );

        assertEquals(IdentityMatchRule.NORMALIZED_KEY, resolution.matchRule());
        assertEquals(0.90, resolution.confidence());
        assertEquals(Set.of(), resolution.cpeCandidates());
        assertEquals("pkg:generic:microsoft:office", resolution.identity().getCanonicalKey());
        verify(identityLinkRepository).save(any(IdentityLink.class));

        var rediscovered = service.resolveHostSoftwareIdentity(instance, null, normalized, "servicenow");
        assertSame(resolution.identity(), rediscovered.identity());
        verify(softwareIdentityRepository).save(any(SoftwareIdentity.class));
    }

    @Test
    void resolveHostSoftwareIdentityReusesExistingIdentifierMatch() {
        SoftwareIdentityService service = new SoftwareIdentityService(
                softwareIdentityRepository,
                softwareIdentifierRepository,
                identityLinkRepository,
                identityGraphService
        );
        SoftwareInstance instance = new SoftwareInstance();
        UUID instanceId = UUID.randomUUID();
        ReflectionTestUtils.setField(instance, "id", instanceId);
        instance.setVersionEvidence("{00112233-4455-6677-8899-aabbccddeeff}");

        SoftwareIdentity existingIdentity = new SoftwareIdentity();
        ReflectionTestUtils.setField(existingIdentity, "id", UUID.randomUUID());
        existingIdentity.setCanonicalKey("pkg:generic:microsoft:office");
        existingIdentity.setDisplayName("microsoft/office");

        SoftwareIdentifier identifier = new SoftwareIdentifier();
        identifier.setSoftwareIdentity(existingIdentity);
        identifier.setIdType(IdentifierType.MSI_PRODUCT_CODE);
        identifier.setNormalizedValue("{00112233-4455-6677-8899-aabbccddeeff}");
        identifier.setVerified(true);
        identifier.setConfidence(1.0);

        HostSoftwareNormalizationService.NormalizedHostSoftware normalized =
                new HostSoftwareNormalizationService.NormalizedHostSoftware(
                        "microsoft office",
                        "microsoft",
                        "16.0",
                        "microsoft",
                        "office",
                        "16.0",
                        "microsoft:office",
                        "pkg:generic/microsoft/office@16.0",
                        "{00112233-4455-6677-8899-aabbccddeeff}",
                        false
                );

        when(softwareIdentifierRepository.findByIdTypeAndNormalizedValue(
                IdentifierType.MSI_PRODUCT_CODE,
                "{00112233-4455-6677-8899-aabbccddeeff}"))
                .thenReturn(List.of(identifier));
        when(softwareIdentityRepository.save(any(SoftwareIdentity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(identityLinkRepository.findBySourceTypeAndSourceIdAndTargetTypeAndTargetIdAndMatchRuleAndSource(
                eq("SOFTWARE_INSTANCE"),
                eq(instanceId.toString()),
                eq("SOFTWARE_IDENTITY"),
                eq(existingIdentity.getId().toString()),
                eq(IdentityMatchRule.IDENTIFIER),
                eq("servicenow")))
                .thenReturn(Optional.empty());

        SoftwareIdentityService.HostIdentityResolution resolution = service.resolveHostSoftwareIdentity(
                instance,
                null,
                normalized,
                "servicenow"
        );

        assertSame(existingIdentity, resolution.identity());
        assertEquals(IdentityMatchRule.IDENTIFIER, resolution.matchRule());
        assertEquals(1.0, resolution.confidence());
        assertTrue(resolution.cpeCandidates().isEmpty());
    }
}
