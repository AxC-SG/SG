package com.prototype.vulnwatch.service.fix;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.FixAsset;
import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FixControlRequest;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FixAssetEventRepository;
import com.prototype.vulnwatch.repo.FixAssetRepository;
import com.prototype.vulnwatch.repo.FixControlDetailRepository;
import com.prototype.vulnwatch.repo.FixRecordCveRepository;
import com.prototype.vulnwatch.repo.FixRecordRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.server.ResponseStatusException;

class FixManagementServiceTest {

    private final FixRecordRepository fixes = mock(FixRecordRepository.class);
    private final FixRecordCveRepository fixCves = mock(FixRecordCveRepository.class);
    private final FixControlDetailRepository controls = mock(FixControlDetailRepository.class);
    private final FixAssetRepository fixAssets = mock(FixAssetRepository.class);
    private final FixAssetEventRepository events = mock(FixAssetEventRepository.class);
    private final AssetRepository assets = mock(AssetRepository.class);
    private final FixManagementService service =
            new FixManagementService(fixes, fixCves, controls, fixAssets, events, assets);

    private final Tenant tenant = tenant();
    private final Tenant otherTenant = tenant();

    @BeforeEach
    void setUp() {
        when(fixes.save(any())).thenAnswer(invocation -> {
            FixRecord record = invocation.getArgument(0);
            if (record.getId() == null) ReflectionTestUtils.setField(record, "id", UUID.randomUUID());
            return record;
        });
        when(controls.findById(any())).thenReturn(Optional.empty());
        when(fixCves.findByFixIdAndCveId(any(), any())).thenReturn(Optional.empty());
        when(fixAssets.findByFixId(any(), any())).thenReturn(List.of());
        when(assets.findAllById(any())).thenReturn(List.of());
    }

    @Test
    void approverMustDifferFromProposer() {
        FixRecord fix = stored(tenant, FixRecord.Status.PROPOSED, "alice");

        assertThatThrownBy(() -> service.approve(tenant, "alice", fix.getId()))
                .isInstanceOf(ResponseStatusException.class)
                .extracting(e -> ((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);

        service.approve(tenant, "bob", fix.getId());
        assertThat(fix.getStatus()).isEqualTo(FixRecord.Status.ACTIVE);
        assertThat(fix.getApprovedBy()).isEqualTo("bob");
    }

    @Test
    void onlyProposedFixesCanBeApproved() {
        FixRecord fix = stored(tenant, FixRecord.Status.DRAFT, "alice");
        assertThatThrownBy(() -> service.approve(tenant, "bob", fix.getId()))
                .extracting(e -> ((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void anotherTenantsFixIsNotFound() {
        FixRecord fix = stored(otherTenant, FixRecord.Status.PROPOSED, "alice");
        assertThatThrownBy(() -> service.approve(tenant, "bob", fix.getId()))
                .extracting(e -> ((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThatThrownBy(() -> service.update(tenant, "bob", fix.getId(), request("WORKAROUND", List.of(), List.of())))
                .extracting(e -> ((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    @Test
    void patchToolFixesAreReadOnly() {
        FixRecord fix = stored(tenant, FixRecord.Status.ACTIVE, null);
        fix.setRecommendationSource(FixRecord.RecommendationSource.PATCH_TOOL.name());
        assertThatThrownBy(() -> service.update(tenant, "bob", fix.getId(), request("WORKAROUND", List.of(), List.of())))
                .extracting(e -> ((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThatThrownBy(() -> service.retire(tenant, fix.getId()))
                .extracting(e -> ((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void editingAnActiveControlSendsItBackForApproval() {
        FixRecord fix = stored(tenant, FixRecord.Status.ACTIVE, "alice");
        fix.setApprovedBy("bob");

        service.update(tenant, "carol", fix.getId(), request("WORKAROUND", List.of(), List.of()));

        assertThat(fix.getStatus()).isEqualTo(FixRecord.Status.PROPOSED);
        assertThat(fix.getApprovedBy()).isNull();
        assertThat(fix.getProposedBy()).isEqualTo("carol");
    }

    @Test
    void staleVersionIsRejected() {
        FixRecord fix = stored(tenant, FixRecord.Status.DRAFT, "alice");
        FixControlRequest stale = new FixControlRequest("WORKAROUND", "Disable SMBv1", null, null, null, null, null, null,
                null, null, null, null, null, null, List.of(), List.of(), false, 7L);
        assertThatThrownBy(() -> service.update(tenant, "alice", fix.getId(), stale))
                .extracting(e -> ((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void createRejectsPatchTypesInvalidCvesAndForeignAssets() {
        assertThatThrownBy(() -> service.create(tenant, "alice", request("PATCH", List.of(), List.of())))
                .extracting(e -> ((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThatThrownBy(() -> service.create(tenant, "alice", request("WORKAROUND", List.of("not-a-cve"), List.of())))
                .extracting(e -> ((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);

        UUID foreignAsset = UUID.randomUUID();
        Asset asset = new Asset();
        asset.setTenant(otherTenant);
        ReflectionTestUtils.setField(asset, "id", foreignAsset);
        when(assets.findAllById(any())).thenReturn(List.of(asset));
        assertThatThrownBy(() -> service.create(tenant, "alice", request("WORKAROUND", List.of(), List.of(foreignAsset))))
                .extracting(e -> ((ResponseStatusException) e).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        verify(fixAssets, never()).save(any());
    }

    @Test
    void createProposesAnalystControlWithNormalizedCves() {
        UUID id = service.create(tenant, "alice", new FixControlRequest("COMPENSATING_CONTROL", "  Block port 445 ",
                null, "high", "windows", null, null, null, null, "NETWORK", null, null, "low", null,
                List.of("cve-2024-12345"), List.of(), true, null));

        assertThat(id).isNotNull();
        org.mockito.ArgumentCaptor<FixRecord> saved = org.mockito.ArgumentCaptor.forClass(FixRecord.class);
        verify(fixes, org.mockito.Mockito.atLeastOnce()).save(saved.capture());
        FixRecord record = saved.getValue();
        assertThat(record.isManaged()).isTrue();
        assertThat(record.getTitle()).isEqualTo("Block port 445");
        assertThat(record.getStatus()).isEqualTo(FixRecord.Status.PROPOSED);
        assertThat(record.getSeverity()).isEqualTo("HIGH");
        assertThat(record.getEcosystem()).isEqualTo(FixRecord.Ecosystem.WINDOWS);
        assertThat(record.getCveId()).isEqualTo("CVE-2024-12345");
    }

    @Test
    void approvalMarksScopedAssetsApplied() {
        FixRecord fix = stored(tenant, FixRecord.Status.PROPOSED, "alice");
        FixAsset scoped = new FixAsset();
        scoped.setProvider("ANALYST");
        scoped.setStatus(FixAssetStatus.SCHEDULED);
        when(fixAssets.findByFixId(any(), any())).thenReturn(List.of(scoped));

        service.approve(tenant, "bob", fix.getId());

        assertThat(scoped.getStatus()).isEqualTo(FixAssetStatus.APPLIED);
        verify(events).save(any());
    }

    private FixRecord stored(Tenant owner, FixRecord.Status status, String proposedBy) {
        FixRecord fix = new FixRecord();
        ReflectionTestUtils.setField(fix, "id", UUID.randomUUID());
        fix.setTenant(owner);
        fix.setFixType("WORKAROUND");
        fix.setManaged(true);
        fix.setRecommendationSource(FixRecord.RecommendationSource.ANALYST.name());
        fix.setStatus(status);
        fix.setProposedBy(proposedBy);
        when(fixes.findById(fix.getId())).thenReturn(Optional.of(fix));
        return fix;
    }

    private static FixControlRequest request(String type, List<String> cves, List<UUID> assetIds) {
        return new FixControlRequest(type, "Disable SMBv1", null, null, null, null, null, null, null, null, null,
                null, null, null, cves, assetIds, false, null);
    }

    private static Tenant tenant() {
        Tenant tenant = new Tenant();
        tenant.setId(UUID.randomUUID());
        return tenant;
    }
}
