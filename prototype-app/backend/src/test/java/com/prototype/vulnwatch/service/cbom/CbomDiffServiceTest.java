package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.BomType;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.BomIngestionRecordRepository;
import com.prototype.vulnwatch.repo.CbomComponentRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class CbomDiffServiceTest {
    @Mock BomIngestionRecordRepository boms;
    @Mock CbomComponentRepository components;

    @Test
    void matchesStableIdentityAndReportsAddedRemovedAndChangedComponents() {
        Tenant tenant = tenant();
        BomIngestionRecord from = bom(tenant);
        BomIngestionRecord to = bom(tenant);
        CbomComponent oldTls = component(tenant, from, "tls", "TLS", "TLS-1.2", 2048);
        CbomComponent newTls = component(tenant, to, "tls", "TLS", "TLS-1.3", 3072);
        CbomComponent removed = component(tenant, from, "removed", "Legacy cert", "RSA", 1024);
        CbomComponent added = component(tenant, to, "added", "PQC key", "ML-KEM", 768);
        when(boms.findById(from.getId())).thenReturn(Optional.of(from));
        when(boms.findById(to.getId())).thenReturn(Optional.of(to));
        when(components.findByTenant_IdAndSourceBom_IdOrderByNameAsc(tenant.getId(), from.getId()))
                .thenReturn(List.of(oldTls, removed));
        when(components.findByTenant_IdAndSourceBom_IdOrderByNameAsc(tenant.getId(), to.getId()))
                .thenReturn(List.of(newTls, added));

        var result = new CbomDiffService(boms, components).diff(tenant, from.getId(), to.getId());

        assertThat(result.addedCount()).isEqualTo(1);
        assertThat(result.removedCount()).isEqualTo(1);
        assertThat(result.changedCount()).isEqualTo(1);
        assertThat(result.changes()).filteredOn(v -> v.changeType().equals("CHANGED"))
                .singleElement().satisfies(v -> assertThat(v.changedFields()).containsExactly("primitive", "keySize"));
    }

    private Tenant tenant() {
        Tenant value = new Tenant();
        value.setId(UUID.randomUUID());
        return value;
    }

    private BomIngestionRecord bom(Tenant tenant) {
        BomIngestionRecord value = new BomIngestionRecord();
        value.setTenant(tenant);
        value.setBomType(BomType.CBOM);
        ReflectionTestUtils.setField(value, "id", UUID.randomUUID());
        return value;
    }

    private CbomComponent component(Tenant tenant, BomIngestionRecord bom, String ref, String name,
                                    String primitive, Integer keySize) {
        CbomComponent value = new CbomComponent();
        value.setTenant(tenant);
        value.setSourceBom(bom);
        value.setBomRef(ref);
        value.setComponentFingerprint(ref);
        value.setName(name);
        value.setPrimitive(primitive);
        value.setKeySize(keySize);
        ReflectionTestUtils.setField(value, "id", UUID.randomUUID());
        return value;
    }
}
