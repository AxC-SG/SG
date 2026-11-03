package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.CbomRelationship;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.CbomRelationshipRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class CbomGraphServiceTest {
    @Mock CbomRelationshipRepository relationships;

    @Test
    void returnsTenantBoundedDeclaredAndObservedGraphWithStaleness() {
        Tenant tenant = new Tenant(); tenant.setId(UUID.randomUUID());
        UUID component = UUID.randomUUID(); UUID application = UUID.randomUUID();
        CbomRelationship edge = new CbomRelationship();
        edge.setTenant(tenant); edge.setSourceType("COMPONENT"); edge.setSourceId(component);
        edge.setTargetType("APPLICATION"); edge.setTargetId(application); edge.setRelationshipType("USED_BY");
        edge.setEvidenceKind("DECLARED"); edge.setValidUntil(Instant.now().minusSeconds(60));
        ReflectionTestUtils.setField(edge, "id", UUID.randomUUID());
        when(relationships.findAdjacent(eq(tenant.getId()), any(), eq(null))).thenReturn(List.of(edge), List.of());

        var result = new CbomGraphService(relationships).traverse(tenant, "component", component, 2, null, 100);

        assertThat(result.nodes()).hasSize(2);
        assertThat(result.edges()).singleElement().satisfies(v -> {
            assertThat(v.evidenceKind()).isEqualTo("DECLARED");
            assertThat(v.stale()).isTrue();
        });
    }

    @Test
    void rejectsUnboundedTraversalParameters() {
        Tenant tenant = new Tenant(); tenant.setId(UUID.randomUUID());
        CbomGraphService service = new CbomGraphService(relationships);
        assertThatThrownBy(() -> service.traverse(tenant, "COMPONENT", UUID.randomUUID(), 4, null, 100))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> service.traverse(tenant, "COMPONENT", UUID.randomUUID(), 1, null, 501))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
