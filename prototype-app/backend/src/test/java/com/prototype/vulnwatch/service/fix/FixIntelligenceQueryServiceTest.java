package com.prototype.vulnwatch.service.fix;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Test;

class FixIntelligenceQueryServiceTest {

    @Test
    void percentIsZeroWhenThereIsNothingToCount() {
        assertThat(FixIntelligenceQueryService.percent(0, 0)).isZero();
        assertThat(FixIntelligenceQueryService.percent(3, 0)).isZero();
        assertThat(FixIntelligenceQueryService.percent(1, 3)).isEqualTo(33);
    }

    @Test
    void coverageIsCappedAndNullWhenNothingApplies() {
        assertThat(FixIntelligenceQueryService.coverage(0, 0)).isNull();
        assertThat(FixIntelligenceQueryService.coverage(4, 9)).isEqualTo(100);
        assertThat(FixIntelligenceQueryService.coverage(4, 1)).isEqualTo(25);
    }

    @Test
    void displayIdDropsTheProviderPrefix() {
        UUID id = UUID.fromString("0a1b2c3d-0000-0000-0000-000000000000");
        assertThat(FixIntelligenceQueryService.displayId("SCCM:16801234", id)).isEqualTo("16801234");
        assertThat(FixIntelligenceQueryService.displayId("KB5034441", id)).isEqualTo("KB5034441");
        assertThat(FixIntelligenceQueryService.displayId(null, id)).isEqualTo("FIX-0A1B2C3D");
    }

    @Test
    void viewsSeparatePatchesFromControls() {
        assertThat(FixIntelligenceQueryService.VIEW_TYPES.get("patches")).containsExactlyInAnyOrder("PATCH", "UPGRADE");
        assertThat(FixIntelligenceQueryService.VIEW_TYPES.get("compensating-controls")).containsExactly("COMPENSATING_CONTROL");
        assertThat(FixIntelligenceQueryService.VIEW_TYPES.get("all")).doesNotContain("NO_FIX");
        assertThat(FixIntelligenceQueryService.originLabel("PATCH_TOOL")).isEqualTo("Patch tool");
    }
}
