package com.prototype.vulnwatch.service.patch.sccm;

import static org.assertj.core.api.Assertions.assertThat;

import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.service.patch.PatchSnapshot;
import com.prototype.vulnwatch.service.patch.sccm.SccmPatchProvider.SccmPatchMapper;
import com.prototype.vulnwatch.service.patch.sccm.SccmPatchProvider.Schedule;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class SccmPatchMapperTest {

    private static final Instant NOW = Instant.parse("2026-10-28T12:00:00Z");

    @Test
    void mapsSeverityCodes() {
        assertThat(SccmPatchMapper.severity("10")).isEqualTo("CRITICAL");
        assertThat(SccmPatchMapper.severity("8")).isEqualTo("HIGH");
        assertThat(SccmPatchMapper.severity("6")).isEqualTo("MEDIUM");
        assertThat(SccmPatchMapper.severity("2")).isEqualTo("LOW");
        assertThat(SccmPatchMapper.severity("0")).isNull();
        assertThat(SccmPatchMapper.vendorSeverity("8")).isEqualTo("Important");
    }

    @Test
    void requiredUpdateIsScheduledInProgressOrMissing() {
        Schedule future = new Schedule("D1", NOW.plusSeconds(3600), NOW.plusSeconds(7200));
        Schedule open = new Schedule("D1", NOW.minusSeconds(3600), NOW.plusSeconds(3600));
        Schedule overdue = new Schedule("D1", NOW.minusSeconds(7200), NOW.minusSeconds(3600));

        assertThat(SccmPatchMapper.required("1", "9", null, NOW).status()).isEqualTo(FixAssetStatus.MISSING);
        assertThat(SccmPatchMapper.required("1", "9", future, NOW).status()).isEqualTo(FixAssetStatus.SCHEDULED);
        assertThat(SccmPatchMapper.required("1", "9", open, NOW).status()).isEqualTo(FixAssetStatus.IN_PROGRESS);
        assertThat(SccmPatchMapper.required("1", "9", overdue, NOW).status()).isEqualTo(FixAssetStatus.MISSING);
    }

    @Test
    void snapshotMapsDevicesUpdatesAndStates() {
        PatchSnapshot snapshot = SccmPatchMapper.snapshot(
                List.of(Map.of("resource_id", "16777220", "name", "WS-01", "os_name", "Windows 11")),
                List.of(Map.of("ci_id", "9", "article_id", "5034441", "title", "2026-10 Cumulative Update",
                        "severity", "10", "is_superseded", "0", "date_posted", "2026-10-14 17:00:00.000")),
                List.of(Map.of("ci_id", "9", "resource_id", "16777220", "status", "3"),
                        Map.of("ci_id", "9", "resource_id", "16777221", "status", "2"),
                        Map.of("ci_id", "9", "resource_id", "16777222", "status", "1")),
                List.of(), Map.of(), NOW, true, List.of());

        assertThat(snapshot.devices()).singleElement().extracting(PatchSnapshot.Device::hostname).isEqualTo("WS-01");
        assertThat(snapshot.patches()).singleElement().satisfies(patch -> {
            assertThat(patch.severity()).isEqualTo("CRITICAL");
            assertThat(patch.superseded()).isFalse();
            assertThat(patch.releaseDate()).isEqualTo(Instant.parse("2026-10-14T17:00:00Z"));
        });
        // Status 1 (not required) is not an applicability record.
        assertThat(snapshot.statuses()).extracting(PatchSnapshot.Status::status)
                .containsExactly(FixAssetStatus.INSTALLED, FixAssetStatus.MISSING);
    }
}
