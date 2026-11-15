package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.UUID;
import org.junit.jupiter.api.Test;

/** The software occurrence key normalizes for itself, whatever each writer stored (Phase 0B §3.2, R2). */
class OccurrenceKeyTest {

    private static final String LODASH = OccurrenceKey.sourceObjectId("npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21");

    @Test
    void ecosystemNameAndPurlIgnoreCaseAndSurroundingSpaces() {
        assertThat(OccurrenceKey.sourceObjectId(" NPM", "Lodash ", "4.17.21 ", "PKG:NPM/Lodash@4.17.21")).isEqualTo(LODASH);
        assertThat(LODASH).startsWith("pkg:").hasSize(4 + 64);
    }

    @Test
    void theVersionKeepsItsCaseAndEveryFieldCounts() {
        assertThat(OccurrenceKey.sourceObjectId("npm", "lodash", "4.17.21-RC", "")).isNotEqualTo(
                OccurrenceKey.sourceObjectId("npm", "lodash", "4.17.21-rc", ""));
        assertThat(OccurrenceKey.sourceObjectId("npm", "lodash", "4.17.22", "pkg:npm/lodash@4.17.21")).isNotEqualTo(LODASH);
        assertThat(OccurrenceKey.sourceObjectId("pypi", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21")).isNotEqualTo(LODASH);
    }

    @Test
    void missingValuesAreEmptyAndTheContextIsTheAsset() {
        assertThat(OccurrenceKey.sourceObjectId(null, "lodash", null, null)).isEqualTo(OccurrenceKey.sourceObjectId("", "lodash", "", ""));
        UUID asset = UUID.fromString("00000000-0000-4000-8000-000000000001");
        assertThat(OccurrenceKey.contextKey(asset)).isEqualTo("asset:00000000-0000-4000-8000-000000000001");
    }
}
