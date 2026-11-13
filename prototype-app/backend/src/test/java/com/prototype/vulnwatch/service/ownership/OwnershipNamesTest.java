package com.prototype.vulnwatch.service.ownership;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class OwnershipNamesTest {

    @Test
    void normalizesWhitespaceWidthAndCase() {
        assertThat(OwnershipNames.display("  Payments \t  Platform ")).isEqualTo("Payments Platform");
        assertThat(OwnershipNames.key("ＰＡＹ")).isEqualTo("pay");
        assertThat(OwnershipNames.key("Payments Platform")).isEqualTo(OwnershipNames.key("PAYMENTS   platform"));
    }

    @Test
    void rejectsBlankLongAndControlInput() {
        for (String bad : new String[] {null, "", "   ", "a\u0000b", "x".repeat(201)}) {
            assertThatThrownBy(() -> OwnershipNames.display(bad)).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
