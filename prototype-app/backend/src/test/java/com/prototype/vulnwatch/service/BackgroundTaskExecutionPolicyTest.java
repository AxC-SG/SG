package com.prototype.vulnwatch.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class BackgroundTaskExecutionPolicyTest {

    @Test
    void rejectsUnknownAndBlankRoles() {
        for (String role : new String[] {null, "   ", "unexpected"}) {
            assertThatThrownBy(() -> new BackgroundTaskExecutionPolicy(role)).isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void blocksBackgroundTasksForApiAndSchemaMigratorRoles() {
        assertThat(BackgroundTaskExecutionPolicy.forRole("api").allowsBackgroundTask("queue.poll")).isFalse();
        assertThat(BackgroundTaskExecutionPolicy.forRole("schema-migrator").allowsBackgroundTask("queue.poll"))
                .isFalse();
        assertThat(BackgroundTaskExecutionPolicy.forRole("worker").allowsBackgroundTask("queue.poll")).isTrue();
        assertThat(BackgroundTaskExecutionPolicy.allowAll().allowsBackgroundTask("queue.poll")).isTrue();
    }
}
