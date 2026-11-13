package com.prototype.vulnwatch.controller;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;

/** Plan §5: every ownership endpoint declares a matrix action; none falls back to default authentication only. */
class OwnershipControllerSecurityTest {

    @Test
    void everyOwnershipEndpointIsGuardedByTheMatrix() {
        for (Class<?> controller : List.of(DirectoryController.class, OwnershipAdminController.class, OwnershipSubjectController.class,
                OwnershipReadController.class)) {
            List<Method> endpoints = Arrays.stream(controller.getDeclaredMethods()).filter(m -> m.isAnnotationPresent(GetMapping.class)
                    || m.isAnnotationPresent(PostMapping.class) || m.isAnnotationPresent(PatchMapping.class)
                    || m.isAnnotationPresent(DeleteMapping.class)).toList();
            assertThat(endpoints).as(controller.getSimpleName()).isNotEmpty();
            for (Method m : endpoints) {
                PreAuthorize guard = m.getAnnotation(PreAuthorize.class);
                assertThat(guard).as(controller.getSimpleName() + "." + m.getName()).isNotNull();
                assertThat(guard.value()).as(m.getName()).startsWith("@ownershipAuthorization.can('");
            }
        }
    }
}
