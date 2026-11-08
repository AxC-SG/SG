package com.prototype.vulnwatch.migration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.HashMap;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ManagedOperatorEnrollmentTest {
    @Test
    void disabledModeRequiresNoEnrollmentInputs() {
        assertNull(ManagedOperatorEnrollment.configured(name -> "", false, false));
        var values = inputs();
        values.remove("APP_MANAGED_INSTALLATION_ENABLED");
        assertThrows(IllegalArgumentException.class, () -> configured(values));
    }

    @Test
    void rejectsLocalOrReportOnlyModeAndInvalidIdentityPairs() {
        var values = inputs();
        assertThrows(IllegalArgumentException.class,
                () -> ManagedOperatorEnrollment.configured(name -> values.getOrDefault(name, ""), true, false));
        assertThrows(IllegalArgumentException.class,
                () -> ManagedOperatorEnrollment.configured(name -> values.getOrDefault(name, ""), false, true));

        values.put("APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_SUBJECT", values.get("APP_MANAGED_INSTALLATION_OWNER_SUBJECT"));
        assertThrows(IllegalArgumentException.class, () -> configured(values));
        values.put("APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_SUBJECT", "admin-subject");
        values.put("APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_EMAIL", "owner@example.test");
        assertThrows(IllegalArgumentException.class, () -> configured(values));
        values.put("APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_EMAIL", "admin@example.test");
        values.put("APP_MANAGED_INSTALLATION_ISSUER", "https://cognito-idp.us-east-1.amazonaws.com/us-west-2_fixture");
        assertThrows(IllegalArgumentException.class, () -> configured(values));
    }

    @Test
    void canonicalEmailsHaveStableDigestsWhileChangedSubjectsDoNot() {
        var values = inputs();
        var spec = configured(values);
        assertEquals("owner@example.test", spec.owner().email());
        values.put("APP_MANAGED_INSTALLATION_OWNER_EMAIL", "owner@example.test");
        assertEquals(spec.digest(), configured(values).digest());
        values.put("APP_MANAGED_INSTALLATION_OWNER_SUBJECT", "changed-subject");
        assertNotEquals(spec.digest(), configured(values).digest());
    }

    static Map<String, String> inputs() {
        return new HashMap<>(Map.of(
                "APP_MANAGED_INSTALLATION_ENABLED", "true",
                "APP_MANAGED_INSTALLATION_ISSUER", "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_fixture",
                "APP_MANAGED_INSTALLATION_OWNER_EMAIL", "Owner@example.test",
                "APP_MANAGED_INSTALLATION_OWNER_SUBJECT", "owner-subject",
                "APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_EMAIL", "admin@example.test",
                "APP_MANAGED_INSTALLATION_INTERNAL_ADMIN_SUBJECT", "admin-subject"));
    }

    private static ManagedOperatorEnrollment.Spec configured(Map<String, String> values) {
        return ManagedOperatorEnrollment.configured(name -> values.getOrDefault(name, ""), false, false);
    }
}
