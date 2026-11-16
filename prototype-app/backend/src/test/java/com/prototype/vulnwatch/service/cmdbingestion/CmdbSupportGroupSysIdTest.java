package com.prototype.vulnwatch.service.cmdbingestion;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.util.Map;
import org.junit.jupiter.api.Test;

/** Phase 0B §1.8: the CMDB sync keeps the support group's reference sys_id for both Table API field shapes. */
class CmdbSupportGroupSysIdTest {

    private static final String GROUP = "8a4dde73c6112278017a6a4baf547aa7";

    @Test
    void displayValueAllRowsCarryTheReferenceBesideTheName() {
        // ServiceNowCmdbSyncService.flattenRow of {"display_value":"Payments Support","value":"<sys_id>"}.
        var row = new CmdbHostInventorySupportService.ImportedRow(Map.of(
                "installed_on_support_group", "Payments Support",
                "installed_on_support_group_display_value", "Payments Support",
                "installed_on_support_group_value", GROUP,
                "installed_on_support_group_sys_id", GROUP));
        assertEquals(GROUP, CmdbInventoryIngestionRunner.supportGroupSysId(row));
    }

    @Test
    void rawValueRowsUseTheFieldItselfWhenItIsASysId() {
        var row = new CmdbHostInventorySupportService.ImportedRow(Map.of("support_group", GROUP.toUpperCase()));
        assertEquals(GROUP, CmdbInventoryIngestionRunner.supportGroupSysId(row));
    }

    @Test
    void aDisplayNameIsNeverTakenForASysId() {
        var row = new CmdbHostInventorySupportService.ImportedRow(Map.of("installed_on_support_group", "Payments Support"));
        assertNull(CmdbInventoryIngestionRunner.supportGroupSysId(row));
    }
}
