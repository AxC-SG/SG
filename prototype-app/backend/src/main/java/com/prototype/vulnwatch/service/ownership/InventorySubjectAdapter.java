package com.prototype.vulnwatch.service.ownership;

import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Maps inventory assets to canonical ownership subjects (plan §7.2, §7.5) and records the link on the additive
 * {@code assets.ownership_subject_id} column. The asset's own type is its subject type; the asset ID is the
 * source object ID. Vulnerability adapter v1 derives a finding's subject from its affected asset only.
 */
@Component
public class InventorySubjectAdapter {

    private static final Map<String, String> SUBJECT_TYPE_BY_ASSET_TYPE = Map.of(
            "APPLICATION", "APPLICATION", "HOST", "HOST", "CONTAINER_IMAGE", "CONTAINER_IMAGE", "CLOUD_RESOURCE", "CLOUD_RESOURCE");

    private final JdbcTemplate jdbc;
    private final OwnershipSubjectService subjects;

    public InventorySubjectAdapter(JdbcTemplate jdbc, OwnershipSubjectService subjects) {
        this.jdbc = jdbc;
        this.subjects = subjects;
    }

    /** The asset's subject, registering it and linking the asset on first use. Empty when the asset does not exist. */
    @Transactional
    public Optional<UUID> subjectForAsset(UUID assetId) {
        List<Map<String, Object>> rows = jdbc.queryForList("SELECT type, ownership_subject_id FROM assets WHERE id = ?", assetId);
        if (rows.isEmpty()) return Optional.empty();
        UUID linked = (UUID) rows.get(0).get("ownership_subject_id");
        if (linked != null) return Optional.of(linked);
        String type = SUBJECT_TYPE_BY_ASSET_TYPE.get(String.valueOf(rows.get(0).get("type")));
        if (type == null) return Optional.empty();
        UUID subject = subjects.register(type, assetId.toString(), null).id();
        jdbc.update("UPDATE assets SET ownership_subject_id = ? WHERE id = ? AND ownership_subject_id IS NULL", subject, assetId);
        return Optional.of(subject);
    }

    /**
     * Registers and links subjects for up to {@code limit} unlinked assets. Software occurrences hang under their asset's
     * subject, so the CLOUD_BOM populate step runs this too (Phase 0B §3.3), even while CORE is still LEGACY.
     */
    @Transactional
    public int linkAssets(int limit) {
        subjects.registerUnlinkedAssets(limit);
        return jdbc.update("""
                UPDATE assets a SET ownership_subject_id = s.id FROM ownership_subject s
                 WHERE a.id IN (SELECT id FROM assets WHERE ownership_subject_id IS NULL
                                   AND type IN ('APPLICATION','HOST','CONTAINER_IMAGE','CLOUD_RESOURCE') ORDER BY id LIMIT ?)
                   AND s.subject_type = a.type AND s.source_object_id = a.id::text AND s.context_key = '' AND s.lifecycle_status = 'ACTIVE'
                """, limit);
    }

}
