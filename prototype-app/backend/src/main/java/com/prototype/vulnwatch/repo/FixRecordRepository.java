package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.FixRecord;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface FixRecordRepository extends JpaRepository<FixRecord, UUID> {

    List<FixRecord> findByCveIdOrderByCreatedAtAsc(String cveId);

    java.util.Optional<FixRecord> findByFixTypeAndExternalKey(String fixType, String externalKey);

    @Query(
            value = """
                    SELECT *
                    FROM fix_records f
                    WHERE EXISTS (
                        SELECT 1
                        FROM jsonb_array_elements(coalesce(f.software_entities, '[]'::jsonb)) AS elem
                        WHERE upper(coalesce(elem->>'name', '')) LIKE upper(concat('%', :software, '%'))
                      )
                    ORDER BY f.created_at ASC
                    """,
            nativeQuery = true
    )
    List<FixRecord> findBySoftwareNameContaining(@Param("software") String software);

    @Modifying
    void deleteByCveId(String cveId);

    /** Workbench regeneration replaces only its own (unmanaged) records. */
    @Modifying
    void deleteByCveIdAndManagedFalse(String cveId);
}
