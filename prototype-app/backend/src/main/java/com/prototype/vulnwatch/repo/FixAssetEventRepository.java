package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.FixAssetEvent;
import java.time.Instant;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface FixAssetEventRepository extends JpaRepository<FixAssetEvent, UUID> {
    @Modifying
    @Query("delete from FixAssetEvent e where e.occurredAt < :cutoff")
    int deleteOlderThan(@Param("cutoff") Instant cutoff);
}
