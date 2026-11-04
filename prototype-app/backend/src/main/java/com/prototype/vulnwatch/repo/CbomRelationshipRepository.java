package com.prototype.vulnwatch.repo;

import com.prototype.vulnwatch.domain.CbomRelationship;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.repository.query.Param;

public interface CbomRelationshipRepository extends JpaRepository<CbomRelationship, UUID> {
    @Modifying
    void deleteBySourceBom_Id(UUID sourceBomId);
    @Query("""
            select r from CbomRelationship r
            where r.tenant.id = :tenantId
              and (r.sourceId in :nodeIds or r.targetId in :nodeIds)
              and (:relationshipType is null or r.relationshipType = :relationshipType)
            order by r.id
            """)
    List<CbomRelationship> findAdjacent(@Param("tenantId") UUID tenantId,
                                        @Param("nodeIds") Collection<UUID> nodeIds,
                                        @Param("relationshipType") String relationshipType);
}
