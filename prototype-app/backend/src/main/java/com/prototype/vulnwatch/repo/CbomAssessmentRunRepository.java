package com.prototype.vulnwatch.repo;
import com.prototype.vulnwatch.domain.CbomAssessmentRun;
import java.util.*;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
public interface CbomAssessmentRunRepository extends JpaRepository<CbomAssessmentRun,UUID> {
    List<CbomAssessmentRun> findByTenant_IdAndBom_IdOrderByCreatedAtDesc(UUID tenantId,UUID bomId,Pageable pageable);
    boolean existsByBom_IdAndStatusIn(UUID bomId,Collection<String> statuses);
    Optional<CbomAssessmentRun> findFirstByBom_IdAndRulePackageDigestAndEvaluatorVersionAndStatusOrderByCreatedAtDesc(UUID bomId,String digest,String evaluatorVersion,String status);
    Optional<CbomAssessmentRun> findFirstByTenant_IdAndBom_IdAndStatusOrderByCreatedAtDesc(UUID tenantId,UUID bomId,String status);
    /** Artifacts that already have a successful run under the given package digest and evaluator. */
    @org.springframework.data.jpa.repository.Query("""
        select distinct r.bom.id from CbomAssessmentRun r
         where r.tenant.id = :tenantId and r.rulePackageDigest = :digest
           and r.evaluatorVersion = :evaluatorVersion and r.status = 'SUCCEEDED'
        """)
    Set<UUID> findAssessedBomIds(@org.springframework.data.repository.query.Param("tenantId") UUID tenantId,
            @org.springframework.data.repository.query.Param("digest") String digest,
            @org.springframework.data.repository.query.Param("evaluatorVersion") String evaluatorVersion);
}
