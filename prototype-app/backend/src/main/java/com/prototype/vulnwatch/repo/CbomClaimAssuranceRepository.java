package com.prototype.vulnwatch.repo;
import com.prototype.vulnwatch.domain.CbomClaimAssurance;
import java.util.*;
import org.springframework.data.jpa.repository.JpaRepository;
public interface CbomClaimAssuranceRepository extends JpaRepository<CbomClaimAssurance,UUID>{ List<CbomClaimAssurance> findByAssessmentRun_IdOrderByClaimPathAsc(UUID runId); }
