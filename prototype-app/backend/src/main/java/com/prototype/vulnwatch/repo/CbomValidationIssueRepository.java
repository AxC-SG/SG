package com.prototype.vulnwatch.repo;
import com.prototype.vulnwatch.domain.CbomValidationIssue;
import java.util.*;
import org.springframework.data.jpa.repository.JpaRepository;
public interface CbomValidationIssueRepository extends JpaRepository<CbomValidationIssue,UUID>{ List<CbomValidationIssue> findByAssessmentRun_IdOrderBySeverityDescCodeAsc(UUID runId); }
