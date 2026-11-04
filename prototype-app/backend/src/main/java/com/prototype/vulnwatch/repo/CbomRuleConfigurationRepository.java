package com.prototype.vulnwatch.repo;
import com.prototype.vulnwatch.domain.CbomRuleConfiguration;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;
public interface CbomRuleConfigurationRepository extends JpaRepository<CbomRuleConfiguration,UUID>{}
