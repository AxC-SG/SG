package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.repo.VulnerabilityIntelObservationRepository;
import java.util.Set;
import org.springframework.stereotype.Service;

@Service
public class TenantApprovedIntelligenceService {
    private final VulnerabilityIntelObservationRepository observations;
    private final VulnerabilityIntelSummaryAssembler assembler;
    public TenantApprovedIntelligenceService(VulnerabilityIntelObservationRepository observations,VulnerabilityIntelSummaryAssembler assembler) {
        this.observations=observations;this.assembler=assembler;
    }
    public Vulnerability resolve(Vulnerability canonical,Set<String> enabled) {
        // A fresh detached value avoids inherited disabled-source fields and dirty
        // updates to the central canonical entity while evaluating tenant policy.
        Vulnerability resolved=new Vulnerability();
        resolved.setId(canonical.getId());resolved.setExternalId(canonical.getExternalId());resolved.setSource(null);
        var eligible=observations.findByVulnerabilityOrderByLastSeenAtDesc(canonical).stream()
                .filter(observation -> IntelligenceSourceRegistry.enabled(observation.getSourceSystem(),enabled)).toList();
        assembler.mergeCanonicalVulnerability(resolved,eligible);
        var metrics=com.prototype.vulnwatch.util.CvssUtil.parse(resolved.getCvssVector());
        if(metrics!=null) {
            resolved.setCvssVersion(metrics.version());resolved.setAttackVector(metrics.attackVector());
            resolved.setAttackComplexity(metrics.attackComplexity());resolved.setPrivilegesRequired(metrics.privilegesRequired());
            resolved.setUserInteraction(metrics.userInteraction());resolved.setScope(metrics.scope());
        }
        if(enabled.contains("kev")) {
            resolved.setKevDateAdded(canonical.getKevDateAdded());resolved.setKevDueDate(canonical.getKevDueDate());resolved.setKevRequiredAction(canonical.getKevRequiredAction());
        }
        return resolved;
    }
}
