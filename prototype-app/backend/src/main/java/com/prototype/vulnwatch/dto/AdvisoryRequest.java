package com.prototype.vulnwatch.dto;

import java.util.List;

public record AdvisoryRequest(
        String externalId,
        String title,
        String description,
        Double cvssScore,
        String severity,
        List<AdvisoryRuleRequest> rules,
        Boolean withdrawn
) {
    public AdvisoryRequest(String externalId,String title,String description,Double cvssScore,String severity,List<AdvisoryRuleRequest> rules) {
        this(externalId,title,description,cvssScore,severity,rules,false);
    }
}
