package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.dto.CbomAssessmentResponse;
import com.prototype.vulnwatch.repo.*;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.time.Instant;
import java.util.*;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CbomAssessmentService {
    private final BomIngestionRecordRepository boms;
    private final CbomComponentRepository components;
    private final CbomRiskFindingRepository findings;
    private final CbomAssessmentRunRepository runs;
    private final CbomValidationIssueRepository issues;
    private final CbomClaimAssuranceRepository assurances;
    private final CbomRulePackageService packages;
    private CbomFindingMirrorService mirror;
    @org.springframework.beans.factory.annotation.Autowired(required=false) public void setMirror(CbomFindingMirrorService value){mirror=value;}
    private com.prototype.vulnwatch.service.FindingDeltaQueueService deltaQueue;
    private CbomContradictionService contradictions;
    @org.springframework.beans.factory.annotation.Autowired(required=false) public void setContradictions(CbomContradictionService value){contradictions=value;}
    @org.springframework.beans.factory.annotation.Autowired(required=false) public void setDeltaQueue(com.prototype.vulnwatch.service.FindingDeltaQueueService value){deltaQueue=value;}

    public CbomAssessmentService(BomIngestionRecordRepository boms,CbomComponentRepository components,
            CbomRiskFindingRepository findings,CbomAssessmentRunRepository runs,
            CbomValidationIssueRepository issues,CbomClaimAssuranceRepository assurances,
            CbomRulePackageService packages){
        this.boms=boms;this.components=components;this.findings=findings;this.runs=runs;
        this.issues=issues;this.assurances=assurances;this.packages=packages;
    }

    @Transactional
    public CbomAssessmentResponse assess(Tenant tenant,UUID bomId){
        BomIngestionRecord bom=boms.findById(bomId).filter(v->v.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(()->new IllegalArgumentException("CBOM artifact not found"));
        if(bom.getBomType()!=BomType.CBOM) throw new IllegalArgumentException("Assessment requires a CBOM artifact");
        CbomRulePackageService.EffectivePackage pkg=packages.effective(tenant);
        Optional<CbomAssessmentRun> prior=runs.findFirstByBom_IdAndRulePackageDigestAndEvaluatorVersionAndStatusOrderByCreatedAtDesc(
                bomId,pkg.digest(),pkg.evaluatorVersion(),"SUCCEEDED");
        if(prior.isPresent()) return response(prior.get());

        CbomAssessmentRun run=new CbomAssessmentRun(); run.setTenant(tenant);run.setBom(bom);
        run.setArtifactChecksum(Objects.requireNonNullElse(bom.getChecksumSha256(),"unknown"));
        run.setRulePackageId(pkg.id());run.setRulePackageVersion(pkg.version());run.setRulePackageDigest(pkg.digest());
        run.setEvaluatorVersion(pkg.evaluatorVersion());run.setStatus("RUNNING");run.setStartedAt(Instant.now());run=runs.save(run);

        List<CbomComponent> items=components.findByTenant_IdAndSourceBom_IdAndActiveTrueOrderByRiskScoreDescNameAsc(tenant.getId(),bomId);
        List<CbomValidationIssue> validation=new ArrayList<>();
        List<CbomClaimAssurance> claims=new ArrayList<>();
        int present=0, expected=0;
        for(int index=0;index<items.size();index++){
            CbomComponent component=items.get(index);
            String base="/cryptoProperties/"+index;
            if(component.getAssetType()==null||component.getAssetType()==CbomAssetType.UNKNOWN)
                validation.add(issue(tenant,run,"CBOM_ASSET_TYPE_UNKNOWN","WARNING",base+"/assetType","Cryptographic asset type is missing or unsupported."));
            expected++; present+=claim(tenant,run,claims,component,base+"/name",component.getName(),"Component identity is declared.");
            switch(component.getAssetType()==null?CbomAssetType.UNKNOWN:component.getAssetType()){
                case ALGORITHM,PROTOCOL -> {expected++;present+=claim(tenant,run,claims,component,base+"/primitive",component.getPrimitive(),"Cryptographic primitive is declared.");}
                case CERTIFICATE -> {expected++;present+=claim(tenant,run,claims,component,base+"/notAfter",component.getNotAfter(),"Certificate expiry is declared.");}
                case RELATED_CRYPTO_MATERIAL -> {expected++;present+=claim(tenant,run,claims,component,base+"/usedIn",component.getUsedIn(),"Material usage is declared.");}
                case UNKNOWN -> { }
            }
        }
        if(items.isEmpty()) validation.add(issue(tenant,run,"CBOM_EMPTY","ERROR","/cryptoProperties","No cryptographic assets were available for assessment."));
        issues.saveAll(validation);assurances.saveAllAndFlush(claims);
        if(contradictions!=null)contradictions.detect(tenant.getId(),bomId);
        List<UUID> findingIds=findings.findIdsBySourceBomId(bomId);
        long findingCount=findingIds.size();
        BigDecimal completeness=expected==0?BigDecimal.ZERO:BigDecimal.valueOf((double)present/expected).setScale(5,RoundingMode.HALF_UP);
        long unknown=claims.stream().filter(c->"UNKNOWN".equals(c.getAssuranceLevel())).count();
        BigDecimal confidence=claims.isEmpty()?BigDecimal.ZERO:BigDecimal.valueOf((double)(claims.size()-unknown)/claims.size()).setScale(5,RoundingMode.HALF_UP);
        run.setComponentCount(items.size());run.setFindingCount(Math.toIntExact(findingCount));
        run.setCompletenessScore(completeness);run.setConfidenceScore(confidence);
        run.setValidationOutcome(validation.stream().anyMatch(v->"ERROR".equals(v.getSeverity()))?"INVALID":
                validation.isEmpty()?"VALID":"VALID_WITH_WARNINGS");
        run.setStatus("SUCCEEDED");run.setCompletedAt(Instant.now());runs.save(run);
        // The run changes the explainability evidence of each mirrored finding; publish per-finding deltas.
        if(deltaQueue!=null)deltaQueue.enqueueCbomDeltas(tenant.getId(),findingIds,"cbom-assessment");
        else if(mirror!=null)mirror.syncTenant(tenant);
        return response(run);
    }

    @Transactional(readOnly=true)
    public List<CbomAssessmentResponse> list(Tenant tenant,UUID bomId){
        return runs.findByTenant_IdAndBom_IdOrderByCreatedAtDesc(tenant.getId(),bomId,PageRequest.of(0,50)).stream().map(this::response).toList();
    }

    @Transactional(readOnly=true)
    public CbomAssessmentResponse get(Tenant tenant,UUID runId){
        return response(runs.findById(runId).filter(v->v.getTenant().getId().equals(tenant.getId()))
                .orElseThrow(()->new IllegalArgumentException("CBOM assessment not found")));
    }

    private int claim(Tenant tenant,CbomAssessmentRun run,List<CbomClaimAssurance> target,CbomComponent component,String path,Object value,String declared){
        CbomClaimAssurance claim=new CbomClaimAssurance();claim.setTenant(tenant);claim.setAssessmentRun(run);claim.setComponent(component);claim.setClaimPath(path);
        boolean present=value!=null&&!String.valueOf(value).isBlank();claim.setAssuranceLevel(present?"DECLARED":"UNKNOWN");claim.setEvidenceState("SUPPORTED");
        claim.setExplanation(present?declared:"The CBOM did not declare this important claim; no failure is inferred.");target.add(claim);return present?1:0;
    }
    private CbomValidationIssue issue(Tenant tenant,CbomAssessmentRun run,String code,String severity,String pointer,String message){
        CbomValidationIssue issue=new CbomValidationIssue();issue.setTenant(tenant);issue.setAssessmentRun(run);issue.setCode(code);issue.setSeverity(severity);issue.setJsonPointer(pointer);issue.setMessage(message);return issue;
    }
    private CbomAssessmentResponse response(CbomAssessmentRun run){
        return new CbomAssessmentResponse(run.getId(),run.getBom().getId(),run.getBom().getPreviousBomId(),run.getArtifactChecksum(),run.getRulePackageId(),run.getRulePackageVersion(),run.getRulePackageDigest(),run.getEvaluatorVersion(),run.getStatus(),run.getValidationOutcome(),run.getComponentCount(),run.getFindingCount(),run.getConfidenceScore(),run.getCompletenessScore(),run.getStartedAt(),run.getCompletedAt(),
                issues.findByAssessmentRun_IdOrderBySeverityDescCodeAsc(run.getId()).stream().map(v->new CbomAssessmentResponse.ValidationIssue(v.getId(),v.getCode(),v.getSeverity(),v.getJsonPointer(),v.getMessage())).toList(),
                assurances.findByAssessmentRun_IdOrderByClaimPathAsc(run.getId()).stream().map(v->new CbomAssessmentResponse.ClaimAssurance(v.getId(),v.getComponent()==null?null:v.getComponent().getId(),v.getClaimPath(),v.getAssuranceLevel(),v.getEvidenceState(),v.getExplanation())).toList());
    }
}
