package com.prototype.vulnwatch.service.cbom;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.*;
import com.prototype.vulnwatch.dto.CbomGovernanceDtos.*;
import com.prototype.vulnwatch.repo.*;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.RequestActor;
import com.prototype.vulnwatch.service.RequestActorService;
import java.math.BigDecimal;
import java.time.Instant;
import java.time.LocalDate;
import java.time.temporal.ChronoUnit;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CbomGovernanceService {
    private final CbomRuleConfigurationRepository configs;
    private final CbomComponentRepository components;
    private final CbomRiskFindingRepository findings;
    private final CbomAssessmentService assessments;
    private final RequestActorService actors;
    private final AuditEventService audit;
    private final ObjectMapper mapper;
    private CbomRulePackageRegistry registry;
    private CbomRulePackageService packages;
    private CbomRuleLifecycleStore lifecycle;

    public CbomGovernanceService(CbomRuleConfigurationRepository configs, CbomComponentRepository components,
            CbomRiskFindingRepository findings, CbomAssessmentService assessments, RequestActorService actors,
            AuditEventService audit, ObjectMapper mapper) {
        this.configs=configs;this.components=components;this.findings=findings;this.assessments=assessments;
        this.actors=actors;this.audit=audit;this.mapper=mapper;
    }

    private CbomRiskEngine riskEngine = new CbomRiskEngine(new ObjectMapper());
    private CbomRelationshipRepository relationships;

    @org.springframework.beans.factory.annotation.Autowired(required=false)
    public void setRelationships(CbomRelationshipRepository value){this.relationships=value;}
    private CbomIngestionService ingestion;
    private com.prototype.vulnwatch.repo.BomIngestionRecordRepository boms;

    @org.springframework.beans.factory.annotation.Autowired(required=false)
    public void setRuleEvaluation(CbomRiskEngine riskEngine,CbomIngestionService ingestion,com.prototype.vulnwatch.repo.BomIngestionRecordRepository boms){
        if(riskEngine!=null)this.riskEngine=riskEngine;this.ingestion=ingestion;this.boms=boms;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setRulePackages(CbomRulePackageRegistry registry,CbomRulePackageService packages,CbomRuleLifecycleStore lifecycle){
        this.registry=registry;this.packages=packages;this.lifecycle=lifecycle;
    }

    @Transactional(readOnly=true)
    public RuleConfiguration configuration(Tenant tenant){return response(tenant,configs.findById(tenant.getId()).orElseGet(()->defaults(tenant)));}

    /** Impact of a proposed configuration: rule and parameter diff against what is effective now, plus projected finding counts. */
    @Transactional(readOnly=true)
    public RuleImpactPreview preview(Tenant tenant, RuleConfigurationRequest request){
        CbomRulePackageRegistry.RulePackage target=target(tenant,request);
        Map<String,Integer> p=validate(target,request);
        CbomRuleConfiguration config=configs.findById(tenant.getId()).orElseGet(()->defaults(tenant));
        CbomRulePackageRegistry.RulePackage current;
        try{current=packages.resolve(config,Instant.now());}catch(RuntimeException unsupported){current=null;}
        Map<String,Integer> currentParameters=read(config);
        List<CbomComponent> active=components.findByTenant_IdAndActiveTrueOrderByNameAsc(tenant.getId());
        int[] projected=counts(active,p),now=counts(active,currentParameters);
        Map<String,String> before=new LinkedHashMap<>(),after=new LinkedHashMap<>();
        if(current!=null)current.rules().forEach(r->before.put(r.id(),r.mode()));
        target.rules().forEach(r->after.put(r.id(),r.mode()));
        List<String> added=after.keySet().stream().filter(k->!before.containsKey(k)).sorted().toList();
        List<String> removed=before.keySet().stream().filter(k->!after.containsKey(k)).sorted().toList();
        List<String> modes=after.entrySet().stream().filter(e->before.containsKey(e.getKey())&&!before.get(e.getKey()).equals(e.getValue()))
                .map(e->e.getKey()+": "+before.get(e.getKey())+" -> "+e.getValue()).sorted().toList();
        Map<String,List<Integer>> parameters=new LinkedHashMap<>();
        p.forEach((name,value)->{Integer previous=currentParameters.get(name);if(!java.util.Objects.equals(previous,value))parameters.put(name,java.util.Arrays.asList(previous,value));});
        return new RuleImpactPreview(active.size(),projected[0],projected[1],target.parameters().entrySet().stream()
                .map(v->v.getKey()+"="+v.getValue().min()+".."+v.getValue().max()).sorted().toList(),
                current==null?null:current.version(),target.version(),added,removed,modes,parameters,now[0],now[1]);
    }

    /** Projected counts from the real engine, so the preview matches what activation will raise. */
    /** Activation applies at once: active CBOMs are re-evaluated with the new thresholds in this transaction. */
    private int reevaluateActiveCboms(Tenant tenant){
        if(ingestion==null||boms==null)return 0;
        configs.flush();
        int count=0;
        for(BomIngestionRecord bom:boms.findByTenant_IdAndStatus(tenant.getId(),BomStatus.ACTIVE)){
            if(bom.getBomType()!=BomType.CBOM)continue;
            ingestion.reevaluate(tenant,bom);count++;
        }
        return count;
    }

    private int[] counts(List<CbomComponent> active,Map<String,Integer> p){
        CbomRiskEngine.RuleParameters parameters=CbomRiskEngine.RuleParameters.from(p);
        int rsa=0,expiring=0;
        for(CbomComponent c:active)for(var finding:riskEngine.evaluate(c,parameters)){
            if("CBOM-RSA-SMALL-KEY".equals(finding.getRuleId()))rsa++;
            if("CBOM-CERT-EXPIRING".equals(finding.getRuleId()))expiring++;}
        return new int[]{rsa,expiring};
    }

    @Transactional
    public RuleConfiguration update(Tenant tenant,RuleConfigurationRequest request){
        RequestActor actor=requireAdmin();
        String reason=required(request.reason(),"reason");
        String policy=required(request.versionPolicy(),"versionPolicy").toUpperCase(Locale.ROOT);
        if(!Set.of("FOLLOW_LATEST","PINNED").contains(policy))throw new IllegalArgumentException("Unsupported versionPolicy");
        CbomRuleConfiguration config=configs.findById(tenant.getId()).orElseGet(()->defaults(tenant));
        String before=currentVersion(config);
        if("PINNED".equals(policy)){
            Instant now=Instant.now();
            var pin=registry.find(config.getPackageId(),required(request.pinnedVersion(),"pinnedVersion"))
                    .orElseThrow(()->new IllegalArgumentException("Unknown rule package version: "+request.pinnedVersion()));
            if(pin.retired(now)||pin.deprecated(now))throw new IllegalArgumentException("Deprecated or retired rule package versions cannot be pinned");
        }
        CbomRulePackageRegistry.RulePackage target=target(tenant,request);
        Map<String,Integer> parameters=validate(target,request);
        config.setVersionPolicy(policy);config.setPinnedVersion("PINNED".equals(policy)?request.pinnedVersion():null);
        config.setPinState("CURRENT");config.setDeprecationNoticeAt(null);config.setUpgradeRequiredAt(null);
        config.setParametersJson(write(parameters));config.setUpdatedBy(actor.userId());config.touch();configs.save(config);
        int reevaluated=reevaluateActiveCboms(tenant);
        lifecycle.recordHistory(tenant.getId(),config.getPackageId(),"TENANT_UPDATE",before,target.version(),policy,actor.userId(),reason,config.getParametersJson(),
                "{\"reevaluatedCboms\":"+reevaluated+"}");
        audit.record("cbom.rules.updated","tenant",tenant.getId().toString(),"{\"reason\":"+quote(reason)+",\"versionPolicy\":\""+policy+"\",\"version\":"+quote(target.version())+"}");
        return response(tenant,config);
    }

    /**
     * Post-quantum readiness of active cryptographic assets, using the shared classifier and the
     * declared relationships so keys and protocols take the outcome of the algorithms they use.
     */
    @Transactional(readOnly=true)
    public PqcReadiness pqc(Tenant tenant){
        List<CbomComponent> values=components.findByTenant_IdAndActiveTrueOrderByNameAsc(tenant.getId());
        Map<UUID,CbomComponent> byId=new HashMap<>();values.forEach(c->byId.put(c.getId(),c));
        Map<UUID,List<UUID>> uses=new HashMap<>();
        if(relationships!=null&&!values.isEmpty())for(CbomRelationship edge:relationships.findAdjacent(tenant.getId(),byId.keySet(),null)){
            if("COMPONENT".equals(edge.getSourceType())&&"COMPONENT".equals(edge.getTargetType())&&!"APPLICATION_USES".equals(edge.getRelationshipType()))
                uses.computeIfAbsent(edge.getSourceId(),k->new ArrayList<>()).add(edge.getTargetId());
        }
        Map<CbomQuantumClassifier.Readiness,Integer> counts=new EnumMap<>(CbomQuantumClassifier.Readiness.class);
        List<ComponentReadiness> rows=new ArrayList<>();
        for(CbomComponent c:values){
            CbomQuantumClassifier.Result result=CbomQuantumClassifier.classify(c,uses,byId);
            counts.merge(result.readiness(),1,Integer::sum);
            String priority=switch(result.readiness()){
                case QUANTUM_VULNERABLE -> (c.getSensitivity()!=null&&!c.getSensitivity().isBlank())?"HIGH":"MEDIUM";
                case CLASSICALLY_WEAK -> "HIGH";
                default -> "LOW";
            };
            rows.add(new ComponentReadiness(c.getId(),c.getName(),c.getPrimitive(),result.readiness().name(),priority,result.reason()));
        }
        rows.sort(Comparator.comparing((ComponentReadiness v)->"HIGH".equals(v.migrationPriority())?0:"MEDIUM".equals(v.migrationPriority())?1:2).thenComparing(ComponentReadiness::name));
        return new PqcReadiness(values.size(),counts.getOrDefault(CbomQuantumClassifier.Readiness.QUANTUM_VULNERABLE,0),
                counts.getOrDefault(CbomQuantumClassifier.Readiness.PQC_READY,0),counts.getOrDefault(CbomQuantumClassifier.Readiness.UNKNOWN,0),
                rows.stream().limit(100).toList(),counts.getOrDefault(CbomQuantumClassifier.Readiness.QUANTUM_SAFE,0),
                counts.getOrDefault(CbomQuantumClassifier.Readiness.CLASSICALLY_WEAK,0));
    }

    @Transactional(readOnly=true)
    public GateResult gate(Tenant tenant,GateRequest request){
        var run=assessments.get(tenant,request.assessmentRunId());List<String> reasons=new ArrayList<>();
        BigDecimal minimum=request.minimumCompleteness()==null?new BigDecimal("0.80"):request.minimumCompleteness();
        if(minimum.compareTo(BigDecimal.ZERO)<0||minimum.compareTo(BigDecimal.ONE)>0)throw new IllegalArgumentException("minimumCompleteness must be between 0 and 1");
        if(run.completenessScore()==null||run.completenessScore().compareTo(minimum)<0)reasons.add("Completeness is below "+minimum);
        if("INVALID".equals(run.validationOutcome()))reasons.add("CBOM validation failed");
        Set<String> severities=request.failOnSeverities()==null?Set.of("CRITICAL","HIGH"):request.failOnSeverities().stream().map(String::toUpperCase).collect(java.util.stream.Collectors.toSet());
        findings.findBySourceBomId(run.bomId()).stream().filter(v->v.getStatus()==CbomFindingStatus.OPEN)
                .filter(v->severities.contains(v.getSeverity().name())).findAny().ifPresent(v->reasons.add("Open "+v.getSeverity()+" cryptographic findings exist"));
        String outcome="INVALID".equals(run.validationOutcome())?"INDETERMINATE":reasons.isEmpty()?"PASS":"FAIL";
        return new GateResult(outcome,run.id(),reasons,run.rulePackageDigest(),run.artifactChecksum());
    }

    /** Validates against the immutable package parameter schema; tenant rows cannot exceed its hard bounds. */
    private Map<String,Integer> validate(CbomRulePackageRegistry.RulePackage pkg,RuleConfigurationRequest request){
        Map<String,Integer> result=pkg.defaults();
        if(request.parameters()!=null)for(var entry:request.parameters().entrySet()){
            var parameter=pkg.parameters().get(entry.getKey());if(parameter==null)throw new IllegalArgumentException("Unsupported parameter: "+entry.getKey());
            if(entry.getValue()==null||entry.getValue()<parameter.min()||entry.getValue()>parameter.max())throw new IllegalArgumentException(entry.getKey()+" is outside safety bounds");result.put(entry.getKey(),entry.getValue());}
        return result;
    }
    /** The package a request would make effective: the requested pin, or the tenant's current effective package. */
    private CbomRulePackageRegistry.RulePackage target(Tenant tenant,RuleConfigurationRequest request){
        CbomRuleConfiguration config=configs.findById(tenant.getId()).orElseGet(()->defaults(tenant));
        if(request!=null&&"PINNED".equalsIgnoreCase(request.versionPolicy())&&request.pinnedVersion()!=null){
            return registry.find(config.getPackageId(),request.pinnedVersion()).orElseThrow(()->new IllegalArgumentException("Unknown rule package version: "+request.pinnedVersion()));
        }
        if(request!=null&&"FOLLOW_LATEST".equalsIgnoreCase(request.versionPolicy())&&"PINNED".equals(config.getVersionPolicy())){
            CbomRuleConfiguration following=defaults(tenant);following.setEffectiveVersion(config.getEffectiveVersion());
            return packages.resolve(following,Instant.now());
        }
        try{return packages.resolve(config,Instant.now());}
        catch(CbomRulePackageService.UnsupportedRulePackageException unsupported){
            return registry.generalDefault(config.getPackageId(),Instant.now()).orElseThrow(()->unsupported);
        }
    }
    private String currentVersion(CbomRuleConfiguration config){
        try{return packages.resolve(config,Instant.now()).version();}catch(RuntimeException unsupported){return config.getPinnedVersion();}
    }
    private CbomRuleConfiguration defaults(Tenant tenant){CbomRuleConfiguration c=new CbomRuleConfiguration();c.setTenantId(tenant.getId());return c;}
    private RuleConfiguration response(Tenant tenant,CbomRuleConfiguration c){
        Instant now=Instant.now();
        String effective=null;
        try{effective=packages.resolve(c,now).version();}catch(CbomRulePackageService.UnsupportedRulePackageException ignored){/* surfaced via pinState */}
        Map<String,String> statuses=new HashMap<>();
        lifecycle.availability(tenant.getId()).forEach(a->statuses.put(a.version(),a.status()));
        List<PackageVersion> versions=registry.all().stream().filter(p->p.packageId().equals(c.getPackageId()))
                .map(p->new PackageVersion(p.version(),p.title(),p.digest(),p.evaluatorMajor(),p.stage().name(),p.deprecatedAt(),p.retiresAt(),
                        !p.deprecated(now)&&!p.retired(now),statuses.get(p.version()))).toList();
        List<SelectionHistory> history=lifecycle.history(tenant.getId(),20).stream()
                .map(h->new SelectionHistory(h.id(),h.action(),h.fromVersion(),h.toVersion(),h.versionPolicy(),h.actor(),h.reason(),h.impactJson(),h.createdAt())).toList();
        return new RuleConfiguration(c.getPackageId(),c.getVersionPolicy(),c.getPinnedVersion(),read(c),c.getVersion(),c.getUpdatedBy(),
                effective,c.getPinState(),remediation(c),versions,history,rules(tenant,c,now));
    }
    /** Rules of the package that evaluates this workspace, with its thresholds filled in and its open findings counted. */
    private List<PackageRule> rules(Tenant tenant,CbomRuleConfiguration c,Instant now){
        CbomRulePackageRegistry.RulePackage pkg;
        try{pkg=packages.resolve(c,now);}
        catch(CbomRulePackageService.UnsupportedRulePackageException unsupported){
            pkg=registry.find(c.getPackageId(),c.getPinnedVersion()).or(()->registry.generalDefault(c.getPackageId(),now)).orElse(null);
        }
        if(pkg==null)return List.of();
        CbomRiskEngine.RuleParameters parameters=packages.parameters(tenant);
        Map<String,String> values=Map.of("minimumRsaBits",String.valueOf(parameters.minimumRsaBits()),
                "certificateExpiryWarningDays",String.valueOf(parameters.certificateExpiryWarningDays()));
        Map<String,Long> open=new HashMap<>();
        for(Object[] row:findings.countOpenByRule(tenant.getId()))open.put((String)row[0],((Number)row[1]).longValue());
        return pkg.rules().stream().map(r->new PackageRule(r.id(),r.version(),r.mode(),r.title(),r.severity(),r.category(),
                fill(r.condition(),values),fill(r.recommendation(),values),open.getOrDefault(r.id(),0L))).toList();
    }

    private static String fill(String template,Map<String,String> values){
        if(template==null)return null;
        String out=template;
        for(var entry:values.entrySet())out=out.replace("{"+entry.getKey()+"}",entry.getValue());
        return out;
    }

    private String remediation(CbomRuleConfiguration c){
        return switch(c.getPinState()==null?"CURRENT":c.getPinState()){
            case "UPGRADE_AVAILABLE" -> "A newer rule package is available. Pinned behaviour is unchanged until you select it.";
            case "DEPRECATED" -> "The pinned rule package is deprecated. Select a supported version before it retires.";
            case "UPGRADE_REQUIRED" -> "The pinned rule package has retired. It will move to the lowest compatible supported version after the grace period unless you select one.";
            case "UNSUPPORTED" -> "No supported rule package accepts this configuration. Assessment is paused and the last assessment is stale; choose a supported version or adjust parameters.";
            default -> null;
        };
    }
    private Map<String,Integer> read(CbomRuleConfiguration c){
        try{Map<String,Integer> v=mapper.readValue(c.getParametersJson(),new TypeReference<>(){});
            if(!v.isEmpty())return v;
            var pkg=registry.find(c.getPackageId(),currentVersion(c)).or(()->registry.generalDefault(c.getPackageId(),Instant.now()));
            return pkg.map(CbomRulePackageRegistry.RulePackage::defaults).orElse(v);
        }catch(Exception e){throw new IllegalStateException("Invalid stored CBOM rule configuration",e);}
    }
    private String write(Object v){try{return mapper.writeValueAsString(v);}catch(Exception e){throw new IllegalStateException(e);}}
    private RequestActor requireAdmin(){RequestActor a=actors.currentActor();if(!a.hasDirectTenantMembership()||!a.hasRole("TENANT_ADMIN"))throw new SecurityException("Direct tenant administrator membership is required");return a;}
    private String required(String v,String name){if(v==null||v.isBlank())throw new IllegalArgumentException(name+" is required");return v.trim();}
    private String upper(String v){return v==null?"":v.toUpperCase(Locale.ROOT);}
    private String quote(String v){try{return mapper.writeValueAsString(v);}catch(Exception e){return "\"redacted\"";}}
}
