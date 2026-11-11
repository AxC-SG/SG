package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.BomIngestionRecord;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.CbomFindingStatus;
import com.prototype.vulnwatch.domain.BomEvidenceState;
import com.prototype.vulnwatch.domain.CbomRiskFinding;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.CbomComponentRepository;
import com.prototype.vulnwatch.repo.CbomRiskFindingRepository;
import java.io.IOException;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.springframework.stereotype.Service;

@Service
public class CbomIngestionService {

    private final CbomComponentParser parser;
    private final CbomRiskEngine riskEngine;
    private final CbomRiskScorer riskScorer;
    private final CbomPostureService postureService;
    private final CbomComponentRepository componentRepository;
    private final CbomRiskFindingRepository findingRepository;
    private final CbomFindingMirrorService findingMirror;
    private CbomSecretDetector secretDetector = new CbomSecretDetector();
    private CbomRelationshipExtractor relationshipExtractor;
    private com.prototype.vulnwatch.repo.CbomRelationshipRepository relationshipRepository;
    private com.prototype.vulnwatch.service.IngestionJobService ingestionJobService;
    private com.prototype.vulnwatch.service.FindingDeltaQueueService deltaQueue;

    /** Mirror changes are published as CBOM_DELTA in the ingest transaction instead of a tenant scan. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setDeltaQueue(com.prototype.vulnwatch.service.FindingDeltaQueueService value) {
        this.deltaQueue = value;
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setIngestionJobService(com.prototype.vulnwatch.service.IngestionJobService value) {
        this.ingestionJobService = value;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setSecretDetector(CbomSecretDetector value) { this.secretDetector = value; }

    private com.prototype.vulnwatch.service.AuditEventService audit;
    private CbomRulePackageService rulePackages;

    /** Rules evaluate with the tenant's parameters; without the package service the baseline defaults apply. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setRulePackages(CbomRulePackageService value) { this.rulePackages = value; }

    private CbomRiskEngine.RuleParameters parameters(Tenant tenant) {
        return rulePackages == null ? CbomRiskEngine.DEFAULTS : rulePackages.parameters(tenant);
    }

    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setAuditEventService(com.prototype.vulnwatch.service.AuditEventService value) { this.audit = value; }

    @org.springframework.beans.factory.annotation.Autowired
    public void setRelationshipSupport(CbomRelationshipExtractor extractor,
            com.prototype.vulnwatch.repo.CbomRelationshipRepository repository) {
        this.relationshipExtractor=extractor;this.relationshipRepository=repository;
    }

    public CbomIngestionService(
            CbomComponentParser parser,
            CbomRiskEngine riskEngine,
            CbomRiskScorer riskScorer,
            CbomPostureService postureService,
            CbomComponentRepository componentRepository,
            CbomRiskFindingRepository findingRepository,
            CbomFindingMirrorService findingMirror
    ) {
        this.parser = parser;
        this.riskEngine = riskEngine;
        this.riskScorer = riskScorer;
        this.postureService = postureService;
        this.componentRepository = componentRepository;
        this.findingRepository = findingRepository;
        this.findingMirror = findingMirror;
    }

    public void validateContent(byte[] content) throws IOException {
        secretDetector.rejectSecretBearing(content);
        if (parser.parse(content).isEmpty()) {
            throw new IOException("No CBOM cryptographic assets could be extracted from the submitted document");
        }
    }

    public CbomIngestionResult ingest(Tenant tenant, Asset asset, BomIngestionRecord sourceBom, byte[] content) throws IOException {
        return ingestPrepared(tenant, asset, sourceBom, prepare(content));
    }

    public PreparedContent prepare(byte[] content) throws IOException {
        CbomSecretDetector.ScanResult secrets = secretDetector.rejectSecretBearing(content);
        List<CbomParsedComponent> parsedComponents = parser.parse(content);
        var relationships = relationshipExtractor == null ? List.<CbomRelationshipExtractor.DeclaredRelationship>of()
                : relationshipExtractor.extract(content);
        return new PreparedContent(secrets, List.copyOf(parsedComponents), List.copyOf(relationships));
    }

    public CbomIngestionResult ingestPrepared(Tenant tenant, Asset asset, BomIngestionRecord sourceBom,
                                              PreparedContent content) {
        recordSecretWarnings(sourceBom, content.secrets());
        List<CbomParsedComponent> parsedComponents = content.components();
        CbomRiskEngine.RuleParameters ruleParameters = parameters(tenant);
        int findingCount = 0;
        List<java.util.UUID> touchedComponents = new java.util.ArrayList<>();
        for (CbomParsedComponent parsed : parsedComponents) {
            CbomComponent component = componentRepository
                    .findByTenant_IdAndSourceBom_IdAndComponentFingerprint(
                            tenant.getId(),
                            sourceBom.getId(),
                            parsed.componentFingerprint()
                    )
                    .orElseGet(CbomComponent::new);
            applyParsed(component, tenant, asset, sourceBom, parsed);
            component = componentRepository.save(component);

            List<CbomRiskFinding> evaluated = riskEngine.evaluate(component, ruleParameters);
            component.setRiskScore(riskScorer.scoreComponent(component, evaluated));
            component = componentRepository.save(component);
            reconcileFindings(tenant, component, evaluated);
            touchedComponents.add(component.getId());
            findingCount += evaluated.size();
        }
        persistDeclaredRelationships(tenant,sourceBom,asset,content.relationships());
        postureService.rollUp(tenant, asset, sourceBom);
        publishMirrorDeltas(tenant, touchedComponents.isEmpty() ? List.of() : findingRepository
                .findByTenant_IdAndComponent_IdIn(tenant.getId(), touchedComponents).stream()
                .map(CbomRiskFinding::getId).toList(), "cbom-ingest");
        if (ingestionJobService != null) {
            ingestionJobService.enqueueCbomAssessmentJob(tenant, sourceBom.getId(), "cbom-ingestion");
        }
        return new CbomIngestionResult(parsedComponents.size(), findingCount);
    }

    public record PreparedContent(CbomSecretDetector.ScanResult secrets, List<CbomParsedComponent> components,
                                  List<CbomRelationshipExtractor.DeclaredRelationship> relationships) { }

    private void persistDeclaredRelationships(Tenant tenant,BomIngestionRecord sourceBom,Asset asset,
            List<CbomRelationshipExtractor.DeclaredRelationship> relationships){
        if(relationshipExtractor==null||relationshipRepository==null)return;
        java.util.Map<String,CbomComponent> byRef=new java.util.HashMap<>();
        List<CbomComponent> active=componentRepository.findByTenant_IdAndSourceBom_IdAndActiveTrue(tenant.getId(),sourceBom.getId());
        for(CbomComponent component:active)if(component.getBomRef()!=null)byRef.put(component.getBomRef(),component);
        relationshipRepository.deleteBySourceBom_Id(sourceBom.getId());
        java.util.List<com.prototype.vulnwatch.domain.CbomRelationship> declared=new java.util.ArrayList<>();
        for(var pair:relationships){CbomComponent source=byRef.get(pair.sourceRef()),target=byRef.get(pair.targetRef());
            if(source==null||target==null)continue;
            declared.add(relationship(tenant,sourceBom,"COMPONENT",source.getId(),"COMPONENT",target.getId(),pair.relationshipType(),pair.evidenceSummary()));}
        // Application relationship: the owning asset uses every cryptographic asset its CBOM declares.
        if(asset!=null&&asset.getId()!=null)for(CbomComponent component:active)
            declared.add(relationship(tenant,sourceBom,"ASSET",asset.getId(),"COMPONENT",component.getId(),
                    CbomRelationshipExtractor.APPLICATION_USES,"The application's CBOM declares this cryptographic asset"));
        relationshipRepository.saveAll(declared);
    }

    private static com.prototype.vulnwatch.domain.CbomRelationship relationship(Tenant tenant,BomIngestionRecord sourceBom,String sourceType,
            java.util.UUID sourceId,String targetType,java.util.UUID targetId,String type,String summary){
        var relationship=new com.prototype.vulnwatch.domain.CbomRelationship();relationship.setTenant(tenant);relationship.setSourceBom(sourceBom);
        relationship.setSourceType(sourceType);relationship.setSourceId(sourceId);relationship.setTargetType(targetType);relationship.setTargetId(targetId);
        relationship.setRelationshipType(type);relationship.setEvidenceKind("DECLARED");relationship.setEvidenceSummary(summary);return relationship;
    }

    /**
     * Re-runs the rules over an active CBOM's stored components without re-parsing the document,
     * for time-dependent rules (certificate and key expiry). Findings reconcile by fingerprint and
     * are published as CBOM_DELTA; the assessment is queued again. Callers own the transaction.
     */
    public int reevaluate(Tenant tenant, BomIngestionRecord sourceBom) {
        List<CbomComponent> active = componentRepository.findByTenant_IdAndSourceBom_IdAndActiveTrue(tenant.getId(), sourceBom.getId());
        List<java.util.UUID> touched = new java.util.ArrayList<>();
        CbomRiskEngine.RuleParameters ruleParameters = parameters(tenant);
        int findings = 0;
        for (CbomComponent component : active) {
            List<CbomRiskFinding> evaluated = riskEngine.evaluate(component, ruleParameters);
            component.setRiskScore(riskScorer.scoreComponent(component, evaluated));
            component.touch();
            componentRepository.save(component);
            reconcileFindings(tenant, component, evaluated);
            touched.add(component.getId());
            findings += evaluated.size();
        }
        if (!active.isEmpty() && active.get(0).getAsset() != null) postureService.rollUp(tenant, active.get(0).getAsset(), sourceBom);
        publishMirrorDeltas(tenant, touched.isEmpty() ? List.of() : findingRepository
                .findByTenant_IdAndComponent_IdIn(tenant.getId(), touched).stream().map(CbomRiskFinding::getId).toList(), "cbom-evidence-expiry");
        return findings;
    }

    /**
     * Retires a superseded or deleted CBOM document's components and withdraws the evidence
     * behind its findings.
     *
     * <p>Status and resolvedAt are deliberately untouched. A document going away is not the
     * risk being remediated, and flipping its findings to RESOLVED here would report a
     * still-weak algorithm as fixed. The next evaluation decides resolution.
     */
    public int deactivateBySourceBomId(java.util.UUID sourceBomId) {
        Instant now = Instant.now();
        List<CbomRiskFinding> reported = findingRepository.findBySourceBomId(sourceBomId);
        List<CbomRiskFinding> withdrawn = new java.util.ArrayList<>();
        for (CbomRiskFinding finding : reported) {
            if (finding.getEvidenceState() == BomEvidenceState.WITHDRAWN) {
                continue;
            }
            finding.setEvidenceState(BomEvidenceState.WITHDRAWN);
            finding.setWithdrawnAt(now);
            // lastSeenAt is left alone: withdrawal is not an observation.
            withdrawn.add(finding);
        }
        if (!withdrawn.isEmpty()) {
            findingRepository.saveAll(withdrawn);
        }
        int retired = componentRepository.softDeleteBySourceBomId(sourceBomId);
        if (!reported.isEmpty()) {
            publishMirrorDeltas(reported.get(0).getTenant(),
                    reported.stream().map(CbomRiskFinding::getId).toList(), "cbom-withdrawal");
        }
        return retired;
    }

    private void publishMirrorDeltas(Tenant tenant, List<java.util.UUID> cbomFindingIds, String sourceTag) {
        if (deltaQueue == null) {
            // Unit-test and minimal contexts without the queue keep the inline mirror.
            findingMirror.syncTenant(tenant);
            return;
        }
        deltaQueue.enqueueCbomDeltas(tenant.getId(), cbomFindingIds, sourceTag);
    }

    private void applyParsed(CbomComponent component, Tenant tenant, Asset asset, BomIngestionRecord sourceBom, CbomParsedComponent parsed) {
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSourceBom(sourceBom);
        component.setBomRef(parsed.bomRef());
        component.setComponentFingerprint(parsed.componentFingerprint());
        component.setName(parsed.name());
        component.setDescription(parsed.description());
        component.setAssetType(parsed.assetType());
        component.setComponentType(parsed.componentType());
        component.setPrimitive(parsed.primitive());
        component.setParameterSetIdentifier(parsed.parameterSetIdentifier());
        component.setKeySize(parsed.keySize());
        component.setCurve(parsed.curve());
        component.setPadding(parsed.padding());
        component.setProtocolVersion(parsed.protocolVersion());
        component.setState(parsed.state());
        component.setFormat(parsed.format());
        component.setStorageLocation(parsed.storageLocation());
        component.setTransmission(parsed.transmission());
        component.setSensitivity(parsed.sensitivity());
        component.setUsedIn(parsed.usedIn());
        component.setNotBefore(parsed.notBefore());
        component.setNotAfter(parsed.notAfter());
        component.setIssuer(parsed.issuer());
        component.setSubject(parsed.subject());
        component.setSerialNumber(parsed.serialNumber());
        component.setSignatureAlgorithm(parsed.signatureAlgorithm());
        component.setKeyUsage(parsed.keyUsage());
        component.setActive(true);
    }

    private void reconcileFindings(Tenant tenant, CbomComponent component, List<CbomRiskFinding> evaluated) {
        Set<String> currentFingerprints = new HashSet<>();
        Instant now = Instant.now();
        for (CbomRiskFinding incoming : evaluated) {
            currentFingerprints.add(incoming.getFindingFingerprint());
            CbomRiskFinding persisted = findingRepository
                    .findByTenant_IdAndComponent_IdAndFindingFingerprint(
                            tenant.getId(),
                            component.getId(),
                            incoming.getFindingFingerprint()
                    )
                    .orElse(incoming);
            if (persisted.getId() != null && persisted.getStatus() == CbomFindingStatus.RESOLVED) {
                persisted.setStatus(CbomFindingStatus.OPEN);
                persisted.setResolvedAt(null);
            }
            persisted.setTenant(tenant);
            persisted.setComponent(component);
            persisted.setRuleId(incoming.getRuleId());
            persisted.setRuleVersion(incoming.getRuleVersion());
            persisted.setRiskClass(incoming.getRiskClass());
            persisted.setSeverity(incoming.getSeverity());
            persisted.setTitle(incoming.getTitle());
            persisted.setDetail(incoming.getDetail());
            persisted.setEvidence(incoming.getEvidence());
            persisted.setRecommendation(incoming.getRecommendation());
            persisted.setFindingFingerprint(incoming.getFindingFingerprint());
            persisted.setLastSeenAt(now);
            // Reported again by a live document, so any earlier withdrawal is retracted.
            persisted.setEvidenceState(BomEvidenceState.SUPPORTED);
            persisted.setWithdrawnAt(null);
            findingRepository.save(persisted);
        }

        for (CbomRiskFinding existing : findingRepository.findByTenant_IdAndComponent_Id(tenant.getId(), component.getId())) {
            if (!currentFingerprints.contains(existing.getFindingFingerprint())
                    && existing.getStatus() == CbomFindingStatus.OPEN) {
                existing.setStatus(CbomFindingStatus.RESOLVED);
                existing.setResolvedAt(now);
                existing.setLastSeenAt(now);
                findingRepository.save(existing);
            }
        }
    }

    /** Warning-only heuristic detections are kept as an audit record: codes and pointers, never values. */
    private void recordSecretWarnings(BomIngestionRecord sourceBom, CbomSecretDetector.ScanResult secrets) {
        if (audit == null || secrets == null || secrets.warnings().isEmpty()) return;
        StringBuilder json = new StringBuilder("{\"mode\":\"WARN\",\"detections\":[");
        for (int index = 0; index < secrets.warnings().size(); index++) {
            CbomSecretDetector.Detection detection = secrets.warnings().get(index);
            if (index > 0) json.append(',');
            json.append("{\"code\":\"").append(detection.code()).append("\",\"jsonPointer\":")
                    .append(detection.jsonPointer() == null ? "null" : jsonString(detection.jsonPointer())).append('}');
        }
        json.append("]}");
        audit.record("cbom.secret_detection.warning", "bom", sourceBom.getId() == null ? null : sourceBom.getId().toString(), json.toString());
    }

    private static String jsonString(String value) {
        StringBuilder out = new StringBuilder("\"");
        for (char c : value.toCharArray()) {
            if (c == '"' || c == '\\') out.append('\\').append(c);
            else if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
            else out.append(c);
        }
        return out.append('"').toString();
    }
}
