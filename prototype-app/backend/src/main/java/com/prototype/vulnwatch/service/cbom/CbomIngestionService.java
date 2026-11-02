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
        if (parser.parse(content).isEmpty()) {
            throw new IOException("No CBOM cryptographic assets could be extracted from the submitted document");
        }
    }

    public CbomIngestionResult ingest(Tenant tenant, Asset asset, BomIngestionRecord sourceBom, byte[] content) throws IOException {
        List<CbomParsedComponent> parsedComponents = parser.parse(content);
        int findingCount = 0;
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

            List<CbomRiskFinding> evaluated = riskEngine.evaluate(component);
            component.setRiskScore(riskScorer.scoreComponent(component, evaluated));
            component = componentRepository.save(component);
            reconcileFindings(tenant, component, evaluated);
            findingCount += evaluated.size();
        }
        postureService.rollUp(tenant, asset, sourceBom);
        findingMirror.syncTenant(tenant);
        return new CbomIngestionResult(parsedComponents.size(), findingCount);
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
            findingMirror.syncTenant(reported.get(0).getTenant());
        }
        return retired;
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
}
