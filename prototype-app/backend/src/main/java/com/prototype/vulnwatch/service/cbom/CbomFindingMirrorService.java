package com.prototype.vulnwatch.service.cbom;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.BomEvidenceState;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.CbomFindingStatus;
import com.prototype.vulnwatch.domain.CbomRiskFinding;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingCloseReason;
import com.prototype.vulnwatch.domain.FindingCreationSource;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.RiskPolicy;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.CbomRiskFindingRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.service.FindingListProjectionService;
import com.prototype.vulnwatch.service.FindingSlaService;
import com.prototype.vulnwatch.service.FindingWorkflowService;
import com.prototype.vulnwatch.service.RiskPolicyService;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Mirrors CBOM risk findings into the canonical findings list as kind {@value #KIND}, so crypto
 * findings sit beside vulnerability findings and are flagged by their type.
 *
 * <p>{@code cbom_risk_findings} stays the source of truth; each pass derives the canonical row
 * from it and is idempotent. The canonical fingerprint is {@code cbom:<cbom finding id>}.
 * An OPEN finding backed by a live document is OPEN; an accepted one is SUPPRESSED; a finding
 * the latest evaluation no longer reports, or whose document was withdrawn, is auto-closed.
 * Closing for a withdrawn document is not a remediation claim, which is why it is never
 * RESOLVED. A finding that an analyst closed in the findings list reopens only when a newer
 * ingest observes it again.
 */
@Service
public class CbomFindingMirrorService {

    public static final String KIND = "CRYPTO";
    private static final Logger LOG = LoggerFactory.getLogger(CbomFindingMirrorService.class);

    private final CbomRiskFindingRepository cbomFindings;
    private final FindingRepository findings;
    private final FindingWorkflowService workflow;
    private final FindingSlaService sla;
    private final RiskPolicyService riskPolicies;
    private final FindingListProjectionService projections;
    private final ObjectMapper objectMapper;

    public CbomFindingMirrorService(
            CbomRiskFindingRepository cbomFindings,
            FindingRepository findings,
            FindingWorkflowService workflow,
            FindingSlaService sla,
            RiskPolicyService riskPolicies,
            FindingListProjectionService projections,
            ObjectMapper objectMapper
    ) {
        this.cbomFindings = cbomFindings;
        this.findings = findings;
        this.workflow = workflow;
        this.sla = sla;
        this.riskPolicies = riskPolicies;
        this.projections = projections;
        this.objectMapper = objectMapper;
    }

    /** Brings every CRYPTO finding of the tenant in line with its CBOM finding. Needs tenant context. */
    @Transactional
    public int syncTenant(Tenant tenant) {
        int changed = 0;
        for (CbomRiskFinding source : cbomFindings.findByTenant_Id(tenant.getId())) {
            if (mirror(tenant, source)) {
                changed++;
            }
        }
        if (changed > 0) {
            refreshProjectionAfterCommit(tenant);
        }
        return changed;
    }

    static String fingerprint(CbomRiskFinding source) {
        return "cbom:" + source.getId();
    }

    private boolean mirror(Tenant tenant, CbomRiskFinding source) {
        CbomComponent asset = source.getComponent();
        Instant now = Instant.now();
        Finding existing = findings.findByTenantAndFingerprint(tenant, fingerprint(source)).orElse(null);
        if (source.getStatus() == CbomFindingStatus.OPEN
                && asset.isActive() && source.getEvidenceState() != BomEvidenceState.WITHDRAWN) {
            return openOrRefresh(tenant, source, existing, now);
        }
        if (existing == null) {
            return false;
        }
        if (source.getStatus() == CbomFindingStatus.ACCEPTED) {
            return suppress(existing, source, now);
        }
        if (existing.getStatus() != FindingStatus.OPEN) {
            return false;
        }
        boolean reported = source.getStatus() == CbomFindingStatus.RESOLVED;
        workflow.autoCloseFinding(existing,
                reported ? FindingCloseReason.AUTO_NOT_OBSERVED : FindingCloseReason.AUTO_COMPONENT_REMOVED,
                reported ? "The latest CBOM evaluation no longer reports this finding"
                        : "The CBOM document that reported this finding was withdrawn",
                Map.of("cbomFindingId", source.getId().toString()), now);
        findings.save(existing);
        return true;
    }

    private boolean openOrRefresh(Tenant tenant, CbomRiskFinding source, Finding existing, Instant now) {
        double risk = risk(source);
        Instant observedAt = source.getLastSeenAt() == null ? now : source.getLastSeenAt();
        if (existing == null) {
            Finding finding = new Finding();
            finding.setTenant(tenant);
            finding.setFindingKind(KIND);
            finding.setFingerprint(fingerprint(source));
            finding.setWorkflowClass("POSTURE_FINDING");
            finding.setStatus(FindingStatus.OPEN);
            finding.setDecisionState(FindingDecisionState.AFFECTED);
            finding.setCreationSource(FindingCreationSource.AUTOMATIC);
            finding.setMatchedBy("cbom-risk-engine");
            finding.setConfidenceScore(1.0);
            finding.setFirstObservedAt(observedAt);
            finding.setDueAt(dueAt(tenant, observedAt, risk));
            apply(finding, source, risk);
            workflow.markObserved(finding, observedAt, null);
            finding = findings.saveAndFlush(finding);
            workflow.appendEvent(finding, "CREATED_BY_CBOM_EVALUATION", "cbom-risk-engine",
                    "Crypto finding created from a CBOM risk evaluation",
                    Map.of("cbomFindingId", source.getId().toString()));
            return true;
        }
        boolean observedAgain = existing.getLastObservedAt() == null || observedAt.isAfter(existing.getLastObservedAt());
        boolean suppressionActive = existing.getStatus() == FindingStatus.SUPPRESSED
                && (existing.getSuppressedUntil() == null || existing.getSuppressedUntil().isAfter(now));
        if (existing.getStatus() == FindingStatus.OPEN) {
            if (!observedAgain && sameContent(existing, source)) {
                return false;
            }
            workflow.markObserved(existing, observedAt, null);
        } else if (observedAgain && !suppressionActive) {
            workflow.reopenByObservation(existing, observedAt, null);
            existing.setDueAt(dueAt(tenant, observedAt, risk));
        } else {
            return false;
        }
        apply(existing, source, risk);
        existing.touch();
        findings.save(existing);
        return true;
    }

    private boolean suppress(Finding existing, CbomRiskFinding source, Instant now) {
        if (existing.getStatus() == FindingStatus.SUPPRESSED) {
            return false;
        }
        FindingStatus previous = existing.getStatus();
        existing.setStatus(FindingStatus.SUPPRESSED);
        existing.setSuppressionReason("Risk accepted in CBOM posture");
        existing.setSuppressedUntil(null);
        existing.touch();
        findings.save(existing);
        workflow.appendEvent(existing, "SUPPRESSED", "cbom-risk-engine",
                "Crypto finding suppressed because its risk was accepted",
                Map.of("fromStatus", previous.name(), "cbomFindingId", source.getId().toString()));
        return true;
    }

    private void apply(Finding finding, CbomRiskFinding source, double risk) {
        CbomComponent asset = source.getComponent();
        finding.setAsset(asset.getAsset());
        finding.setTitle(source.getTitle());
        finding.setPolicyId(source.getRuleId());
        finding.setPolicyVersion(source.getRuleVersion());
        finding.setReasonCode(source.getRiskClass() == null ? null : source.getRiskClass().name());
        finding.setRiskScore(risk);
        finding.setSeverityOverride(source.getSeverity() == null ? null : source.getSeverity().name());
        finding.setEvidence(evidence(source));
    }

    private boolean sameContent(Finding finding, CbomRiskFinding source) {
        return java.util.Objects.equals(finding.getTitle(), source.getTitle())
                && java.util.Objects.equals(finding.getEvidence(), evidence(source))
                && java.util.Objects.equals(finding.getSeverityOverride(),
                        source.getSeverity() == null ? null : source.getSeverity().name());
    }

    private String evidence(CbomRiskFinding source) {
        CbomComponent asset = source.getComponent();
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("cbomFindingId", source.getId().toString());
        payload.put("cbomComponentId", asset.getId().toString());
        payload.put("assetName", asset.getName());
        payload.put("assetType", asset.getAssetType() == null ? null : asset.getAssetType().name());
        payload.put("ruleId", source.getRuleId());
        payload.put("detail", source.getDetail());
        payload.put("recommendation", source.getRecommendation());
        payload.put("impactReason", source.getDetail());
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            throw new IllegalStateException("Invalid crypto finding evidence", e);
        }
    }

    private double risk(CbomRiskFinding source) {
        if (source.getSeverity() == null) {
            return 3.0;
        }
        return switch (source.getSeverity()) {
            case CRITICAL -> 9.5;
            case HIGH -> 8.0;
            case MEDIUM -> 5.5;
            case LOW -> 3.0;
            case INFO -> 1.0;
        };
    }

    private Instant dueAt(Tenant tenant, Instant observedAt, double risk) {
        RiskPolicy policy = riskPolicies.getOrCreate(tenant);
        return sla.deriveDueAt(observedAt, risk, null, policy);
    }

    private void refreshProjectionAfterCommit(Tenant tenant) {
        if (!TransactionSynchronizationManager.isActualTransactionActive()) {
            projections.refreshTenant(tenant);
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                try {
                    projections.refreshTenant(tenant);
                } catch (RuntimeException ex) {
                    LOG.warn("Crypto finding projection refresh failed after commit for tenant {}: {}",
                            tenant.getId(), ex.getMessage());
                }
            }
        });
    }
}
