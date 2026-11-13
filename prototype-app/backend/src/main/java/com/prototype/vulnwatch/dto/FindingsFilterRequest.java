package com.prototype.vulnwatch.dto;

import com.prototype.vulnwatch.service.FindingQueueResolutionService;
import java.util.List;

public class FindingsFilterRequest {

    private String groupField;
    private String groupValue;
    public String getGroupField() { return groupField; }
    public void setGroupField(String value) { groupField = value; }
    public String getGroupValue() { return groupValue; }
    public void setGroupValue(String value) { groupValue = value; }
    private List<String> severity;
    private List<String> status;
    private List<String> decisionState;
    private List<String> creationSource;
    private List<String> matchMethod;
    private List<String> vexStatus;
    private List<String> vexFreshness;
    private List<String> vexProvider;
    private Double minConfidence;
    private String vulnerabilityId;
    private String packageName;
    private String ecosystem;
    private String queueKey;
    private String ownerGroup;
    private String assignedTo;
    private Boolean unassignedOnly;
    private Boolean incidentLinked;
    private String dueDateBand;
    private String assetName;
    private String supportGroup;
    private List<String> assetType;
    /**
     * Finding kinds to include. Absent means every kind, so the All Findings view stays
     * inclusive and existing callers are unaffected; the software-vulnerability view passes
     * VULNERABILITY explicitly.
     */
    private List<String> findingKind;
    /** Restricts to findings affecting one of these declared AI-BOM resource ids. */
    private List<String> affectedAiResourceId;
    /** {@code true}/{@code false} restricts to findings affecting any/no declared AI resource. */
    private Boolean hasAffectedAiResource;
    /** Canonical owner team ID and resolved status (OWNED, UNOWNED, CONFLICT); ownership plan §9.7. */
    private java.util.UUID ownerTeamId;
    private String ownershipStatus;

    public FindingsFilter toFilter() {
        return new FindingsFilter(
                severity,
                status,
                decisionState,
                creationSource,
                matchMethod,
                vexStatus,
                vexFreshness,
                vexProvider,
                minConfidence,
                vulnerabilityId,
                packageName,
                ecosystem,
                ownerGroup,
                assignedTo,
                unassignedOnly,
                incidentLinked,
                dueDateBand,
                assetName,
                supportGroup,
                null,
                null,
                assetType, groupField, groupValue, findingKind,
                affectedAiResourceId, hasAffectedAiResource,
                ownerTeamId, ownershipStatus
        );
    }

    public java.util.UUID getOwnerTeamId() {
        return ownerTeamId;
    }

    public void setOwnerTeamId(java.util.UUID ownerTeamId) {
        this.ownerTeamId = ownerTeamId;
    }

    public String getOwnershipStatus() {
        return ownershipStatus;
    }

    public void setOwnershipStatus(String ownershipStatus) {
        this.ownershipStatus = ownershipStatus;
    }

    public FindingsFilter resolve(FindingQueueResolutionService queueResolutionService) {
        return queueResolutionService.resolveEffectiveFilter(queueKey, toFilter());
    }

    public List<String> getSeverity() {
        return severity;
    }

    public void setSeverity(List<String> severity) {
        this.severity = severity;
    }

    public List<String> getStatus() {
        return status;
    }

    public void setStatus(List<String> status) {
        this.status = status;
    }

    public List<String> getDecisionState() {
        return decisionState;
    }

    public void setDecisionState(List<String> decisionState) {
        this.decisionState = decisionState;
    }

    public List<String> getCreationSource() {
        return creationSource;
    }

    public void setCreationSource(List<String> creationSource) {
        this.creationSource = creationSource;
    }

    public List<String> getMatchMethod() {
        return matchMethod;
    }

    public void setMatchMethod(List<String> matchMethod) {
        this.matchMethod = matchMethod;
    }

    public List<String> getVexStatus() {
        return vexStatus;
    }

    public void setVexStatus(List<String> vexStatus) {
        this.vexStatus = vexStatus;
    }

    public List<String> getVexFreshness() {
        return vexFreshness;
    }

    public void setVexFreshness(List<String> vexFreshness) {
        this.vexFreshness = vexFreshness;
    }

    public List<String> getVexProvider() {
        return vexProvider;
    }

    public void setVexProvider(List<String> vexProvider) {
        this.vexProvider = vexProvider;
    }

    public Double getMinConfidence() {
        return minConfidence;
    }

    public void setMinConfidence(Double minConfidence) {
        this.minConfidence = minConfidence;
    }

    public String getVulnerabilityId() {
        return vulnerabilityId;
    }

    public void setVulnerabilityId(String vulnerabilityId) {
        this.vulnerabilityId = vulnerabilityId;
    }

    public String getPackageName() {
        return packageName;
    }

    public void setPackageName(String packageName) {
        this.packageName = packageName;
    }

    public String getEcosystem() {
        return ecosystem;
    }

    public void setEcosystem(String ecosystem) {
        this.ecosystem = ecosystem;
    }

    public String getQueueKey() {
        return queueKey;
    }

    public void setQueueKey(String queueKey) {
        this.queueKey = queueKey;
    }

    public String getOwnerGroup() {
        return ownerGroup;
    }

    public void setOwnerGroup(String ownerGroup) {
        this.ownerGroup = ownerGroup;
    }

    public String getAssignedTo() {
        return assignedTo;
    }

    public void setAssignedTo(String assignedTo) {
        this.assignedTo = assignedTo;
    }

    public Boolean getUnassignedOnly() {
        return unassignedOnly;
    }

    public void setUnassignedOnly(Boolean unassignedOnly) {
        this.unassignedOnly = unassignedOnly;
    }

    public Boolean getIncidentLinked() {
        return incidentLinked;
    }

    public void setIncidentLinked(Boolean incidentLinked) {
        this.incidentLinked = incidentLinked;
    }

    public String getDueDateBand() {
        return dueDateBand;
    }

    public void setDueDateBand(String dueDateBand) {
        this.dueDateBand = dueDateBand;
    }

    public String getAssetName() {
        return assetName;
    }

    public void setAssetName(String assetName) {
        this.assetName = assetName;
    }

    public String getSupportGroup() {
        return supportGroup;
    }

    public void setSupportGroup(String supportGroup) {
        this.supportGroup = supportGroup;
    }

    public List<String> getFindingKind() {
        return findingKind;
    }

    public void setFindingKind(List<String> findingKind) {
        this.findingKind = findingKind;
    }

    public List<String> getAssetType() {
        return assetType;
    }

    public void setAssetType(List<String> assetType) {
        this.assetType = assetType;
    }

    public List<String> getAffectedAiResourceId() {
        return affectedAiResourceId;
    }

    public void setAffectedAiResourceId(List<String> affectedAiResourceId) {
        this.affectedAiResourceId = affectedAiResourceId;
    }

    public Boolean getHasAffectedAiResource() {
        return hasAffectedAiResource;
    }

    public void setHasAffectedAiResource(Boolean hasAffectedAiResource) {
        this.hasAffectedAiResource = hasAffectedAiResource;
    }
}
