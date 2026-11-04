package com.prototype.vulnwatch.service.cbom;

import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.CbomFindingStatus;
import com.prototype.vulnwatch.domain.CbomPostureSummary;
import com.prototype.vulnwatch.domain.CbomRiskFinding;
import com.prototype.vulnwatch.domain.CbomRiskSeverity;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CbomBomAssetResponse;
import com.prototype.vulnwatch.dto.CbomComponentResponse;
import com.prototype.vulnwatch.dto.CbomPostureSummaryResponse;
import com.prototype.vulnwatch.dto.CbomRiskFindingResponse;
import com.prototype.vulnwatch.repo.CbomComponentRepository;
import com.prototype.vulnwatch.repo.CbomPostureSummaryRepository;
import com.prototype.vulnwatch.repo.CbomRiskFindingRepository;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

@Service
public class CbomReadService {

    private final CbomPostureSummaryRepository postureSummaryRepository;
    private final CbomComponentRepository componentRepository;
    private final CbomRiskFindingRepository findingRepository;

    public CbomReadService(
            CbomPostureSummaryRepository postureSummaryRepository,
            CbomComponentRepository componentRepository,
            CbomRiskFindingRepository findingRepository
    ) {
        this.postureSummaryRepository = postureSummaryRepository;
        this.componentRepository = componentRepository;
        this.findingRepository = findingRepository;
    }

    @Transactional(readOnly = true)
    public List<CbomPostureSummaryResponse> listPosture(Tenant tenant) {
        return postureSummaryRepository.findByTenant_IdOrderByPostureScoreDesc(tenant.getId())
                .stream()
                .map(this::toPostureResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public CbomPostureSummaryResponse getPosture(Tenant tenant, UUID assetId) {
        return postureSummaryRepository.findByTenant_IdAndAsset_Id(tenant.getId(), assetId)
                .map(this::toPostureResponse)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "CBOM posture not found"));
    }

    @Transactional(readOnly = true)
    public List<CbomComponentResponse> listComponents(Tenant tenant, UUID assetId, int page, int size) {
        List<CbomComponent> components = componentRepository
                .findByTenant_IdAndAsset_IdAndActiveTrueOrderByRiskScoreDescNameAsc(
                        tenant.getId(),
                        assetId,
                        PageRequest.of(Math.max(0, page), Math.min(Math.max(1, size), 500))
                );
        List<UUID> componentIds = components.stream().map(CbomComponent::getId).toList();
        Map<UUID, List<CbomRiskFinding>> findingsByComponent = findingRepository
                .findByTenant_IdAndComponent_IdIn(tenant.getId(), componentIds)
                .stream()
                .collect(Collectors.groupingBy(f -> f.getComponent().getId()));
        return components.stream().map(component -> toComponentResponse(component, findingsByComponent.getOrDefault(component.getId(), List.of()))).toList();
    }

    /** The assets one CBOM document reported, riskiest first, each with its findings of any status. */
    @Transactional(readOnly = true)
    public List<CbomBomAssetResponse> listAssetsForBom(Tenant tenant, UUID bomId) {
        List<CbomComponent> components = componentRepository
                .findByTenant_IdAndSourceBom_IdAndActiveTrueOrderByRiskScoreDescNameAsc(tenant.getId(), bomId);
        List<UUID> componentIds = components.stream().map(CbomComponent::getId).toList();
        Map<UUID, List<CbomRiskFinding>> findingsByComponent = componentIds.isEmpty()
                ? Map.of()
                : findingRepository.findByTenant_IdAndComponent_IdIn(tenant.getId(), componentIds)
                        .stream()
                        .collect(Collectors.groupingBy(f -> f.getComponent().getId()));
        return components.stream()
                .map(component -> {
                    List<CbomRiskFinding> findings = findingsByComponent.getOrDefault(component.getId(), List.of());
                    return new CbomBomAssetResponse(
                            toComponentResponse(component, findings),
                            findings.stream().map(this::toFindingResponse).toList()
                    );
                })
                .toList();
    }

    @Transactional(readOnly = true)
    public List<CbomRiskFindingResponse> listFindings(Tenant tenant, UUID assetId, String severity) {
        List<CbomRiskFinding> findings;
        CbomRiskSeverity parsedSeverity = parseSeverity(severity);
        if (parsedSeverity == null) {
            findings = findingRepository.findByTenant_IdAndComponent_Asset_IdAndStatusOrderBySeverityAscCreatedAtDesc(
                    tenant.getId(),
                    assetId,
                    CbomFindingStatus.OPEN
            );
        } else {
            findings = findingRepository.findByTenant_IdAndComponent_Asset_IdAndSeverityAndStatusOrderByCreatedAtDesc(
                    tenant.getId(),
                    assetId,
                    parsedSeverity,
                    CbomFindingStatus.OPEN
            );
        }
        return findings.stream().map(this::toFindingResponse).toList();
    }

    private CbomPostureSummaryResponse toPostureResponse(CbomPostureSummary summary) {
        return new CbomPostureSummaryResponse(
                summary.getId(),
                summary.getAsset().getId(),
                summary.getAsset().getName(),
                summary.getLastSourceBom() == null ? null : summary.getLastSourceBom().getId(),
                summary.getTotalComponents(),
                summary.getCriticalFindings(),
                summary.getHighFindings(),
                summary.getMediumFindings(),
                summary.getLowFindings(),
                summary.getInfoFindings(),
                summary.getAcceptedFindings(),
                summary.getQuantumVulnerable(),
                summary.getWeakAlgorithms(),
                summary.getExpiringCerts(),
                summary.getPostureScore(),
                summary.getLastEvaluatedAt()
        );
    }

    private CbomComponentResponse toComponentResponse(CbomComponent component, List<CbomRiskFinding> findings) {
        int open = (int) findings.stream().filter(f -> f.getStatus() == CbomFindingStatus.OPEN).count();
        int high = (int) findings.stream().filter(f -> f.getStatus() == CbomFindingStatus.OPEN && f.getSeverity() == CbomRiskSeverity.HIGH).count();
        int critical = (int) findings.stream().filter(f -> f.getStatus() == CbomFindingStatus.OPEN && f.getSeverity() == CbomRiskSeverity.CRITICAL).count();
        return new CbomComponentResponse(
                component.getId(),
                component.getAsset() == null ? null : component.getAsset().getId(),
                component.getSourceBom() == null ? null : component.getSourceBom().getId(),
                component.getBomRef(),
                component.getName(),
                component.getDescription(),
                component.getAssetType() == null ? null : component.getAssetType().name(),
                component.getComponentType(),
                component.getPrimitive(),
                component.getKeySize(),
                component.getCurve(),
                component.getPadding(),
                component.getProtocolVersion(),
                component.getState(),
                component.getFormat(),
                component.getStorageLocation(),
                component.getTransmission(),
                component.getSensitivity(),
                component.getUsedIn(),
                component.getNotAfter(),
                component.getRiskScore(),
                open,
                high,
                critical
        );
    }

    private CbomRiskFindingResponse toFindingResponse(CbomRiskFinding finding) {
        CbomComponent component = finding.getComponent();
        return new CbomRiskFindingResponse(
                finding.getId(),
                component.getId(),
                component.getName(),
                component.getAsset() == null ? null : component.getAsset().getId(),
                finding.getRuleId(),
                finding.getRiskClass() == null ? null : finding.getRiskClass().name(),
                finding.getSeverity() == null ? null : finding.getSeverity().name(),
                finding.getTitle(),
                finding.getDetail(),
                finding.getEvidence(),
                finding.getRecommendation(),
                finding.getStatus() == null ? null : finding.getStatus().name(),
                finding.getFirstSeenAt(),
                finding.getLastSeenAt()
        );
    }

    private CbomRiskSeverity parseSeverity(String severity) {
        if (severity == null || severity.isBlank()) return null;
        try {
            return CbomRiskSeverity.valueOf(severity.trim().toUpperCase());
        } catch (IllegalArgumentException ignored) {
            return null;
        }
    }
}
