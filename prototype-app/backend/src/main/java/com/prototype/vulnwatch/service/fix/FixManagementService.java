package com.prototype.vulnwatch.service.fix;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.FixAsset;
import com.prototype.vulnwatch.domain.FixAssetEvent;
import com.prototype.vulnwatch.domain.FixAssetStatus;
import com.prototype.vulnwatch.domain.FixControlDetail;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.FixRecordCve;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.FixControlRequest;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.FixAssetEventRepository;
import com.prototype.vulnwatch.repo.FixAssetRepository;
import com.prototype.vulnwatch.repo.FixControlDetailRepository;
import com.prototype.vulnwatch.repo.FixRecordCveRepository;
import com.prototype.vulnwatch.repo.FixRecordRepository;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;
import static org.springframework.http.HttpStatus.BAD_REQUEST;
import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.HttpStatus.NOT_FOUND;

/**
 * Write side of Fix Intelligence: analyst workarounds, configuration changes and compensating
 * controls, with a propose → approve lifecycle.
 *
 * <p>Rules enforced here, not only in the UI: patch-tool and Workbench records are read-only;
 * a record from another tenant is a 404; the approver cannot be the proposer; editing an active
 * control sends it back for approval; CVE and asset references are validated and bounded.
 */
@Service
public class FixManagementService {

    static final Set<String> CONTROL_TYPES = Set.of("WORKAROUND", "CONFIGURATION_CHANGE", "COMPENSATING_CONTROL");
    static final int MAX_CVES = 200;
    static final int MAX_ASSETS = 2000;

    private final FixRecordRepository fixes;
    private final FixRecordCveRepository fixCves;
    private final FixControlDetailRepository controls;
    private final FixAssetRepository fixAssets;
    private final FixAssetEventRepository events;
    private final AssetRepository assets;

    public FixManagementService(
            FixRecordRepository fixes,
            FixRecordCveRepository fixCves,
            FixControlDetailRepository controls,
            FixAssetRepository fixAssets,
            FixAssetEventRepository events,
            AssetRepository assets
    ) {
        this.fixes = fixes;
        this.fixCves = fixCves;
        this.controls = controls;
        this.fixAssets = fixAssets;
        this.events = events;
        this.assets = assets;
    }

    @Transactional
    public UUID create(Tenant tenant, String actor, FixControlRequest request) {
        FixControlRequest req = require(request);
        String type = controlType(req.fixType());
        FixRecord fix = new FixRecord();
        fix.setTenant(tenant);
        fix.setFixType(type);
        fix.setManaged(true);
        fix.setRecommendationSource(FixRecord.RecommendationSource.ANALYST.name());
        fix.setRelatedCveIdsJson("[]");
        fix.setSoftwareEntitiesJson("[]");
        fix.setSourceUrlsJson("[]");
        fix.setGeneratedAt(Instant.now());
        fix.setProposedBy(actor);
        apply(fix, req);
        fix.setStatus(Boolean.TRUE.equals(req.submit()) ? FixRecord.Status.PROPOSED : FixRecord.Status.DRAFT);
        FixRecord saved = fixes.save(fix);
        saveControl(tenant, saved.getId(), req);
        replaceCves(tenant, saved, req.cveIds());
        replaceAssets(tenant, saved.getId(), req.assetIds(), false);
        return saved.getId();
    }

    @Transactional
    public void update(Tenant tenant, String actor, UUID fixId, FixControlRequest request) {
        FixControlRequest req = require(request);
        FixRecord fix = editable(tenant, fixId);
        if (req.version() != null && req.version() != fix.getVersion()) {
            throw new ResponseStatusException(CONFLICT, "This fix was changed by someone else; reload and try again");
        }
        if (req.fixType() != null && !controlType(req.fixType()).equals(fix.getFixType())) {
            throw new ResponseStatusException(BAD_REQUEST, "A fix's type cannot be changed");
        }
        apply(fix, req);
        boolean wasLive = fix.getStatus() == FixRecord.Status.ACTIVE || fix.getStatus() == FixRecord.Status.APPROVED;
        if (wasLive || Boolean.TRUE.equals(req.submit())) {
            // A changed control is a different control: it needs approval again.
            fix.setStatus(FixRecord.Status.PROPOSED);
            fix.setApprovedBy(null);
            fix.setApprovedAt(null);
            fix.setProposedBy(actor);
        }
        fixes.save(fix);
        saveControl(tenant, fix.getId(), req);
        replaceCves(tenant, fix, req.cveIds());
        replaceAssets(tenant, fix.getId(), req.assetIds(), false);
    }

    @Transactional
    public void approve(Tenant tenant, String actor, UUID fixId) {
        FixRecord fix = editable(tenant, fixId);
        if (fix.getStatus() != FixRecord.Status.PROPOSED) {
            throw new ResponseStatusException(CONFLICT, "Only a proposed fix can be approved");
        }
        if (actor == null || Objects.equals(actor, fix.getProposedBy())) {
            throw new ResponseStatusException(FORBIDDEN, "A fix must be approved by someone other than its proposer");
        }
        fix.setStatus(FixRecord.Status.ACTIVE);
        fix.setApprovedBy(actor);
        fix.setApprovedAt(Instant.now());
        fixes.save(fix);
        // Scoped assets now carry an approved control.
        for (FixAsset row : fixAssets.findByFixId(fixId, org.springframework.data.domain.Pageable.unpaged())) {
            if ("ANALYST".equals(row.getProvider()) && row.getStatus() != FixAssetStatus.APPLIED) {
                recordChange(tenant, row, FixAssetStatus.APPLIED);
            }
        }
    }

    @Transactional
    public void retire(Tenant tenant, UUID fixId) {
        FixRecord fix = editable(tenant, fixId);
        fix.setStatus(FixRecord.Status.RETIRED);
        fixes.save(fix);
        for (FixAsset row : fixAssets.findByFixId(fixId, org.springframework.data.domain.Pageable.unpaged())) {
            if ("ANALYST".equals(row.getProvider()) && row.getStatus() != FixAssetStatus.NOT_APPLICABLE) {
                recordChange(tenant, row, FixAssetStatus.NOT_APPLICABLE);
            }
        }
    }

    // ── Helpers ──────────────────────────────────────────────────────────────────────────────

    /** The fix if it belongs to this tenant and is an analyst-managed control; otherwise 404 / 409. */
    private FixRecord editable(Tenant tenant, UUID fixId) {
        FixRecord fix = fixes.findById(fixId)
                .filter(f -> f.getTenant() != null && tenant.getId().equals(f.getTenant().getId()))
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "Fix not found"));
        if (!fix.isManaged() || !FixRecord.RecommendationSource.ANALYST.name().equals(fix.getRecommendationSource())) {
            throw new ResponseStatusException(CONFLICT, "Patch-tool and recommendation fixes are read-only");
        }
        if (fix.getStatus() == FixRecord.Status.RETIRED) {
            throw new ResponseStatusException(CONFLICT, "A retired fix cannot be changed");
        }
        return fix;
    }

    private void apply(FixRecord fix, FixControlRequest req) {
        String title = trimToNull(req.title());
        if (title == null) throw new ResponseStatusException(BAD_REQUEST, "A title is required");
        fix.setTitle(limit(title, 500));
        fix.setSummary(limit(title, 255));
        fix.setDescription(limit(trimToNull(req.description()), 20_000));
        fix.setSeverity(enumValue(req.severity(), FixIntelligenceQueryService.SEVERITIES, "severity"));
        String ecosystem = enumValue(req.ecosystem(), FixIntelligenceQueryService.ECOSYSTEMS, "ecosystem");
        fix.setEcosystem(ecosystem == null ? FixRecord.Ecosystem.CROSS_PLATFORM : FixRecord.Ecosystem.valueOf(ecosystem));
        fix.setInstallationInstructions(limit(trimToNull(req.installationInstructions()), 20_000));
        fix.setRollbackInstructions(limit(trimToNull(req.rollbackInstructions()), 20_000));
        fix.setKnownLimitations(limit(trimToNull(req.knownLimitations()), 20_000));
        fix.setOwner(limit(trimToNull(req.owner()), 255));
        fix.setReviewDueAt(req.reviewDueAt());
    }

    private void saveControl(Tenant tenant, UUID fixId, FixControlRequest req) {
        FixControlDetail detail = controls.findById(fixId).orElseGet(() -> {
            FixControlDetail created = new FixControlDetail();
            created.setFixId(fixId);
            created.setTenant(tenant);
            return created;
        });
        detail.setControlType(limit(trimToNull(req.controlType()), 64));
        detail.setScopeDescription(limit(trimToNull(req.scopeDescription()), 2000));
        detail.setVerificationMethod(limit(trimToNull(req.verificationMethod()), 2000));
        detail.setResidualRisk(enumValue(req.residualRisk(), Set.of("HIGH", "MEDIUM", "LOW"), "residual risk"));
        controls.save(detail);
    }

    private void replaceCves(Tenant tenant, FixRecord fix, List<String> requested) {
        Set<String> cves = new LinkedHashSet<>();
        for (String cve : requested == null ? List.<String>of() : requested) {
            String normalized = cve == null ? "" : cve.trim().toUpperCase(Locale.ROOT);
            if (!normalized.matches("^CVE-\\d{4}-\\d{4,}$")) {
                throw new ResponseStatusException(BAD_REQUEST, "Invalid CVE id: " + limit(String.valueOf(cve), 40));
            }
            cves.add(normalized);
        }
        if (cves.size() > MAX_CVES) throw new ResponseStatusException(BAD_REQUEST, "At most " + MAX_CVES + " CVEs per fix");
        fixCves.deleteByFixIdAndSource(fix.getId(), "ANALYST");
        fixCves.flush();
        for (String cve : cves) {
            if (fixCves.findByFixIdAndCveId(fix.getId(), cve).isPresent()) continue;
            FixRecordCve link = new FixRecordCve();
            link.setTenant(tenant);
            link.setFixId(fix.getId());
            link.setCveId(cve);
            link.setSource("ANALYST");
            link.setConfidence("HIGH");
            link.setCreatedAt(Instant.now());
            fixCves.save(link);
        }
        fix.setCveId(cves.isEmpty() ? null : cves.iterator().next());
        fixes.save(fix);
    }

    private void replaceAssets(Tenant tenant, UUID fixId, List<UUID> requested, boolean applied) {
        Set<UUID> wanted = new LinkedHashSet<>(requested == null ? List.of() : requested);
        if (wanted.size() > MAX_ASSETS) throw new ResponseStatusException(BAD_REQUEST, "At most " + MAX_ASSETS + " assets per fix");
        // Only this tenant's assets resolve (tenant schema + RLS); anything else is rejected, not ignored.
        List<Asset> found = assets.findAllById(wanted);
        if (found.size() != wanted.size()
                || found.stream().anyMatch(a -> a.getTenant() == null || !tenant.getId().equals(a.getTenant().getId()))) {
            throw new ResponseStatusException(BAD_REQUEST, "One or more assets were not found");
        }
        for (FixAsset row : fixAssets.findByFixId(fixId, org.springframework.data.domain.Pageable.unpaged())) {
            if ("ANALYST".equals(row.getProvider()) && !wanted.remove(row.getAssetId())) {
                fixAssets.delete(row);
            }
        }
        for (UUID assetId : wanted) {
            FixAsset row = new FixAsset();
            row.setTenant(tenant);
            row.setFixId(fixId);
            row.setAssetId(assetId);
            row.setProvider("ANALYST");
            row.setStatus(applied ? FixAssetStatus.APPLIED : FixAssetStatus.SCHEDULED);
            row.setFirstDetectedAt(Instant.now());
            row.setLastReportedAt(Instant.now());
            fixAssets.save(row);
        }
    }

    private void recordChange(Tenant tenant, FixAsset row, FixAssetStatus next) {
        FixAssetEvent event = new FixAssetEvent();
        event.setTenant(tenant);
        event.setFixAssetId(row.getId());
        event.setFromStatus(row.getStatus() == null ? null : row.getStatus().name());
        event.setToStatus(next.name());
        event.setProvider("ANALYST");
        event.setOccurredAt(Instant.now());
        row.setStatus(next);
        row.setLastReportedAt(Instant.now());
        fixAssets.save(row);
        events.save(event);
    }

    private static FixControlRequest require(FixControlRequest request) {
        if (request == null) throw new ResponseStatusException(BAD_REQUEST, "A fix is required");
        return request;
    }

    private static String controlType(String value) {
        String type = value == null ? "" : value.trim().toUpperCase(Locale.ROOT);
        if (!CONTROL_TYPES.contains(type)) {
            throw new ResponseStatusException(BAD_REQUEST, "Fix type must be WORKAROUND, CONFIGURATION_CHANGE or COMPENSATING_CONTROL");
        }
        return type;
    }

    private static String enumValue(String value, Set<String> allowed, String name) {
        if (value == null || value.isBlank()) return null;
        String upper = value.trim().toUpperCase(Locale.ROOT);
        if (!allowed.contains(upper)) throw new ResponseStatusException(BAD_REQUEST, "Unknown " + name + ": " + limit(value, 40));
        return upper;
    }

    private static String trimToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static String limit(String value, int max) {
        return value == null || value.length() <= max ? value : value.substring(0, max);
    }
}
