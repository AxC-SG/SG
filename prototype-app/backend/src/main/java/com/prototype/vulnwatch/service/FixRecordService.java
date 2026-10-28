package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.client.http.AdvisoryFetchService;
import com.prototype.vulnwatch.client.http.OpenAiClient;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.FixRecord;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.dto.FixRecordResponse;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FixRecordRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import com.prototype.vulnwatch.util.LogUtil;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class FixRecordService {

    private static final Logger log = LoggerFactory.getLogger(FixRecordService.class);

    private final FixRecordRepository fixRecordRepository;
    private final VulnerabilityRepository vulnerabilityRepository;
    private final OrgCveRecordRepository orgCveRecordRepository;
    private final ComponentVulnerabilityStateRepository cvsRepository;
    private final VulnerabilityTargetRepository vulnTargetRepository;
    private final AdvisoryFetchService advisoryFetchService;
    private final OpenAiClient openAiClient;
    private final ObjectMapper objectMapper;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private TransactionTemplate writeTransactionTemplate;
    private com.prototype.vulnwatch.repo.FixRecordCveRepository fixRecordCveRepository;

    public FixRecordService(
            FixRecordRepository fixRecordRepository,
            VulnerabilityRepository vulnerabilityRepository,
            OrgCveRecordRepository orgCveRecordRepository,
            ComponentVulnerabilityStateRepository cvsRepository,
            VulnerabilityTargetRepository vulnTargetRepository,
            AdvisoryFetchService advisoryFetchService,
            OpenAiClient openAiClient,
            ObjectMapper objectMapper,
            TenantSchemaExecutionService tenantSchemaExecutionService
    ) {
        this.fixRecordRepository = fixRecordRepository;
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.cvsRepository = cvsRepository;
        this.vulnTargetRepository = vulnTargetRepository;
        this.advisoryFetchService = advisoryFetchService;
        this.openAiClient = openAiClient;
        this.objectMapper = objectMapper;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
    }

    /** CVE links for Fix Intelligence; injected after construction so existing callers keep their signature. */
    @org.springframework.beans.factory.annotation.Autowired(required = false)
    public void setFixRecordCveRepository(com.prototype.vulnwatch.repo.FixRecordCveRepository fixRecordCveRepository) {
        this.fixRecordCveRepository = fixRecordCveRepository;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager == null) {
            this.writeTransactionTemplate = null;
            return;
        }
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    public List<FixRecordResponse> getFixRecords(Tenant tenant, String cveId) {
        return tenantSchemaExecutionService.run(tenant, () -> fixRecordRepository.findByCveIdOrderByCreatedAtAsc(cveId)
                .stream()
                .map(this::toResponse)
                .toList());
    }

    public List<FixRecordResponse> getFixRecordsBySoftware(Tenant tenant, String software) {
        if (software == null || software.isBlank()) return List.of();
        return tenantSchemaExecutionService.run(tenant, () -> fixRecordRepository.findBySoftwareNameContaining(software)
                .stream()
                .map(this::toResponse)
                .toList());
    }

    public record AnalystFixEntry(
            String software,
            String version,
            String vendor,
            String fixType,
            String solutionText,
            int assetCount
    ) {}

    public List<FixRecordResponse> saveAnalystFixes(Tenant tenant, String cveId, List<AnalystFixEntry> entries) {
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            List<FixRecord> existing = fixRecordRepository.findByCveIdOrderByCreatedAtAsc(cveId)
                    .stream()
                    .filter(r -> FixRecord.RecommendationSource.ANALYST.name().equals(r.getRecommendationSource()))
                    // Fix Intelligence workarounds and controls are lifecycle-managed, not Workbench entries.
                    .filter(r -> !r.isManaged())
                    .toList();
            fixRecordRepository.deleteAll(existing);

            List<FixRecord> saved = new ArrayList<>();
            for (AnalystFixEntry entry : entries) {
                if (entry.solutionText() == null || entry.solutionText().isBlank()) continue;
                FixRecord r = new FixRecord();
                r.setTenant(tenant);
                r.setCveId(cveId);
                r.setRelatedCveIdsJson("[]");
                String summary = entry.solutionText().length() > 200
                        ? entry.solutionText().substring(0, 197) + "..."
                        : entry.solutionText();
                r.setSummary(summary);
                r.setDescription(entry.solutionText());
                r.setFixType(normalizeFixType(entry.fixType()));
                r.setRecommendationSource(FixRecord.RecommendationSource.ANALYST.name());
                Map<String, Object> entity = new LinkedHashMap<>();
                entity.put("name", entry.software());
                entity.put("ecosystem", entry.vendor() != null ? entry.vendor() : "");
                entity.put("version", entry.version());
                entity.put("assetCount", entry.assetCount());
                r.setSoftwareEntitiesJson(toJson(List.of(entity)));
                r.setSourceUrlsJson("[]");
                r.setGeneratedAt(Instant.now());
                saved.add(persistRecommendation(r, null));
            }
            return saved.stream().map(this::toResponse).toList();
        }));
    }

    public List<FixRecordResponse> generateFixRecords(Tenant tenant, String cveId) {
        return generateFixRecords(tenant, cveId, List.of());
    }

    public List<FixRecordResponse> generateFixRecords(
            Tenant tenant, String cveId,
            List<com.prototype.vulnwatch.controller.CveDetailController.GenerateFixesSoftwareEntry> extraSoftware
    ) {
        return tenantSchemaExecutionService.run(
                tenant,
                () -> executeWrite(() -> generateFixRecordsInTenantSchema(tenant, cveId, extraSoftware))
        );
    }

    private List<FixRecordResponse> generateFixRecordsInTenantSchema(
            Tenant tenant, String cveId,
            List<com.prototype.vulnwatch.controller.CveDetailController.GenerateFixesSoftwareEntry> extraSoftware
    ) {
        Vulnerability vulnerability = vulnerabilityRepository.findByExternalId(cveId)
                .orElseThrow(() -> new NoSuchElementException("CVE not found: " + cveId));

        // ── 1. Collect matched software from CVS records (same filter as Affected Entities tab) ──
        List<ComponentVulnerabilityState> applicableStates = cvsRepository
                .findByVulnerability_Id(vulnerability.getId())
                .stream()
                .filter(s -> s.getComponent() != null)
                .filter(s -> s.getComponent().getComponentStatus() == InventoryComponentStatus.ACTIVE)
                .toList();

        // ── 2. Build software context map: coordKey -> SoftwareContext ───────
        Map<String, SoftwareContext> softwareMap = new LinkedHashMap<>();
        for (ComponentVulnerabilityState state : applicableStates) {
            var comp = state.getComponent();
            String key = comp.getEcosystem() + ":" + comp.getPackageName();
            SoftwareContext ctx = softwareMap.computeIfAbsent(key, k -> {
                SoftwareContext c = new SoftwareContext();
                c.name = comp.getPackageName();
                c.ecosystem = comp.getEcosystem();
                c.version = comp.getVersion();
                c.isEol = Boolean.TRUE.equals(comp.getIsEol());
                c.eolDate = comp.getEolDate() != null ? comp.getEolDate().toString() : null;
                c.supportPhase = comp.getSupportPhase();
                return c;
            });
            if (comp.getAsset() != null) {
                ctx.assetIds.add(comp.getAsset().getId());
                if (comp.getAsset().getType() != null) {
                    ctx.assetTypes.add(comp.getAsset().getType().toString());
                }
            }
        }

        // ── 2b. Merge investigation-identified software not in CVS records ────
        for (var extra : extraSoftware) {
            String key = (extra.vendor() != null ? extra.vendor().toLowerCase() : "") + ":" + extra.name();
            softwareMap.computeIfAbsent(key, k -> {
                SoftwareContext c = new SoftwareContext();
                c.name = extra.name();
                c.ecosystem = extra.vendor() != null ? extra.vendor().toLowerCase() : "";
                c.version = extra.version();
                return c;
            });
            // Add placeholder asset IDs so assetCount reflects the investigation count
            SoftwareContext ctx = softwareMap.get(key);
            if (ctx.assetIds.isEmpty() && extra.assetCount() > 0) {
                for (int i = 0; i < extra.assetCount(); i++) ctx.assetIds.add(UUID.randomUUID());
            }
        }

        // ── 3. Vendor intelligence: fixed versions + OS-scoped CPE targets ───
        List<VulnerabilityTarget> targets = vulnTargetRepository.findByVulnerability(vulnerability);
        List<String> fixedVersionsFromIntel = targets.stream()
                .filter(t -> t.getFixedVersion() != null && !t.getFixedVersion().isBlank())
                .map(VulnerabilityTarget::getFixedVersion)
                .distinct()
                .toList();

        // Derive OS hints from CPE part='o' targets
        Set<String> osPlatforms = targets.stream()
                .filter(t -> t.getCpeDim() != null && "o".equalsIgnoreCase(t.getCpeDim().getPart()))
                .map(t -> t.getCpeDim().getProduct())
                .filter(p -> p != null && !p.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));

        // ── 4. Reference URLs ────────────────────────────────────────────────
        List<String> referenceUrls = parseReferenceUrls(vulnerability.getReferencesJson());

        // ── 5. Cross-reference: find other APPLICABLE org CVEs sharing same software ─
        List<String> relatedCveIds = findRelatedCveIds(tenant, cveId, softwareMap, fixedVersionsFromIntel);

        // ── 6. Delete previous records; generate fresh ───────────────────────
        // Only this generator's own records are replaced; patch-tool and Fix Intelligence records stay.
        fixRecordRepository.deleteByCveIdAndManagedFalse(cveId);

        // One fix record per distinct software product (versions of same product share one record)
        Map<String, Map<String, SoftwareContext>> byProduct = new LinkedHashMap<>();
        for (Map.Entry<String, SoftwareContext> entry : softwareMap.entrySet()) {
            byProduct.computeIfAbsent(entry.getValue().name, k -> new LinkedHashMap<>())
                     .put(entry.getKey(), entry.getValue());
        }

        // Normalize osPlatforms into distinct OS families (Windows / Linux / macOS)
        // If multiple families exist → one fix per (product × OS family)
        // If single or no OS family → one fix per product (platform-agnostic)
        Set<String> osFamilies = osPlatforms.stream()
                .map(FixRecordService::normalizeOsFamily)
                .filter(f -> !f.isBlank())
                .collect(Collectors.toCollection(LinkedHashSet::new));

        List<FixRecord> records = new ArrayList<>();
        for (Map<String, SoftwareContext> productMap : byProduct.values()) {
            if (osFamilies.size() > 1) {
                // OS-specific: generate one fix per distinct OS family
                for (String osFamily : osFamilies) {
                    FixRecord fix = generateSingleFixRecord(
                            tenant, cveId, vulnerability, productMap,
                            referenceUrls, targets, osPlatforms, relatedCveIds, fixedVersionsFromIntel, osFamily);
                    if (fix == null) {
                        fix = buildFallbackFix(tenant, cveId, vulnerability, productMap, referenceUrls, relatedCveIds);
                        fix.setOsHint(osFamily);
                    }
                    records.add(persistRecommendation(fix, vulnerability.getSeverity()));
                }
            } else {
                // Platform-agnostic (or single OS): one fix per product
                String singleOs = osFamilies.size() == 1 ? osFamilies.iterator().next() : null;
                FixRecord fix = generateSingleFixRecord(
                        tenant, cveId, vulnerability, productMap,
                        referenceUrls, targets, osPlatforms, relatedCveIds, fixedVersionsFromIntel, singleOs);
                if (fix == null) {
                    fix = buildFallbackFix(tenant, cveId, vulnerability, productMap, referenceUrls, relatedCveIds);
                }
                records.add(persistRecommendation(fix, vulnerability.getSeverity()));
            }
        }

        if (records.isEmpty()) {
            records.add(persistRecommendation(
                    buildFallbackFix(tenant, cveId, vulnerability, softwareMap, referenceUrls, relatedCveIds),
                    vulnerability.getSeverity()));
        }

        return records.stream().map(this::toResponse).toList();
    }

    // ── private helpers ────────────────────────────────────────────────────────

    /**
     * Saves a Workbench recommendation with its Fix Intelligence classification (title,
     * ecosystem, severity) and links every CVE it names, so it appears in Fix Intelligence
     * alongside patch-tool records.
     */
    private FixRecord persistRecommendation(FixRecord record, String vulnerabilitySeverity) {
        if (record.getTitle() == null) record.setTitle(record.getSummary());
        if (record.getEcosystem() == null) record.setEcosystem(ecosystemFor(record.getOsHint()));
        if (record.getSeverity() == null) record.setSeverity(normalizeSeverity(vulnerabilitySeverity));
        FixRecord saved = fixRecordRepository.save(record);
        if (fixRecordCveRepository != null) {
            Set<String> cves = new LinkedHashSet<>();
            if (saved.getCveId() != null) cves.add(saved.getCveId());
            cves.addAll(parseStringList(saved.getRelatedCveIdsJson()));
            for (String cve : cves) {
                if (cve == null || !cve.matches("^CVE-\\d{4}-\\d{4,}$")) continue;
                if (fixRecordCveRepository.findByFixIdAndCveId(saved.getId(), cve).isEmpty()) {
                    com.prototype.vulnwatch.domain.FixRecordCve link = new com.prototype.vulnwatch.domain.FixRecordCve();
                    link.setTenant(saved.getTenant());
                    link.setFixId(saved.getId());
                    link.setCveId(cve);
                    link.setSource("RECOMMENDATION");
                    link.setConfidence("MEDIUM");
                    link.setCreatedAt(Instant.now());
                    fixRecordCveRepository.save(link);
                }
            }
        }
        return saved;
    }

    static FixRecord.Ecosystem ecosystemFor(String osHint) {
        if (osHint == null) return FixRecord.Ecosystem.CROSS_PLATFORM;
        return switch (osHint.trim().toLowerCase(java.util.Locale.ROOT)) {
            case "windows" -> FixRecord.Ecosystem.WINDOWS;
            case "linux" -> FixRecord.Ecosystem.LINUX;
            case "macos" -> FixRecord.Ecosystem.MACOS;
            default -> FixRecord.Ecosystem.CROSS_PLATFORM;
        };
    }

    static String normalizeSeverity(String severity) {
        if (severity == null) return null;
        String upper = severity.trim().toUpperCase(java.util.Locale.ROOT);
        return Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE").contains(upper) ? upper : null;
    }

    /**
     * Find other CVEs in the tenant that affect the same software packages and
     * share at least one fixed version — i.e. the same upgrade fixes both.
     */
    private List<String> findRelatedCveIds(
            Tenant tenant, String cveId,
            Map<String, SoftwareContext> softwareMap,
            List<String> fixedVersions
    ) {
        if (softwareMap.isEmpty() || fixedVersions.isEmpty()) return List.of();
        try {
            Set<String> packageKeys = softwareMap.keySet();
            return orgCveRecordRepository.findBySuppressedByRuleIdIsNull()
                    .stream()
                    .filter(r -> !cveId.equals(r.getExternalId()))
                    .filter(r -> r.getApplicabilityState() == ApplicabilityState.APPLICABLE)
                    .filter(r -> r.getVulnerability() != null)
                    .filter(r -> {
                        // Check if this other CVE has overlapping applicable software
                        List<ComponentVulnerabilityState> otherStates = cvsRepository
                                .findByVulnerability_Id(r.getVulnerability().getId())
                                .stream()
                                .filter(s -> s.getComponent() != null
                                        && s.getApplicabilityState() == ApplicabilityState.APPLICABLE)
                                .toList();
                        for (ComponentVulnerabilityState s : otherStates) {
                            String key = s.getComponent().getEcosystem() + ":" + s.getComponent().getPackageName();
                            if (packageKeys.contains(key)) return true;
                        }
                        return false;
                    })
                    .filter(r -> {
                        // Check if the other CVE shares at least one fixed version
                        List<String> otherFixed = vulnTargetRepository
                                .findByVulnerability(r.getVulnerability())
                                .stream()
                                .filter(t -> t.getFixedVersion() != null && !t.getFixedVersion().isBlank())
                                .map(VulnerabilityTarget::getFixedVersion)
                                .distinct()
                                .toList();
                        return fixedVersions.stream().anyMatch(otherFixed::contains);
                    })
                    .map(OrgCveRecord::getExternalId)
                    .distinct()
                    .limit(10)
                    .toList();
        } catch (Exception e) {
            log.warn("Related CVE lookup failed for {}: {}", LogUtil.safe(cveId), e.getMessage());
            return List.of();
        }
    }

    /**
     * Generates a SINGLE comprehensive fix record per CVE.
     * Combines primary fix (UPGRADE/PATCH) + compensating controls + timeline + rollback
     * into one structured JSON stored in the description field.
     */
    private FixRecord generateSingleFixRecord(
            Tenant tenant, String cveId, Vulnerability vulnerability,
            Map<String, SoftwareContext> softwareMap, List<String> referenceUrls,
            List<VulnerabilityTarget> targets, Set<String> osPlatforms,
            List<String> relatedCveIds, List<String> fixedVersionsFromIntel,
            String targetOs  // null = all platforms; "Windows"/"Linux"/"macOS" for OS-specific fix
    ) {
        if (!openAiClient.isAvailable()) {
            // AI-off fallback is built from already stored intelligence by the caller. Do not
            // fetch extra advisory payloads for an assistance path that cannot run.
            return null;
        }
        // Fetch advisory content
        String advisoryContent = "";
        if (!referenceUrls.isEmpty()) {
            try {
                advisoryContent = advisoryFetchService.fetchAdvisoryContent(referenceUrls);
            } catch (Exception e) {
                throw new IllegalStateException("Vendor advisory evidence is unavailable", e);
            }
        }
        try {
            String msrc = advisoryFetchService.fetchMsrcPatchInfo(cveId);
            if (!msrc.isBlank()) advisoryContent = (advisoryContent + "\n" + msrc).trim();
        } catch (Exception e) {
            throw new IllegalStateException("MSRC patch evidence is unavailable", e);
        }

        String softwareSummary = softwareMap.values().stream()
                .map(s -> s.ecosystem + ":" + s.name
                        + " " + (s.version != null ? s.version : "?")
                        + " (" + s.assetIds.size() + " assets)"
                        + (s.isEol ? " [EOL" + (s.eolDate != null ? " since " + s.eolDate : "") + "]" : "")
                        + (s.supportPhase != null && !s.supportPhase.isBlank() ? " phase=" + s.supportPhase : ""))
                .collect(Collectors.joining("\n  "));

        String appTargets = targets.stream()
                .filter(t -> t.getCpeDim() != null && !"o".equalsIgnoreCase(t.getCpeDim().getPart()))
                .map(t -> t.getCpeDim().getVendor() + ":" + t.getCpeDim().getProduct()
                        + (t.getCpeDim().getTargetSw() != null ? " (target_sw=" + t.getCpeDim().getTargetSw() + ")" : ""))
                .distinct().limit(10).collect(Collectors.joining(", "));

        String osTargets = targetOs != null ? targetOs
                : (osPlatforms.isEmpty() ? "" : String.join(", ", osPlatforms));
        String severity = vulnerability.getSeverity() != null ? vulnerability.getSeverity() : "UNKNOWN";
        String vulnDescription = vulnerability.getDescriptionSnippet() != null ? vulnerability.getDescriptionSnippet() : "";
        boolean hasEolComponents = softwareMap.values().stream().anyMatch(s -> s.isEol);

        // Collect all versions of this software for supersedence analysis
        List<String> allVersions = softwareMap.values().stream()
                .map(s -> s.version).filter(v -> v != null && !v.isBlank()).distinct().toList();

        String systemPrompt = """
                You are a senior security engineer producing a structured fix record for a vulnerability management platform.
                Return a SINGLE JSON object (not an array) combining the primary fix and compensating controls.

                Required JSON structure:
                {
                  "summary": "<one concise action line naming the specific product and fix>",
                  "fix_type": "<UPGRADE | PATCH | WORKAROUND | CONFIGURATION_CHANGE | EOL_MIGRATION | NO_FIX>",
                  "os_hint": "<Windows | Linux | macOS | null>",
                  "is_supersedence": false,
                  "supersedes": [],
                  "primary_fix": {
                    "action": "<Upgrade | Patch | Configure | Migrate>",
                    "target_version": "<exact fixed version or null>",
                    "patch_id": "<KB number, advisory ID, or null>",
                    "applies_to": "<exact product name and affected versions>",
                    "reboot_required": false,
                    "verification": "<CLI command or UI step to confirm the fix is applied>"
                  },
                  "compensating_controls": [
                    {"control": "<specific control name>", "effort": "Low|Medium|High", "effectiveness": "Low|Medium|High"}
                  ],
                  "rollback_plan": ["<step 1>", "<step 2>"],
                  "lifecycle_warning": null
                }

                Rules:
                - CRITICAL: The fix MUST be for the affected software listed under "Affected software in this organization". \
                  Do NOT generate fixes for any other product mentioned in advisory content or CVE description.
                - Combine ALL fix types (primary upgrade/patch + workarounds) into this SINGLE record.
                - Group ALL affected software versions together — do NOT produce a separate record per version.
                - os_hint: set to the TARGET OS if this fix is platform-specific, otherwise null.
                - Supersedence: if a single patch/upgrade covers multiple listed versions (e.g. upgrading to 97.0 fixes both 95.0 and 96.1), \
                  set is_supersedence=true and list the older versions in "supersedes" (e.g. ["95.0","96.1"]). \
                  Same logic applies for OS patches: if a single KB supersedes all listed OS versions, set is_supersedence=true.
                - lifecycle_warning must be non-null only when a component is EOL.
                - advisory IDs/KB numbers are supplementary to identify the right patch — do not change the primary product target.
                - Output raw JSON only — no markdown fences, no prose outside the JSON.
                """;

        String userPrompt = "CVE: " + cveId
                + "\nSeverity: " + severity
                + "\nDescription: " + vulnDescription
                + "\n\nAffected software in this organization:\n  " + (softwareSummary.isBlank() ? "(none matched)" : softwareSummary)
                + (allVersions.size() > 1 ? "\n\nAll affected versions of this software: " + String.join(", ", allVersions) : "")
                + (fixedVersionsFromIntel.isEmpty() ? "" : "\n\nVendor-confirmed fixed version(s): " + String.join(", ", fixedVersionsFromIntel))
                + (appTargets.isBlank() ? "" : "\n\nCPE application targets: " + appTargets)
                + (osTargets.isBlank() ? "" : "\n\nTarget OS for this fix: " + osTargets)
                + (hasEolComponents ? "\n\nNote: one or more affected components are EOL — set lifecycle_warning accordingly." : "")
                + (!relatedCveIds.isEmpty() ? "\n\nRelated CVEs sharing the same fix: " + String.join(", ", relatedCveIds) : "")
                + (advisoryContent.isBlank() ? "" : "\n\nAdvisory content (supplementary — use only to extract patch IDs/KB numbers for the affected software above):\n"
                        + advisoryContent.substring(0, Math.min(advisoryContent.length(), 6000)));

        String raw = null;
        try {
            raw = openAiClient.chatCompletionJson(systemPrompt, userPrompt, 3000);
        } catch (Exception e) {
            log.warn("OpenAI call failed for fix generation on {}: {}", LogUtil.safe(cveId), e.getMessage());
        }

        if (raw == null || raw.isBlank()) {
            if (!advisoryContent.isBlank()) {
                return buildReferenceFix(tenant, cveId, vulnerability, softwareMap,
                        referenceUrls, advisoryContent, relatedCveIds);
            }
            return null;
        }

        try {
            // Unwrap array if AI returned one anyway
            String jsonObject = raw.trim();
            if (jsonObject.startsWith("[")) {
                com.fasterxml.jackson.databind.JsonNode arr = objectMapper.readTree(jsonObject);
                if (arr.isArray() && arr.size() > 0) {
                    jsonObject = objectMapper.writeValueAsString(arr.get(0));
                }
            }
            Map<String, Object> parsed = objectMapper.readValue(jsonObject, new TypeReference<>() {});
            FixRecord r = new FixRecord();
            r.setTenant(tenant);
            r.setCveId(cveId);
            r.setRelatedCveIdsJson(toJson(relatedCveIds));
            r.setSummary(stringVal(parsed.get("summary"), "Fix for " + cveId));
            r.setDescription(jsonObject); // store the full structured JSON
            r.setFixType(normalizeFixType(stringVal(parsed.get("fix_type"), "PATCH")));
            r.setOsHint(normalizeOsHint(stringVal(parsed.get("os_hint"), null)));
            r.setRecommendationSource(FixRecord.RecommendationSource.AI.name());
            r.setSoftwareEntitiesJson(toJson(buildSoftwareEntityList(softwareMap)));
            r.setSourceUrlsJson(toJson(referenceUrls));
            r.setGeneratedAt(Instant.now());
            return r;
        } catch (Exception e) {
            log.warn("Failed to parse AI fix record for {}: {}", LogUtil.safe(cveId), e.getMessage());
            FixRecord r = new FixRecord();
            r.setTenant(tenant);
            r.setCveId(cveId);
            r.setRelatedCveIdsJson(toJson(relatedCveIds));
            r.setSummary("Remediation guidance for " + cveId);
            r.setDescription(raw.trim());
            r.setFixType(FixRecord.FixType.PATCH.name());
            r.setRecommendationSource(FixRecord.RecommendationSource.AI.name());
            r.setSoftwareEntitiesJson(toJson(buildSoftwareEntityList(softwareMap)));
            r.setSourceUrlsJson(toJson(referenceUrls));
            r.setGeneratedAt(Instant.now());
            return r;
        }
    }

    private FixRecord buildReferenceFix(
            Tenant tenant, String cveId, Vulnerability vulnerability,
            Map<String, SoftwareContext> softwareMap, List<String> referenceUrls,
            String advisoryContent, List<String> relatedCveIds
    ) {
        FixRecord r = new FixRecord();
        r.setTenant(tenant);
        r.setCveId(cveId);
        r.setRelatedCveIdsJson(toJson(relatedCveIds));
        r.setSummary("Apply vendor fix for " + cveId);
        r.setDescription("Advisory content extracted from vendor references:\n\n"
                + advisoryContent.substring(0, Math.min(advisoryContent.length(), 2000)));
        r.setFixType(FixRecord.FixType.PATCH.name());
        r.setRecommendationSource(FixRecord.RecommendationSource.REFERENCE.name());
        r.setSoftwareEntitiesJson(toJson(buildSoftwareEntityList(softwareMap)));
        r.setSourceUrlsJson(toJson(referenceUrls));
        r.setGeneratedAt(Instant.now());
        return r;
    }

    private FixRecord buildFallbackFix(
            Tenant tenant, String cveId, Vulnerability vulnerability,
            Map<String, SoftwareContext> softwareMap, List<String> referenceUrls,
            List<String> relatedCveIds
    ) {
        String severity = vulnerability.getSeverity() != null ? vulnerability.getSeverity() : "UNKNOWN";
        FixRecord r = new FixRecord();
        r.setTenant(tenant);
        r.setCveId(cveId);
        r.setRelatedCveIdsJson(toJson(relatedCveIds));
        r.setSummary("Review vendor advisories for " + cveId + " (" + severity + ")");
        r.setDescription("No verified automated fix is available; generative assistance may be disabled or unavailable. "
                + "Review the CVE references and apply vendor-recommended patches or workarounds for the affected software. "
                + "If a patch is unavailable, consider compensating controls such as network segmentation, "
                + "access restrictions, or temporary disablement of the vulnerable feature.");
        r.setFixType(FixRecord.FixType.WORKAROUND.name());
        r.setRecommendationSource(FixRecord.RecommendationSource.REFERENCE.name());
        r.setSoftwareEntitiesJson(toJson(buildSoftwareEntityList(softwareMap)));
        r.setSourceUrlsJson(toJson(referenceUrls));
        r.setGeneratedAt(Instant.now());
        return r;
    }

    private <T> T executeWrite(java.util.function.Supplier<T> work) {
        if (writeTransactionTemplate == null) {
            return work.get();
        }
        return writeTransactionTemplate.execute(status -> work.get());
    }

    @SuppressWarnings("unchecked")
    private List<String> parseReferenceUrls(String referencesJson) {
        if (referencesJson == null || referencesJson.isBlank()) return List.of();
        try {
            List<Object> parsed = objectMapper.readValue(referencesJson, List.class);
            List<String> urls = new ArrayList<>();
            for (Object item : parsed) {
                if (item instanceof String s) {
                    urls.add(s);
                } else if (item instanceof Map<?, ?> map) {
                    Object url = map.get("url");
                    if (url instanceof String s && !s.isBlank()) urls.add(s);
                }
            }
            return urls;
        } catch (Exception e) {
            return List.of();
        }
    }

    private List<Map<String, Object>> buildSoftwareEntityList(Map<String, SoftwareContext> softwareMap) {
        return softwareMap.values().stream()
                .map(ctx -> {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("name", ctx.name);
                    m.put("ecosystem", ctx.ecosystem);
                    m.put("version", ctx.version);
                    m.put("assetCount", ctx.assetIds.size());
                    return m;
                })
                .toList();
    }

    private String normalizeFixType(String raw) {
        if (raw == null) return FixRecord.FixType.PATCH.name();
        try {
            return FixRecord.FixType.valueOf(raw.toUpperCase().replace(' ', '_')).name();
        } catch (IllegalArgumentException e) {
            return FixRecord.FixType.PATCH.name();
        }
    }

    private String normalizeOsHint(String raw) {
        if (raw == null || raw.equalsIgnoreCase("null")) return null;
        return raw.trim().isEmpty() ? null : raw.trim();
    }

    private static String normalizeOsFamily(String cpePlatform) {
        if (cpePlatform == null) return "";
        String p = cpePlatform.toLowerCase();
        if (p.contains("windows")) return "Windows";
        if (p.contains("linux") || p.contains("ubuntu") || p.contains("debian")
                || p.contains("red_hat") || p.contains("rhel") || p.contains("centos")
                || p.contains("fedora") || p.contains("suse")) return "Linux";
        if (p.contains("mac") || p.contains("macos") || p.contains("darwin")) return "macOS";
        return "";
    }

    private String stringVal(Object o, String defaultValue) {
        if (o == null) return defaultValue;
        String s = String.valueOf(o).trim();
        return s.isEmpty() ? defaultValue : s;
    }

    private String toJson(Object o) {
        try {
            return objectMapper.writeValueAsString(o);
        } catch (Exception e) {
            return "[]";
        }
    }

    private FixRecordResponse toResponse(FixRecord r) {
        return new FixRecordResponse(
                r.getId(),
                r.getCveId(),
                parseStringList(r.getRelatedCveIdsJson()),
                r.getSummary(),
                r.getDescription(),
                r.getFixType(),
                parseSoftwareEntities(r.getSoftwareEntitiesJson()),
                r.getOsHint(),
                r.getRecommendationSource(),
                parseStringList(r.getSourceUrlsJson()),
                r.getGeneratedAt(),
                r.getCreatedAt()
        );
    }

    private List<String> parseStringList(String json) {
        if (json == null || json.isBlank()) return List.of();
        try {
            return objectMapper.readValue(json, new TypeReference<>() {});
        } catch (Exception e) {
            return List.of();
        }
    }

    @SuppressWarnings("unchecked")
    private List<FixRecordResponse.SoftwareEntity> parseSoftwareEntities(String json) {
        if (json == null || json.isBlank()) return List.of();
        try {
            List<Map<String, Object>> raw = objectMapper.readValue(json, new TypeReference<>() {});
            return raw.stream().map(m -> new FixRecordResponse.SoftwareEntity(
                    stringVal(m.get("name"), ""),
                    stringVal(m.get("ecosystem"), ""),
                    stringVal(m.get("version"), null),
                    m.get("assetCount") instanceof Number n ? n.intValue() : 0
            )).toList();
        } catch (Exception e) {
            return List.of();
        }
    }

    // ── inner helper ──────────────────────────────────────────────────────────

    private static class SoftwareContext {
        String name;
        String ecosystem;
        String version;
        boolean isEol;
        String eolDate;
        String supportPhase;
        final Set<UUID> assetIds = new LinkedHashSet<>();
        final Set<String> assetTypes = new LinkedHashSet<>();
    }
}
