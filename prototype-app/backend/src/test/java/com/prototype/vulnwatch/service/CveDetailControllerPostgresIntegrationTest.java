package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static com.prototype.vulnwatch.support.AuthRequest.authedGet;
import static com.prototype.vulnwatch.support.AuthRequest.authedPost;
import static com.prototype.vulnwatch.support.AuthRequest.authedPut;

import com.prototype.vulnwatch.domain.Asset;
import com.prototype.vulnwatch.domain.AssetType;
import com.prototype.vulnwatch.domain.ApplicabilityAssessment;
import com.prototype.vulnwatch.domain.ApplicabilityState;
import com.prototype.vulnwatch.domain.ComponentVulnerabilityState;
import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingDecisionState;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.ImpactState;
import com.prototype.vulnwatch.domain.InventoryComponent;
import com.prototype.vulnwatch.domain.InventoryComponentStatus;
import com.prototype.vulnwatch.domain.Investigation;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.OrgCveAiArtifact;
import com.prototype.vulnwatch.domain.SbomFormat;
import com.prototype.vulnwatch.domain.SbomUpload;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.domain.Vulnerability;
import com.prototype.vulnwatch.domain.VulnerabilitySource;
import com.prototype.vulnwatch.domain.VulnerabilityTarget;
import com.prototype.vulnwatch.domain.VulnerabilityTargetType;
import com.prototype.vulnwatch.domain.VexAssertion;
import com.prototype.vulnwatch.repo.ApplicabilityAssessmentRepository;
import com.prototype.vulnwatch.repo.AssetRepository;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.InventoryComponentRepository;
import com.prototype.vulnwatch.repo.InvestigationRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.OrgCveAiArtifactRepository;
import com.prototype.vulnwatch.repo.SbomUploadRepository;
import com.prototype.vulnwatch.repo.TenantRepository;
import com.prototype.vulnwatch.repo.VexAssertionRepository;
import com.prototype.vulnwatch.repo.VulnerabilityRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import com.prototype.vulnwatch.support.LocalPostgresTestDatabase;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionTemplate;

@SpringBootTest(properties = {
        "app.security.api-key=test-api-key",
        "app.security.creator-key=test-creator-key",
        "app.tenancy.require-tenant-context=false",
        "app.schema-migration.legacy-test-runner-enabled=true",
        "app.correlation.backfill-targets-on-startup=false"
})
@AutoConfigureMockMvc
@ActiveProfiles("postgres")
@EnabledIfSystemProperty(named = "run.postgres.it", matches = "true")
class CveDetailControllerPostgresIntegrationTest {

    private static final LocalPostgresTestDatabase.DatabaseConfig DATABASE =
            LocalPostgresTestDatabase.provision("cve_detail_controller");

    @DynamicPropertySource
    static void registerDatabaseProperties(DynamicPropertyRegistry registry) {
        registry.add("DB_URL", DATABASE::url);
        registry.add("DB_USERNAME", DATABASE::username);
        registry.add("DB_PASSWORD", DATABASE::password);
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TenantService tenantService;

    @Autowired
    private VulnerabilityRepository vulnerabilityRepository;

    @Autowired
    private InvestigationRepository investigationRepository;

    @Autowired
    private ApplicabilityAssessmentRepository assessmentRepository;

    @Autowired
    private AssetRepository assetRepository;

    @Autowired
    private SbomUploadRepository sbomUploadRepository;

    @Autowired
    private InventoryComponentRepository inventoryComponentRepository;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private ComponentVulnerabilityStateRepository componentVulnerabilityStateRepository;

    @Autowired
    private OrgCveRecordRepository orgCveRecordRepository;

    @Autowired
    private OrgCveAiArtifactRepository orgCveAiArtifactRepository;

    @Autowired
    private VulnerabilityTargetRepository vulnerabilityTargetRepository;

    @Autowired
    private VexAssertionRepository vexAssertionRepository;

    @Autowired
    private TenantRepository tenantRepository;

    @Autowired
    private TransactionTemplate transactionTemplate;

    @Test
    void workbenchPersistsInvestigationAssessmentFindingAndAnalystFixEndToEnd() throws Exception {
        String cveId = "CVE-2099-9920";
        Vulnerability vulnerability = createVulnerability(cveId);
        Tenant tenant = tenantService.getDefaultTenant();
        InventoryComponent component = createComponent(tenant, "workbench-end-to-end");
        ComponentVulnerabilityState state = new ComponentVulnerabilityState();
        state.setTenant(tenant);
        state.setComponent(component);
        state.setVulnerability(vulnerability);
        state.setApplicabilityState(ApplicabilityState.APPLICABLE);
        state.setImpactState(ImpactState.IMPACTED);
        state.setEligibleForFinding(true);
        state.touch();
        componentVulnerabilityStateRepository.save(state);

        mockMvc.perform(authedGet("/api/cve-detail/{cveId}", cveId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.matchedSoftware[0].componentId").value(component.getId().toString()));

        mockMvc.perform(authedPut("/api/cve-detail/{cveId}/investigation/runbook", cveId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"leadAnalyst":"workbench-analyst","agentConfidence":{},"logEntries":[],
                                 "taskStates":[{"taskId":"review-asset-inventory","state":"DONE","producedBy":"ANALYST"}]}
                                """))
                .andExpect(status().isOk());
        mockMvc.perform(authedPost("/api/cve-detail/{cveId}/investigation/submit", cveId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"status":"IN_PROGRESS","assignedTo":"workbench-analyst","notes":"Inventory verified"}
                                """))
                .andExpect(status().isOk());

        mockMvc.perform(authedPost("/api/cve-detail/{cveId}/assessment/submit", cveId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"softwareDetected":true,"finalResult":"AFFECTED","confidenceLevel":"HIGH",
                                 "justification":"Verified affected software","componentAnalystDispositions":{"%s":"IMPACTED"}}
                                """.formatted(component.getId())))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.finalResult").value("AFFECTED"));

        String findingRequest = """
                {"componentIds":["%s"],"justification":"Patch approved","severity":"CRITICAL",
                 "dueDate":"2099-11-01","findingCreationMode":"ASSET_CVE","existingFindingBehavior":"ADD_TO_EXISTING"}
                """.formatted(component.getId());
        mockMvc.perform(authedPost("/api/cve-detail/{cveId}/manual-finding", cveId)
                        .contentType(MediaType.APPLICATION_JSON).content(findingRequest))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.createdCount").value(1));
        mockMvc.perform(authedPost("/api/cve-detail/{cveId}/manual-finding", cveId)
                        .contentType(MediaType.APPLICATION_JSON).content(findingRequest))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.createdCount").value(0))
                .andExpect(jsonPath("$.alreadyOpenCount").value(1));
        var findings = findingRepository.findByTenant_IdAndVulnerability_Id(tenant.getId(), vulnerability.getId());
        assertEquals(1, findings.size());
        assertEquals("CRITICAL", findings.get(0).getSeverityOverride());
        assertEquals(Instant.parse("2099-11-01T00:00:00Z"), findings.get(0).getDueAt());

        mockMvc.perform(authedPost("/api/cve-detail/{cveId}/analyst-fixes", cveId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"solutions":[{"software":"log4j-core","version":"2.17.1","vendor":"Apache",
                                  "fixType":"UPGRADE","solutionText":"Upgrade to the supported version","assetCount":1}]}
                                """))
                .andExpect(status().isOk());

        // Re-read independently of the write responses, as after a browser reload.
        mockMvc.perform(authedGet("/api/cve-detail/{cveId}/investigation/runbook", cveId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.leadAnalyst").value("workbench-analyst"))
                .andExpect(jsonPath("$.taskStates[0].state").value("DONE"));
        mockMvc.perform(authedGet("/api/cve-detail/{cveId}", cveId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.investigations[0].notes").value("Inventory verified"))
                .andExpect(jsonPath("$.assessments[0].finalResult").value("AFFECTED"));
        mockMvc.perform(authedGet("/api/cve-detail/{cveId}/fixes", cveId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].summary").value("Upgrade to the supported version"))
                .andExpect(jsonPath("$[0].softwareEntities[0].name").value("log4j-core"));
    }

    @Test
    void internalTenantCanGenerateAiSolution() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        tenant.setPlanCode("ENTERPRISE");
        tenantRepository.save(tenant);
        String cveId = "CVE-2099-9910";
        createVulnerability(cveId);

        mockMvc.perform(post("/api/cve-detail/{cveId}/ai-solution", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"severity":"HIGH","affected_entities":[]}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").exists());
    }

    @Test
    void enterpriseTenantCanReachAiSolutionEndpoint() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        tenant.setPlanCode("ENTERPRISE");
        tenantRepository.save(tenant);
        String cveId = "CVE-2099-9911";
        createVulnerability(cveId);

        mockMvc.perform(post("/api/cve-detail/{cveId}/ai-solution", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"severity":"HIGH","affected_entities":[]}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").exists());
    }

    @Test
    void internalTenantCanReadSavedAiSolution() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String cveId = "CVE-2099-9912";
        Vulnerability vulnerability = createVulnerability(cveId);
        createSavedAiArtifacts(tenant, vulnerability, true, false, false);

        tenant.setPlanCode("ENTERPRISE");
        tenantRepository.save(tenant);

        mockMvc.perform(get("/api/cve-detail/{cveId}/ai-solution", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").exists());
    }

    @Test
    void internalTenantCanReadSavedAiActions() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String cveId = "CVE-2099-9913";
        Vulnerability vulnerability = createVulnerability(cveId);
        createSavedAiArtifacts(tenant, vulnerability, false, true, false);

        tenant.setPlanCode("ENTERPRISE");
        tenantRepository.save(tenant);

        mockMvc.perform(get("/api/cve-detail/{cveId}/ai-actions", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk());
    }

    @Test
    void internalTenantCanReadSavedAiInvestigationSummary() throws Exception {
        Tenant tenant = tenantService.getDefaultTenant();
        String cveId = "CVE-2099-9914";
        Vulnerability vulnerability = createVulnerability(cveId);
        createSavedAiArtifacts(tenant, vulnerability, false, false, true);

        tenant.setPlanCode("ENTERPRISE");
        tenantRepository.save(tenant);

        mockMvc.perform(get("/api/cve-detail/{cveId}/saved-investigation-summary", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk());
    }

    @Test
    void submitEndpointsUseRealTenantAndPersistWorkflowOnPostgres() throws Exception {
        String cveId = "CVE-2099-9902";
        createVulnerability(cveId);

        mockMvc.perform(post("/api/cve-detail/{cveId}/investigation/submit", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "priority": "HIGH",
                                  "assignedTo": "analyst-a",
                                  "notes": "triage started"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveId").value(cveId))
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"))
                .andExpect(jsonPath("$.priority").value("HIGH"));

        mockMvc.perform(post("/api/cve-detail/{cveId}/investigation/submit", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "priority": "MEDIUM",
                                  "assignedTo": "analyst-b",
                                  "notes": "handoff"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveId").value(cveId))
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"))
                .andExpect(jsonPath("$.priority").value("MEDIUM"));

        mockMvc.perform(post("/api/cve-detail/{cveId}/assessment/submit", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "softwareDetected": true,
                                  "detectionMethod": "sbom",
                                  "affectedComponents": "pkg:maven/example/component",
                                  "vulnerableVersionPresent": true,
                                  "finalResult": "AFFECTED",
                                  "confidenceLevel": "HIGH",
                                  "justification": "validated via inventory",
                                  "recommendedAction": "patch immediately"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveId").value(cveId))
                .andExpect(jsonPath("$.status").value("COMPLETED"))
                .andExpect(jsonPath("$.finalResult").value("AFFECTED"));

        mockMvc.perform(get("/api/cve-detail/{cveId}", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.externalId").value(cveId))
                .andExpect(jsonPath("$.investigations[0].status").value("IN_PROGRESS"))
                .andExpect(jsonPath("$.assessments[0].status").value("COMPLETED"));

        Tenant tenant = tenantService.getDefaultTenant();
        Investigation investigation = investigationRepository.findByTenantIdAndCveId(tenant.getId(), cveId).stream()
                .findFirst()
                .orElseThrow();
        ApplicabilityAssessment assessment = assessmentRepository.findByTenantIdAndCveId(tenant.getId(), cveId).stream()
                .findFirst()
                .orElseThrow();

        assertEquals(Investigation.InvestigationStatus.IN_PROGRESS, investigation.getStatus());
        assertEquals(ApplicabilityAssessment.AssessmentStatus.COMPLETED, assessment.getStatus());
    }

    @Test
    void cveDetailUsesActorTenantUuidForInvestigationsAndAssessments() throws Exception {
        Tenant defaultTenant = createTenant(TenantService.DEFAULT_TENANT_NAME);
        Tenant legacyShadowTenant = createLegacyShadowTenant("Legacy Workspace");
        String cveId = "CVE-2099-9905";
        Vulnerability vulnerability = createVulnerability(cveId);

        investigationRepository.save(createInvestigation(defaultTenant, vulnerability, Investigation.InvestigationStatus.PENDING_REVIEW, "default-tenant"));
        investigationRepository.save(createInvestigation(legacyShadowTenant, vulnerability, Investigation.InvestigationStatus.CLOSED, "legacy-shadow"));

        assessmentRepository.save(createAssessment(defaultTenant, vulnerability, ApplicabilityAssessment.AssessmentResult.AFFECTED, "default-tenant"));
        assessmentRepository.save(createAssessment(legacyShadowTenant, vulnerability, ApplicabilityAssessment.AssessmentResult.NOT_AFFECTED, "legacy-shadow"));

        mockMvc.perform(get("/api/cve-detail/{cveId}", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.investigations[0].status").value("PENDING_REVIEW"))
                .andExpect(jsonPath("$.investigations[0].notes").value("default-tenant"))
                .andExpect(jsonPath("$.assessments[0].finalResult").value("AFFECTED"))
                .andExpect(jsonPath("$.assessments[0].justification").value("default-tenant"));
    }

    @Test
    void submitInvestigationPersistsAgainstActorTenantUuidInsteadOfLegacyShadowTenant() throws Exception {
        Tenant defaultTenant = createTenant(TenantService.DEFAULT_TENANT_NAME);
        Tenant legacyShadowTenant = createLegacyShadowTenant("Legacy Workspace");
        String cveId = "CVE-2099-9906";
        createVulnerability(cveId);

        mockMvc.perform(post("/api/cve-detail/{cveId}/investigation/submit", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "priority": "HIGH",
                                  "notes": "triage on default tenant"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("IN_PROGRESS"))
                .andExpect(jsonPath("$.notes").value("triage on default tenant"));

        assertEquals(1, investigationRepository.findByTenantIdAndCveId(defaultTenant.getId(), cveId).size());
        assertEquals(0, investigationRepository.findByTenantIdAndCveId(legacyShadowTenant.getId(), cveId).size());
    }

    @Test
    void suppressEndpointPersistsOrgCveSuppressionAndSuppressesExistingFindings() throws Exception {
        String cveId = "CVE-2099-9903";
        Vulnerability vulnerability = createVulnerability(cveId);
        Tenant tenant = tenantService.getDefaultTenant();
        InventoryComponent component = createComponent(tenant, "suppression-check");
        createOpenFinding(tenant, component, vulnerability);

        mockMvc.perform(post("/api/cve-detail/{cveId}/suppress", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-User-ID", "test-user")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "reason": "FALSE_POSITIVE",
                                  "justification": "validated compensating control",
                                  "duration": 30
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.cveId").value(cveId))
                .andExpect(jsonPath("$.suppressed").value(true))
                .andExpect(jsonPath("$.reason").value("FALSE_POSITIVE"))
                .andExpect(jsonPath("$.suppressedBy").value("test-user"))
                .andExpect(jsonPath("$.suppressedAt").exists())
                .andExpect(jsonPath("$.expiresAt").exists());

        OrgCveRecord record = orgCveRecordRepository.findByTenantIdAndVulnerability(tenant.getId(), vulnerability)
                .orElseThrow();
        Finding finding = findingRepository.findByTenant_IdAndVulnerability_Id(tenant.getId(), vulnerability.getId()).stream()
                .findFirst()
                .orElseThrow();

        assertEquals("FALSE_POSITIVE", record.getSuppressionReason());
        assertEquals("validated compensating control", record.getSuppressionJustification());
        assertEquals("test-user", record.getSuppressedBy());
        assertNotNull(record.getSuppressedAt());
        assertNotNull(record.getSuppressedUntil());
        assertEquals(FindingStatus.SUPPRESSED, finding.getStatus());
        assertEquals("FALSE_POSITIVE: validated compensating control", finding.getSuppressionReason());
        assertNotNull(finding.getSuppressedUntil());
    }

    @Test
    void getCveDetailHandlesTextPayloadFieldsOnPostgres() throws Exception {
        String cveId = "ADV-DEMO-DETAIL-001";
        Vulnerability vulnerability = createVulnerability(cveId);
        vulnerability.setReferencesJson("""
                [{"url":"https://example.com/advisories/ADV-DEMO-DETAIL-001","source":"unit-test"}]
                """);
        vulnerability = vulnerabilityRepository.save(vulnerability);

        Tenant tenant = tenantService.getDefaultTenant();
        InventoryComponent component = createComponent(tenant, "detail-text");

        ComponentVulnerabilityState state = new ComponentVulnerabilityState();
        state.setTenant(tenant);
        state.setComponent(component);
        state.setVulnerability(vulnerability);
        state.setApplicabilityState(ApplicabilityState.APPLICABLE);
        state.setImpactState(ImpactState.IMPACTED);
        state.setEligibleForFinding(true);
        state.setMatchedBy("advisory-pkg-indexed-exact+version");
        state.setTraceJson("""
                {"matchedBy":"advisory-pkg-indexed-exact+version","why":"postgres-text-regression"}
                """);
        componentVulnerabilityStateRepository.save(state);

        mockMvc.perform(get("/api/cve-detail/{cveId}", cveId)
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.summary.externalId").value(cveId))
                .andExpect(jsonPath("$.matchedSoftware[0].packageName").value("log4j-core"))
                .andExpect(jsonPath("$.matchedSoftware[0].impactState").value("IMPACTED"));
    }

    @Test
    void getVexEvidenceReturnsMatchedAssertionForComponent() throws Exception {
        String cveId = "CVE-2099-9904";
        Vulnerability vulnerability = createVulnerability(cveId);
        Tenant tenant = tenantService.getDefaultTenant();
        InventoryComponent component = createComponent(tenant, "vex-evidence");

        VulnerabilityTarget target = new VulnerabilityTarget();
        target.setVulnerability(vulnerability);
        target.setTargetType(VulnerabilityTargetType.PURL);
        target.setSource("vex-microsoft");
        target.setNormalizedTargetKey("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0");
        target.setEcosystem("maven");
        target.setPackageName("log4j-core");
        target.setVersionExact("2.17.0");
        target = vulnerabilityTargetRepository.save(target);

        VexAssertion assertion = new VexAssertion();
        assertion.setVulnerability(vulnerability);
        assertion.setTarget(target);
        assertion.setSourceSystem("vex-microsoft");
        assertion.setProvider("microsoft");
        assertion.setDocumentId("msrc-2099-9904");
        assertion.setStatementKey("affected::log4j-core::2.17.0");
        assertion.setStatus("AFFECTED");
        assertion.setTrustTier("HIGH");
        assertion.setFreshness("FRESH");
        assertion.setNormalizedProductKey("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0");
        assertion.setPackageName("log4j-core");
        assertion.setVersionExact("2.17.0");
        assertion.setEvidenceJson("""
                {"advisoryUrl":"https://example.test/msrc-2099-9904.json","actionStatement":"Patch immediately"}
                """);
        assertion.setPublishedAt(Instant.parse("2099-01-01T00:00:00Z"));
        assertion.setLastSeenAt(Instant.parse("2099-01-02T00:00:00Z"));
        assertion.touch();
        assertion = vexAssertionRepository.save(assertion);

        ComponentVulnerabilityState state = new ComponentVulnerabilityState();
        state.setTenant(tenant);
        state.setComponent(component);
        state.setVulnerability(vulnerability);
        state.setApplicabilityState(ApplicabilityState.APPLICABLE);
        state.setImpactState(ImpactState.IMPACTED);
        state.setImpactReason("vex_affected");
        state.setImpactReasonDetail("Vendor VEX marks the exact installed software version as affected.");
        state.setMatchedVexAssertionId(assertion.getId());
        state.setEligibleForFinding(true);
        state.touch();
        componentVulnerabilityStateRepository.save(state);

        mockMvc.perform(get("/api/cve-detail/{cveId}/vex-evidence", cveId)
                        .param("componentId", component.getId().toString())
                        .header("X-API-Key", "test-api-key")
                        .header("X-Creator-Key", "test-creator-key")
                        .header("X-User-ID", "test-user"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.matchedVexAssertionId").value(assertion.getId().toString()))
                .andExpect(jsonPath("$.status").value("AFFECTED"))
                .andExpect(jsonPath("$.provider").value("microsoft"))
                .andExpect(jsonPath("$.evidence.advisoryUrl").value("https://example.test/msrc-2099-9904.json"))
                .andExpect(jsonPath("$.impactReason").value("vex_affected"));
    }

    private Vulnerability createVulnerability(String externalId) {
        Vulnerability vulnerability = new Vulnerability();
        vulnerability.setExternalId(externalId);
        vulnerability.setSource(VulnerabilitySource.NVD);
        vulnerability.setTitle("Regression test CVE");
        vulnerability.setDescriptionSnippet("Regression test description");
        vulnerability.setSeverity("HIGH");
        vulnerability.setCvssScore(8.5);
        vulnerability.setPublishedAt(Instant.now());
        vulnerability.setLastModifiedAt(Instant.now());
        return vulnerabilityRepository.save(vulnerability);
    }

    private InventoryComponent createComponent(Tenant tenant, String suffix) {
        Asset asset = new Asset();
        asset.setTenant(tenant);
        asset.setType(AssetType.HOST);
        asset.setName(suffix);
        asset.setIdentifier("asset:" + suffix);
        asset = assetRepository.save(asset);

        SbomUpload sbomUpload = new SbomUpload();
        sbomUpload.setTenant(tenant);
        sbomUpload.setAsset(asset);
        sbomUpload.setFormat(SbomFormat.CYCLONEDX);
        sbomUpload.setOriginalFilename(suffix + ".json");
        sbomUpload = sbomUploadRepository.save(sbomUpload);

        InventoryComponent component = new InventoryComponent();
        component.setTenant(tenant);
        component.setAsset(asset);
        component.setSbomUpload(sbomUpload);
        component.setEcosystem("maven");
        component.setPackageName("log4j-core");
        component.setVersion("2.17.0");
        component.setPurl("pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0");
        component.setComponentStatus(InventoryComponentStatus.ACTIVE);
        return inventoryComponentRepository.save(component);
    }

    private Tenant createTenant(String name) {
        return tenantService.getDefaultTenant();
    }

    private Tenant createLegacyShadowTenant(String name) {
        return tenantRepository.findByNameIgnoreCase(name).orElseGet(() -> {
            Tenant tenant = new Tenant();
            tenant.setName(name);
            tenant.setSchemaName("tenant_legacy_shadow");
            return tenantRepository.save(tenant);
        });
    }

    private Investigation createInvestigation(
            Tenant tenant,
            Vulnerability vulnerability,
            Investigation.InvestigationStatus status,
            String notes
    ) {
        Investigation investigation = new Investigation();
        investigation.setTenant(tenant);
        investigation.setVulnerability(vulnerability);
        investigation.setStatus(status);
        investigation.setPriority(Investigation.InvestigationPriority.MEDIUM);
        investigation.setNotes(notes);
        investigation.setCreatedBy("test-user");
        investigation.setModifiedBy("test-user");
        return investigation;
    }

    private ApplicabilityAssessment createAssessment(
            Tenant tenant,
            Vulnerability vulnerability,
            ApplicabilityAssessment.AssessmentResult finalResult,
            String justification
    ) {
        ApplicabilityAssessment assessment = new ApplicabilityAssessment();
        assessment.setTenant(tenant);
        assessment.setVulnerability(vulnerability);
        assessment.setStatus(ApplicabilityAssessment.AssessmentStatus.COMPLETED);
        assessment.setFinalResult(finalResult);
        assessment.setConfidenceLevel(ApplicabilityAssessment.ConfidenceLevel.HIGH);
        assessment.setJustification(justification);
        assessment.setRecommendedAction("test");
        assessment.setAssessedBy("test-user");
        assessment.setCompletedAt(Instant.now());
        return assessment;
    }

    private void createOpenFinding(Tenant tenant, InventoryComponent component, Vulnerability vulnerability) {
        Finding finding = new Finding();
        finding.setTenant(tenant);
        finding.setAsset(component.getAsset());
        finding.setComponent(component);
        finding.setVulnerability(vulnerability);
        finding.setStatus(FindingStatus.OPEN);
        finding.setDecisionState(FindingDecisionState.AFFECTED);
        finding.setMatchedBy("cpe-indexed-direct+version");
        finding.setRiskScore(9.8);
        finding.setConfidenceScore(0.99);
        finding.setEvidence("{\"source\":\"test\"}");
        finding.setFirstObservedAt(Instant.now());
        finding.setLastObservedAt(Instant.now());
        finding.touch();
        findingRepository.save(finding);
    }

    private void createSavedAiArtifacts(
            Tenant tenant,
            Vulnerability vulnerability,
            boolean includeAiSolution,
            boolean includeAiActions,
            boolean includeAiSummary
    ) {
        transactionTemplate.executeWithoutResult(status -> {
        OrgCveRecord record = new OrgCveRecord();
        record.setTenant(tenant);
        record.setVulnerability(vulnerability);
        record.setExternalId(vulnerability.getExternalId());
        record.setSeverity(vulnerability.getSeverity());
        record.setCvssScore(vulnerability.getCvssScore());
        record.setLastEvaluatedAt(Instant.now());
        record = orgCveRecordRepository.save(record);

        OrgCveAiArtifact artifact = new OrgCveAiArtifact();
        artifact.setOrgCveRecord(record);
        if (includeAiSolution) {
            artifact.setAiSolutionJson("""
                    {"recommendation":"Apply vendor patch"}
                    """);
            artifact.setAiSolutionGeneratedAt(Instant.now());
        }
        if (includeAiActions) {
            artifact.setAiActionsJson("""
                    {"actions":[{"priority":1,"title":"Patch the fleet"}]}
                    """);
            artifact.setAiActionsGeneratedAt(Instant.now());
        }
        if (includeAiSummary) {
            artifact.setInvestigationSummaryInputJson("""
                    {"summary":{"cveId":"%s"}}
                    """.formatted(vulnerability.getExternalId()));
            artifact.setInvestigationSummaryOutputJson("""
                    {"generatedAt":"2099-01-01T00:00:00Z","executiveSummary":"AI summary","riskAnalysis":{"level":"HIGH","score":8,"rationale":"test"},"impactAnalysis":{"externalFacingCount":0,"internalAssetCount":0,"falsePositiveSummary":"none","eolRiskSummary":"none","patchGapSummary":"none"},"remediationPlan":[],"keyFindings":[],"metrics":{"totalAffected":0,"truePositives":0,"falsePositives":0,"externalFacing":0,"unpatchedVulnerable":0,"eolCount":0},"markdownReport":"AI summary"}
                    """);
            artifact.setInvestigationSummaryMode("ai");
            artifact.setInvestigationSummaryGeneratedAt(Instant.now());
        }
        artifact.touch();
        orgCveAiArtifactRepository.save(artifact);
        });
    }
}
