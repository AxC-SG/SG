package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Finding;
import com.prototype.vulnwatch.domain.FindingStatus;
import com.prototype.vulnwatch.domain.OrgCveRecord;
import com.prototype.vulnwatch.domain.SuppressionRule;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SuppressionRuleRequest;
import com.prototype.vulnwatch.dto.SuppressionRuleResponse;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.SuppressionRuleRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class SuppressionRuleService {
    private static final Logger LOG = LoggerFactory.getLogger(SuppressionRuleService.class);

    private final SuppressionRuleRepository repo;
    private final FindingRepository findingRepository;
    private final OrgCveRecordRepository orgCveRecordRepository;
    private final ComponentVulnerabilityStateRepository cvsRepository;
    private final VulnerabilityTargetRepository vulnTargetRepository;
    private final FindingsScoreService findingsScoreService;
    private final TenantSchemaExecutionService tenantSchemaExecutionService;
    private final TenantWorkRunner tenantWorkRunner;
    private BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy = BackgroundTaskExecutionPolicy.allowAll();
    private TransactionTemplate readTransactionTemplate;
    private TransactionTemplate writeTransactionTemplate;
    private CanonicalSuppressionMutationService suppressionMutations;
    private AuditEventService auditEventService;

    public SuppressionRuleService(
            SuppressionRuleRepository repo,
            FindingRepository findingRepository,
            OrgCveRecordRepository orgCveRecordRepository,
            ComponentVulnerabilityStateRepository cvsRepository,
            VulnerabilityTargetRepository vulnTargetRepository,
            FindingsScoreService findingsScoreService,
            TenantSchemaExecutionService tenantSchemaExecutionService,
            TenantWorkRunner tenantWorkRunner
    ) {
        this.repo = repo;
        this.findingRepository = findingRepository;
        this.orgCveRecordRepository = orgCveRecordRepository;
        this.cvsRepository = cvsRepository;
        this.vulnTargetRepository = vulnTargetRepository;
        this.findingsScoreService = findingsScoreService;
        this.tenantSchemaExecutionService = tenantSchemaExecutionService;
        this.tenantWorkRunner = tenantWorkRunner;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setBackgroundTaskExecutionPolicy(BackgroundTaskExecutionPolicy backgroundTaskExecutionPolicy) {
        this.backgroundTaskExecutionPolicy = backgroundTaskExecutionPolicy == null
                ? BackgroundTaskExecutionPolicy.allowAll()
                : backgroundTaskExecutionPolicy;
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setTransactionManager(PlatformTransactionManager transactionManager) {
        if (transactionManager == null) {
            this.readTransactionTemplate = null;
            this.writeTransactionTemplate = null;
            return;
        }
        this.readTransactionTemplate = new TransactionTemplate(transactionManager);
        this.readTransactionTemplate.setReadOnly(true);
        this.readTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
        this.writeTransactionTemplate = new TransactionTemplate(transactionManager);
        this.writeTransactionTemplate.setReadOnly(false);
        this.writeTransactionTemplate.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    @org.springframework.beans.factory.annotation.Autowired
    public void setSuppressionDependencies(
            CanonicalSuppressionMutationService suppressionMutations,
            AuditEventService auditEventService
    ) {
        this.suppressionMutations = suppressionMutations;
        this.auditEventService = auditEventService;
    }

    public List<SuppressionRuleResponse> list(Tenant tenant) {
        return tenantSchemaExecutionService.run(tenant, () -> executeRead(() -> repo.findAllByOrderByCreatedAtAsc()
                .stream()
                .map(this::toResponseInCurrentTenantSchema)
                .toList()));
    }

    public SuppressionRuleResponse create(Tenant tenant, SuppressionRuleRequest req) {
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            SuppressionRule rule = new SuppressionRule();
            rule.setTenant(tenant);
            applyRequest(rule, req);
            return toResponseInCurrentTenantSchema(repo.save(rule));
        }));
    }

    public SuppressionRuleResponse update(Tenant tenant, UUID id, SuppressionRuleRequest req) {
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            SuppressionRule rule = repo.findById(id)
                    .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                    .orElseThrow(() -> new NoSuchElementException("Suppression rule not found: " + id));
            applyRequest(rule, req);
            rule.touch();
            return toResponseInCurrentTenantSchema(repo.save(rule));
        }));
    }

    public void delete(Tenant tenant, UUID id) {
        tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            SuppressionRule rule = repo.findById(id)
                    .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                    .orElseThrow(() -> new NoSuchElementException("Suppression rule not found: " + id));
            repo.delete(rule);
            return null;
        }));
    }

    /**
     * Evaluates an APPROVED rule against all matching records for the tenant.
     * For FINDING rules: processes OPEN findings.
     * For CVE rules: processes OrgCveRecords not yet suppressed by any rule.
     *
     * @return count of newly suppressed records
     * @throws IllegalStateException if the rule is not APPROVED
     */
    public int execute(Tenant tenant, UUID ruleId) {
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            SuppressionRule rule = repo.findById(ruleId)
                    .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                    .orElseThrow(() -> new NoSuchElementException("Suppression rule not found: " + ruleId));

            if (rule.getState() != SuppressionRule.State.APPROVED) {
                throw new IllegalStateException(
                        "Only APPROVED rules can be executed. Rule \"" + rule.getName() + "\" is " + rule.getState() + ".");
            }

            if (rule.getRecordType() == SuppressionRule.RecordType.CVE) {
                return executeCveRuleInCurrentTenantSchema(rule);
            }
            return executeFindingRuleInCurrentTenantSchema(rule);
        }));
    }

    /**
     * Reopens all CVE records and findings suppressed by the given rule, and returns
     * the total number of records cleared.
     */
    public int reopenAllByRule(Tenant tenant, UUID ruleId) {
        return tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            repo.findById(ruleId)
                    .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                    .orElseThrow(() -> new NoSuchElementException("Suppression rule not found: " + ruleId));

            List<OrgCveRecord> cveRecords = orgCveRecordRepository.findBySuppressedByRuleId(ruleId);
            for (OrgCveRecord record : cveRecords) {
                record.setSuppressedByRuleId(null);
                record.setSuppressedByRuleName(null);
                record.setSuppressedBy(null);
                record.setSuppressedAt(null);
                record.setSuppressedUntil(null);
                record.setSuppressionReason(null);
                record.touch();
            }
            if (!cveRecords.isEmpty()) {
                orgCveRecordRepository.saveAll(cveRecords);
            }

            List<Finding> findings = findingRepository.findBySuppressedByRuleId(ruleId);
            for (Finding finding : findings) {
                suppressionMutations.reopen(finding, "suppression-rule", "SUPPRESSION_RULE_REVERSED",
                        "Finding reopened because its suppression rule was reversed");
            }
            if (!findings.isEmpty()) {
                findingRepository.saveAll(findings);
            }

            return cveRecords.size() + findings.size();
        }));
    }

    /**
     * Reopens an OrgCveRecord from rule-based suppression by clearing the rule reference.
     */
    public void reopenCveRecord(Tenant tenant, UUID recordId) {
        tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
            OrgCveRecord record = orgCveRecordRepository.findById(recordId)
                    .filter(r -> r.getTenant().getId().equals(tenant.getId()))
                    .orElseThrow(() -> new NoSuchElementException("CVE record not found: " + recordId));
            record.setSuppressedByRuleId(null);
            record.setSuppressedByRuleName(null);
            record.setSuppressedBy(null);
            record.setSuppressedAt(null);
            record.setSuppressedUntil(null);
            record.setSuppressionReason(null);
            record.touch();
            orgCveRecordRepository.save(record);
            return null;
        }));
    }

    /** Nightly job — runs all APPROVED rules for every tenant at midnight. */
    @Scheduled(zone = "UTC", cron = "0 0 0 * * *")
    public void runAllApprovedRulesNightly() {
        if (!backgroundTaskExecutionPolicy.allowsBackgroundTask("suppression-rule.run-approved-rules-nightly")) {
            return;
        }
        tenantWorkRunner.forEachActiveTenant(tenant ->
                tenantSchemaExecutionService.run(tenant, () -> executeWrite(() -> {
                    for (SuppressionRule rule : repo.findAllForUpdate()) {
                        if (rule.getState() == SuppressionRule.State.APPROVED) {
                            if (rule.getRecordType() == SuppressionRule.RecordType.CVE) {
                                executeCveRuleInCurrentTenantSchema(rule);
                            } else {
                                executeFindingRuleInCurrentTenantSchema(rule);
                            }
                        }
                    }
                    return null;
                }))
        );
    }

    // ── private helpers ──────────────────────────────────────────────────────

    private int executeFindingRuleInCurrentTenantSchema(SuppressionRule rule) {
        List<Finding> openFindings = findingRepository.findForMaintenance(FindingStatus.OPEN, null);

        List<Finding> toSuppress = new ArrayList<>();
        int deniedCount = 0;
        for (Finding finding : openFindings) {
            if (finding.getVulnerability() == null
                    || finding.getAsset() == null
                    || finding.getComponent() == null) {
                continue;
            }
            if (findingsScoreService.matchesSuppressionConditions(
                    rule.getConditionsJson(), rule.getConditionLogic(), finding)) {
                try {
                    suppressionMutations.suppress(finding, rule.getReason(), null, rule.getId(), rule.getName(),
                            SuppressionMutationSource.AUTOMATED_RULE, "suppression-rule:" + rule.getId());
                    toSuppress.add(finding);
                } catch (CryptoSuppressionPolicyException denied) {
                    deniedCount++;
                    // Policy denials are finding-local. The rest of the nightly batch continues.
                    auditEventService.record("finding.suppression.rule_denied", "finding", finding.getId().toString(),
                            "{\"ruleId\":\"" + rule.getId() + "\",\"reasonCode\":\""
                                    + denied.getReasonCode() + "\"}", "DENIED");
                }
            }
        }

        if (!toSuppress.isEmpty()) {
            findingRepository.saveAll(toSuppress);
        }
        if (deniedCount > 0) {
            LOG.info("Suppression rule {} applied={} denied_by_crypto_policy={}",
                    rule.getId(), toSuppress.size(), deniedCount);
        }
        return toSuppress.size();
    }

    private int executeCveRuleInCurrentTenantSchema(SuppressionRule rule) {
        // Only process records not yet suppressed by any rule
        List<OrgCveRecord> candidates = orgCveRecordRepository.findBySuppressedByRuleIdIsNullOrderById();

        if (candidates.isEmpty()) {
            return 0;
        }

        // Batch-load all CVS and VulnerabilityTarget data for all candidate vulnerabilities
        // to avoid N+1 queries (one per record in a loop).
        List<UUID> vulnIds = candidates.stream()
                .filter(r -> r.getVulnerability() != null)
                .map(r -> r.getVulnerability().getId())
                .distinct()
                .toList();

        // Map<vulnId, Set<softwareName>> — package names from matched inventory components
        java.util.Map<UUID, java.util.Set<String>> namesByVuln = new java.util.HashMap<>();
        cvsRepository.findByVulnerability_IdIn(vulnIds).forEach(cvs -> {
                    if (cvs.getComponent() != null && cvs.getComponent().getPackageName() != null
                            && !cvs.getComponent().getPackageName().isBlank()) {
                        namesByVuln
                                .computeIfAbsent(cvs.getVulnerability().getId(), k -> new java.util.LinkedHashSet<>())
                                .add(cvs.getComponent().getPackageName());
                    }
                });

        // CPE product + vendor names from VulnerabilityTarget — covers CVEs with no inventory match
        vulnTargetRepository.findByVulnerability_IdIn(vulnIds)
                .forEach(vt -> {
                    if (vt.getCpeDim() != null) {
                        java.util.Set<String> names = namesByVuln
                                .computeIfAbsent(vt.getVulnerability().getId(), k -> new java.util.LinkedHashSet<>());
                        if (vt.getCpeDim().getProduct() != null && !vt.getCpeDim().getProduct().isBlank()) {
                            names.add(vt.getCpeDim().getProduct());
                        }
                        if (vt.getCpeDim().getVendor() != null && !vt.getCpeDim().getVendor().isBlank()) {
                            names.add(vt.getCpeDim().getVendor());
                        }
                    }
                });

        List<OrgCveRecord> toSuppress = new ArrayList<>();
        Instant now = Instant.now();
        for (OrgCveRecord record : candidates) {
            if (record.getVulnerability() == null) continue;

            List<String> packageNames = new ArrayList<>(
                    namesByVuln.getOrDefault(record.getVulnerability().getId(), java.util.Set.of()));

            if (findingsScoreService.matchesCveSuppressionConditions(
                    rule.getConditionsJson(), rule.getConditionLogic(), record, packageNames)) {
                record.setSuppressedByRuleId(rule.getId());
                record.setSuppressedByRuleName(rule.getName());
                record.setSuppressedBy("RULE:" + rule.getName());
                record.setSuppressionReason(rule.getReason());
                record.setSuppressedAt(now);
                record.setSuppressedUntil(null);
                record.touch();
                toSuppress.add(record);
            }
        }

        if (!toSuppress.isEmpty()) {
            orgCveRecordRepository.saveAll(toSuppress);
        }
        return toSuppress.size();
    }

    private void applyRequest(SuppressionRule rule, SuppressionRuleRequest req) {
        if (req.name() != null) {
            rule.setName(req.name());
        }
        if (req.state() != null) {
            rule.setState(SuppressionRule.State.valueOf(req.state()));
        }
        if (req.recordType() != null) {
            rule.setRecordType(SuppressionRule.RecordType.valueOf(req.recordType()));
        }
        if (req.conditionsJson() != null) {
            rule.setConditionsJson(req.conditionsJson());
        }
        if (req.conditionLogic() != null) {
            rule.setConditionLogic(req.conditionLogic());
        }
        rule.setReason(req.reason());
        rule.setValidFrom(req.validFrom() != null ? Instant.parse(req.validFrom()) : null);
        rule.setValidTo(req.validTo() != null ? Instant.parse(req.validTo()) : null);
    }

    private SuppressionRuleResponse toResponseInCurrentTenantSchema(SuppressionRule r) {
        long suppressedCount = findingRepository.countBySuppressedByRuleId(r.getId())
                + orgCveRecordRepository.countBySuppressedByRuleId(r.getId());
        return new SuppressionRuleResponse(
                r.getId(),
                r.getName(),
                r.getState().name(),
                r.getRecordType().name(),
                r.getConditionsJson(),
                r.getConditionLogic(),
                r.getReason(),
                r.getValidFrom(),
                r.getValidTo(),
                r.getCreatedAt(),
                r.getUpdatedAt(),
                suppressedCount
        );
    }

    private <T> T executeRead(java.util.function.Supplier<T> work) {
        if (readTransactionTemplate == null) {
            return work.get();
        }
        T result = readTransactionTemplate.execute(status -> work.get());
        return result == null ? work.get() : result;
    }

    private <T> T executeWrite(java.util.function.Supplier<T> work) {
        if (writeTransactionTemplate == null) {
            return work.get();
        }
        return writeTransactionTemplate.execute(status -> work.get());
    }
}
