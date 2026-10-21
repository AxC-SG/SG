package com.prototype.vulnwatch.service;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.nullable;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.prototype.vulnwatch.domain.SuppressionRule;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.SuppressionRuleRequest;
import com.prototype.vulnwatch.dto.SuppressionRuleResponse;
import com.prototype.vulnwatch.repo.ComponentVulnerabilityStateRepository;
import com.prototype.vulnwatch.repo.FindingRepository;
import com.prototype.vulnwatch.repo.OrgCveRecordRepository;
import com.prototype.vulnwatch.repo.SuppressionRuleRepository;
import com.prototype.vulnwatch.repo.VulnerabilityTargetRepository;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class SuppressionRuleServiceTest {

    @Mock private SuppressionRuleRepository repo;
    @Mock private FindingRepository findingRepository;
    @Mock private OrgCveRecordRepository orgCveRecordRepository;
    @Mock private ComponentVulnerabilityStateRepository cvsRepository;
    @Mock private VulnerabilityTargetRepository vulnTargetRepository;
    @Mock private FindingsScoreService findingsScoreService;
    @Mock private TenantSchemaExecutionService tenantSchemaExecutionService;
    @Mock private TenantWorkRunner tenantWorkRunner;

    private SuppressionRuleService service;

    @BeforeEach
    @SuppressWarnings("unchecked")
    void setUp() {
        lenient().doAnswer(inv -> inv.getArgument(1, Supplier.class).get())
                .when(tenantSchemaExecutionService)
                .run(nullable(Tenant.class), any(Supplier.class));
        lenient().doAnswer(inv -> {
                    inv.getArgument(1, Runnable.class).run();
                    return null;
                })
                .when(tenantSchemaExecutionService)
                .run(nullable(Tenant.class), any(Runnable.class));
        service = new SuppressionRuleService(
                repo,
                findingRepository,
                orgCveRecordRepository,
                cvsRepository,
                vulnTargetRepository,
                findingsScoreService,
                tenantSchemaExecutionService,
                tenantWorkRunner
        );
    }

    private Tenant tenant() {
        Tenant t = new Tenant();
        t.setId(UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"));
        t.setName("Acme");
        t.setSchemaName("tenant_acme");
        return t;
    }

    private SuppressionRule approvedFindingRule(Tenant tenant) {
        SuppressionRule rule = new SuppressionRule();
        ReflectionTestUtils.setField(rule, "id", UUID.fromString("cccccccc-cccc-cccc-cccc-cccccccccccc"));
        rule.setTenant(tenant);
        rule.setName("Suppress low-severity findings");
        rule.setState(SuppressionRule.State.APPROVED);
        rule.setRecordType(SuppressionRule.RecordType.FINDING);
        return rule;
    }

    @Test
    void list_returnsEmptyWhenNoRulesExist() {
        Tenant tenant = tenant();
        when(repo.findAllByOrderByCreatedAtAsc()).thenReturn(List.of());

        List<SuppressionRuleResponse> result = service.list(tenant);

        assertNotNull(result);
        assertEquals(0, result.size());
    }

    @Test
    void list_returnsMappedRulesWithSuppressedCount() {
        Tenant tenant = tenant();
        SuppressionRule rule = approvedFindingRule(tenant);
        when(repo.findAllByOrderByCreatedAtAsc()).thenReturn(List.of(rule));
        when(findingRepository.countBySuppressedByRuleId(rule.getId())).thenReturn(3L);
        when(orgCveRecordRepository.countBySuppressedByRuleId(rule.getId())).thenReturn(0L);

        List<SuppressionRuleResponse> result = service.list(tenant);

        assertEquals(1, result.size());
        assertEquals("Suppress low-severity findings", result.get(0).name());
        assertEquals("APPROVED", result.get(0).state());
        assertEquals(3L, result.get(0).suppressedCount());
    }

    @Test
    void create_savesNewRuleAndReturnsResponse() {
        Tenant tenant = tenant();
        SuppressionRule saved = approvedFindingRule(tenant);
        when(repo.save(any(SuppressionRule.class))).thenReturn(saved);
        when(findingRepository.countBySuppressedByRuleId(any())).thenReturn(0L);
        when(orgCveRecordRepository.countBySuppressedByRuleId(any())).thenReturn(0L);

        SuppressionRuleRequest req = new SuppressionRuleRequest(
                "Suppress low-severity findings", "APPROVED", "FINDING",
                "[]", "AND", "Low risk", null, null
        );

        SuppressionRuleResponse response = service.create(tenant, req);

        assertNotNull(response);
        verify(repo).save(any(SuppressionRule.class));
    }

    @Test
    void update_throwsWhenRuleNotFound() {
        Tenant tenant = tenant();
        UUID ruleId = UUID.fromString("dddddddd-dddd-dddd-dddd-dddddddddddd");
        when(repo.findById(ruleId)).thenReturn(Optional.empty());

        SuppressionRuleRequest req = new SuppressionRuleRequest(
                "Updated", "APPROVED", "FINDING", "[]", "AND", null, null, null
        );

        assertThrows(NoSuchElementException.class, () -> service.update(tenant, ruleId, req));
        verify(repo, never()).save(any());
    }

    @Test
    void update_throwsWhenRuleBelongsToDifferentTenant() {
        Tenant tenant = tenant();
        UUID ruleId = UUID.fromString("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee");

        Tenant otherTenant = new Tenant();
        otherTenant.setId(UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff"));
        SuppressionRule rule = new SuppressionRule();
        rule.setTenant(otherTenant);

        when(repo.findById(ruleId)).thenReturn(Optional.of(rule));

        SuppressionRuleRequest req = new SuppressionRuleRequest(
                "Updated", "APPROVED", "FINDING", "[]", "AND", null, null, null
        );

        assertThrows(NoSuchElementException.class, () -> service.update(tenant, ruleId, req));
    }

    @Test
    void delete_removesRuleFromRepository() {
        Tenant tenant = tenant();
        UUID ruleId = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-000000000001");
        SuppressionRule rule = approvedFindingRule(tenant);

        when(repo.findById(ruleId)).thenReturn(Optional.of(rule));

        service.delete(tenant, ruleId);

        verify(repo).delete(rule);
    }

    @Test
    void delete_throwsWhenRuleNotFound() {
        Tenant tenant = tenant();
        UUID ruleId = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-000000000002");
        when(repo.findById(ruleId)).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class, () -> service.delete(tenant, ruleId));
        verify(repo, never()).delete(any());
    }

    @Test
    void execute_throwsIllegalStateWhenRuleNotApproved() {
        Tenant tenant = tenant();
        UUID ruleId = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-000000000003");

        SuppressionRule draftRule = new SuppressionRule();
        draftRule.setTenant(tenant);
        draftRule.setName("Draft rule");
        draftRule.setState(SuppressionRule.State.DRAFT);
        draftRule.setRecordType(SuppressionRule.RecordType.FINDING);

        when(repo.findById(ruleId)).thenReturn(Optional.of(draftRule));

        assertThrows(IllegalStateException.class, () -> service.execute(tenant, ruleId));
    }

    @Test
    void execute_throwsWhenRuleNotFound() {
        Tenant tenant = tenant();
        UUID ruleId = UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-000000000004");
        when(repo.findById(ruleId)).thenReturn(Optional.empty());

        assertThrows(NoSuchElementException.class, () -> service.execute(tenant, ruleId));
    }

    @Test
    void execute_processesApprovedFindingRuleWithNoMatches() {
        Tenant tenant = tenant();
        UUID ruleId = UUID.fromString("cccccccc-cccc-cccc-cccc-cccccccccccc");
        SuppressionRule rule = approvedFindingRule(tenant);

        when(repo.findById(ruleId)).thenReturn(Optional.of(rule));
        when(findingRepository.findForMaintenance(any(), org.mockito.ArgumentMatchers.isNull())).thenReturn(List.of());

        int suppressed = service.execute(tenant, ruleId);

        assertEquals(0, suppressed);
        verify(findingRepository, never()).saveAll(any());
    }
}
