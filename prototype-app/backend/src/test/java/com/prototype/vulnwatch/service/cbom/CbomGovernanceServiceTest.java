package com.prototype.vulnwatch.service.cbom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.CbomComponent;
import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.dto.CbomGovernanceDtos.RuleConfigurationRequest;
import com.prototype.vulnwatch.repo.*;
import com.prototype.vulnwatch.service.*;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

@ExtendWith(MockitoExtension.class)
class CbomGovernanceServiceTest {
    @Mock CbomRuleConfigurationRepository configs; @Mock CbomComponentRepository components;
    @Mock CbomRiskFindingRepository findings; @Mock CbomAssessmentService assessments;
    @Mock RequestActorService actors; @Mock AuditEventService audit; @Mock CbomRuleLifecycleStore lifecycle;
    Tenant tenant; CbomGovernanceService service;

    @BeforeEach void setUp(){
        tenant=new Tenant();tenant.setId(UUID.randomUUID());
        service=new CbomGovernanceService(configs,components,findings,assessments,actors,audit,new ObjectMapper());
        var registry=new CbomRulePackageRegistry(new ObjectMapper(),"classpath:cbom-rules/index.json","");
        service.setRulePackages(registry,new CbomRulePackageService(configs,registry),lifecycle);
    }

    @Test void previewsChangesWithinSafetyBoundsWithoutPersisting(){
        CbomComponent weak=component("RSA",1024);CbomComponent strong=component("RSA",4096);
        when(components.findByTenant_IdAndActiveTrueOrderByNameAsc(tenant.getId())).thenReturn(List.of(weak,strong));
        var preview=service.preview(tenant,new RuleConfigurationRequest("FOLLOW_LATEST",null,
                Map.of("minimumRsaBits",3072),"raise baseline"));
        assertThat(preview.projectedRsaFindings()).isEqualTo(1);
        assertThat(preview.currentRsaFindings()).isEqualTo(1);
        assertThat(preview.safetyBounds()).isNotEmpty();
    }

    @Test void rejectsParametersOutsideApplicationSafetyBounds(){
        assertThatThrownBy(()->service.preview(tenant,new RuleConfigurationRequest("FOLLOW_LATEST",null,
                Map.of("minimumRsaBits",512),"unsafe"))).isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("safety bounds");
    }

    @Test void onlyDirectTenantAdministratorCanActivateConfiguration(){
        when(actors.currentActor()).thenReturn(new RequestActor("support",false,tenant.getId(),"Tenant",
                Set.of("PLATFORM_OWNER"),TenantAccessMode.SUPPORT_WRITE_ENABLED,UUID.randomUUID(),null));
        assertThatThrownBy(()->service.update(tenant,new RuleConfigurationRequest("FOLLOW_LATEST",null,Map.of(),"change")))
                .isInstanceOf(SecurityException.class);
    }

    @Test void classifiesPqcReadinessWithoutTreatingUnknownAsReady(){
        when(components.findByTenant_IdAndActiveTrueOrderByNameAsc(tenant.getId()))
                .thenReturn(List.of(component("RSA",2048),component("ML-KEM",768),component(null,null)));
        var result=service.pqc(tenant);
        assertThat(result.quantumVulnerable()).isEqualTo(1);
        assertThat(result.pqcReady()).isEqualTo(1);
        assertThat(result.unknown()).isEqualTo(1);
    }

    private CbomComponent component(String primitive,Integer bits){CbomComponent c=new CbomComponent();
        ReflectionTestUtils.setField(c,"id",UUID.randomUUID());c.setName(primitive==null?"Unknown":primitive);c.setPrimitive(primitive);c.setKeySize(bits);
        c.setAssetType(com.prototype.vulnwatch.domain.CbomAssetType.ALGORITHM);c.setComponentFingerprint("fp-"+primitive+"-"+bits);return c;}

    @Test void previewCountsWhatTheEngineWillRaiseUnderTheProposedThresholds(){
        CbomComponent rsa2048=component("RSA",2048);
        when(components.findByTenant_IdAndActiveTrueOrderByNameAsc(tenant.getId())).thenReturn(List.of(rsa2048));
        var preview=service.preview(tenant,new RuleConfigurationRequest("FOLLOW_LATEST",null,Map.of("minimumRsaBits",3072),"raise baseline"));
        assertThat(preview.currentRsaFindings()).isZero();
        assertThat(preview.projectedRsaFindings()).isEqualTo(1);
        assertThat(preview.changedParameters()).containsEntry("minimumRsaBits",java.util.Arrays.asList(2048,3072));
    }

    @Test void tenantParametersOverlayPackageDefaultsWithinBounds(){
        var registry=new CbomRulePackageRegistry(new ObjectMapper(),"classpath:cbom-rules/index.json","");
        var packages=new CbomRulePackageService(configs,registry);
        assertThat(packages.parameters(tenant)).isEqualTo(CbomRiskEngine.DEFAULTS);
        var stored=new com.prototype.vulnwatch.domain.CbomRuleConfiguration();stored.setTenantId(tenant.getId());
        stored.setParametersJson("{\"minimumRsaBits\":3072,\"certificateExpiryWarningDays\":5000}");
        when(configs.findById(tenant.getId())).thenReturn(Optional.of(stored));
        assertThat(packages.parameters(tenant)).isEqualTo(new CbomRiskEngine.RuleParameters(3072,90));
    }

    @Test void configurationListsEveryRuleWithThisWorkspacesThresholdsAndOpenFindings(){
        var stored=new com.prototype.vulnwatch.domain.CbomRuleConfiguration();stored.setTenantId(tenant.getId());
        stored.setParametersJson("{\"minimumRsaBits\":3072}");
        when(configs.findById(tenant.getId())).thenReturn(Optional.of(stored));
        when(findings.countOpenByRule(tenant.getId())).thenReturn(List.<Object[]>of(new Object[]{"CBOM-MISSING-USAGE",6L}));
        var rules=service.configuration(tenant).rules();
        assertThat(rules).hasSize(11);
        var rsa=rules.stream().filter(r->r.id().equals("CBOM-RSA-SMALL-KEY")).findFirst().orElseThrow();
        assertThat(rsa.severity()).isEqualTo("HIGH");
        assertThat(rsa.mode()).isEqualTo("mandatory");
        assertThat(rsa.condition()).contains("3072 bits").doesNotContain("{");
        assertThat(rsa.recommendation()).contains("RSA-3072");
        var expiring=rules.stream().filter(r->r.id().equals("CBOM-CERT-EXPIRING")).findFirst().orElseThrow();
        assertThat(expiring.condition()).contains("90 days");
        assertThat(expiring.mode()).isEqualTo("enabled");
        assertThat(rules.stream().filter(r->r.id().equals("CBOM-MISSING-USAGE")).findFirst().orElseThrow().openFindings()).isEqualTo(6);
        assertThat(rules).allSatisfy(r->{assertThat(r.title()).isNotBlank();assertThat(r.category()).isNotBlank();});
    }
}
