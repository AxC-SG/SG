package com.prototype.vulnwatch.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import java.util.UUID;

/** Detail for a workaround, configuration change or compensating control. */
@Entity
@Table(name = "fix_control_details")
public class FixControlDetail {

    @Id
    @Column(name = "fix_id")
    private UUID fixId;

    @ManyToOne(optional = false)
    @JoinColumn(name = "tenant_id")
    private Tenant tenant;

    @Column(name = "control_type", length = 64)
    private String controlType;

    @Column(name = "scope_description", length = 2000)
    private String scopeDescription;

    @Column(name = "verification_method", length = 2000)
    private String verificationMethod;

    @Column(name = "residual_risk", length = 16)
    private String residualRisk;

    public UUID getFixId() { return fixId; }
    public void setFixId(UUID fixId) { this.fixId = fixId; }
    public Tenant getTenant() { return tenant; }
    public void setTenant(Tenant tenant) { this.tenant = tenant; }
    public String getControlType() { return controlType; }
    public void setControlType(String controlType) { this.controlType = controlType; }
    public String getScopeDescription() { return scopeDescription; }
    public void setScopeDescription(String scopeDescription) { this.scopeDescription = scopeDescription; }
    public String getVerificationMethod() { return verificationMethod; }
    public void setVerificationMethod(String verificationMethod) { this.verificationMethod = verificationMethod; }
    public String getResidualRisk() { return residualRisk; }
    public void setResidualRisk(String residualRisk) { this.residualRisk = residualRisk; }
}
