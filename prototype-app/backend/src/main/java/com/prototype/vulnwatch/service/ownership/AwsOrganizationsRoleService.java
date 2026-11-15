package com.prototype.vulnwatch.service.ownership;

import com.prototype.vulnwatch.client.AwsOrganizationsClient;
import com.prototype.vulnwatch.client.AwsOrganizationsClient.AwsOrganizationsException;
import com.prototype.vulnwatch.service.AuditEventService;
import com.prototype.vulnwatch.service.TenantContext;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.server.ResponseStatusException;

/**
 * The optional AWS Organizations role for account tags (Phase 0B §2.2.1): its ARN and external ID on
 * {@code aws_discovery_configs}, and its connection test ({@code DescribeAccount}). The external ID is tenant
 * ciphertext and write-only: it is never returned, and changing the role ARN needs it again. Needs
 * {@code CONFIGURE_OWNERSHIP_PRODUCER}; every change and test is audited without the values.
 */
@Service
public class AwsOrganizationsRoleService {

    public record RoleRequest(String roleArn, String externalId) { }

    public record RoleView(boolean configured, String roleArn, boolean externalIdSet) { }

    public record TestResult(boolean succeeded, String code, String message, String accountId, String accountName) { }

    static final Pattern ROLE_ARN = Pattern.compile("^arn:aws(-[a-z]+)*:iam::\\d{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$");
    private static final Pattern EXTERNAL_ID = Pattern.compile("^[A-Za-z0-9+=,.@:/_-]{2,1224}$");

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final AwsAccountTagReader reader;
    private final AwsOrganizationsClient organizations;
    private final com.prototype.vulnwatch.security.tenantkey.TenantDataCipher cipher;
    private final AuditEventService audit;

    public AwsOrganizationsRoleService(JdbcTemplate jdbc, TransactionTemplate tx, AwsAccountTagReader reader,
                                       AwsOrganizationsClient organizations,
                                       com.prototype.vulnwatch.security.tenantkey.TenantDataCipher cipher, AuditEventService audit) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.reader = reader;
        this.organizations = organizations;
        this.cipher = cipher;
        this.audit = audit;
    }

    public RoleView view() {
        return tx.execute(status -> {
            List<Map<String, Object>> rows = jdbc.queryForList(
                    "SELECT organizations_role_arn, organizations_external_id IS NOT NULL AS has_external_id FROM aws_discovery_configs ORDER BY created_at LIMIT 1");
            if (rows.isEmpty()) return new RoleView(false, null, false);
            String arn = (String) rows.get(0).get("organizations_role_arn");
            return new RoleView(arn != null && !arn.isBlank(), arn, Boolean.TRUE.equals(rows.get(0).get("has_external_id")));
        });
    }

    /** Sets or clears (blank ARN) the role. A new or changed ARN must come with its external ID. */
    public RoleView configure(RoleRequest request, String actor) {
        UUID tenant = TenantContext.getCurrentTenantId();
        String arn = request.roleArn() == null ? "" : request.roleArn().strip();
        String externalId = request.externalId() == null ? null : request.externalId().strip();
        tx.executeWithoutResult(status -> {
            List<Map<String, Object>> rows = jdbc.queryForList("SELECT id, organizations_role_arn FROM aws_discovery_configs ORDER BY created_at LIMIT 1");
            if (rows.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Configure the AWS connector first");
            UUID id = (UUID) rows.get(0).get("id");
            if (arn.isEmpty()) {
                jdbc.update("UPDATE aws_discovery_configs SET organizations_role_arn = NULL, organizations_external_id = NULL, updated_at = now() WHERE id = ?", id);
                return;
            }
            if (!ROLE_ARN.matcher(arn).matches()) throw bad("Enter an IAM role ARN such as arn:aws:iam::123456789012:role/OwnershipTags");
            boolean changed = !arn.equals(rows.get(0).get("organizations_role_arn"));
            if (externalId == null || externalId.isEmpty()) {
                if (changed) throw bad("A new role needs its external ID");
                jdbc.update("UPDATE aws_discovery_configs SET organizations_role_arn = ?, updated_at = now() WHERE id = ?", arn, id);
                return;
            }
            if (!EXTERNAL_ID.matcher(externalId).matches()) throw bad("The external ID has characters AWS does not allow");
            if (!cipher.readiness(tenant).ready()) {
                throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE, "Tenant encryption is not ready, so the external ID cannot be stored");
            }
            String sealed = cipher.encrypt(tenant, AwsAccountTagReader.EXTERNAL_ID_PURPOSE, externalId);
            jdbc.update("UPDATE aws_discovery_configs SET organizations_role_arn = ?, organizations_external_id = ?, updated_at = now() WHERE id = ?",
                    arn, sealed, id);
        });
        Map<String, Object> details = new LinkedHashMap<>();
        details.put("configured", !arn.isEmpty());
        details.put("externalIdChanged", externalId != null && !externalId.isEmpty());
        audit.record("ownership.cloud_producer.organizations_role_updated", "ownership_source", "AWS", OwnershipEvents.json(details));
        return view();
    }

    /**
     * Assumes the role and describes the connector's account (or {@code accountId}). Not transactional: the AWS calls
     * run with no database transaction open.
     */
    public TestResult test(String accountId, String actor) {
        Optional<AwsAccountTagReader.Configuration> configuration = tx.execute(status -> reader.configuration());
        if (configuration == null || configuration.isEmpty()) throw new ResponseStatusException(HttpStatus.NOT_FOUND, "No AWS Organizations role is configured");
        String target = accountId != null && !accountId.isBlank() ? accountId.strip() : configuration.get().runtimeConfig().getAwsAccountId();
        if (target == null || !target.matches("\\d{12}")) throw bad("Name the 12-digit account to describe");
        TestResult result;
        try {
            AwsOrganizationsClient.AccountDescription account = organizations.describeAccount(reader.credentials(configuration.get()), target);
            result = new TestResult(true, null, "The role can read this account in AWS Organizations", account.accountId(), account.name());
        } catch (AwsOrganizationsException failure) {
            result = new TestResult(false, failure.code(), failure.getMessage(), target, null);
        } catch (RuntimeException failure) {
            result = new TestResult(false, "ASSUME_ROLE_FAILED", "The Organizations role could not be assumed", target, null);
        }
        audit.record("ownership.cloud_producer.organizations_role_tested", "ownership_source", "AWS",
                OwnershipEvents.json(Map.of("succeeded", result.succeeded(), "code", String.valueOf(result.code()))));
        return result;
    }

    private static ResponseStatusException bad(String message) {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST, message);
    }
}
