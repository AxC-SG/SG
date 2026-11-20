package com.prototype.vulnwatch.service;

import com.prototype.vulnwatch.domain.Tenant;
import com.prototype.vulnwatch.repo.FindingDeltaQueueEntryRepository;
import java.util.Collection;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionTemplate;

/** Coalesces inventory summary and organization CVE refreshes by tenant and subject. */
@Service
public class InventoryRollupWorker {
    private static final Logger LOG = LoggerFactory.getLogger(InventoryRollupWorker.class);
    private static final int BATCH_SIZE = 50;
    private static final String SOFTWARE_IDENTITY = "SOFTWARE_IDENTITY";
    private static final String ORG_CVE = "ORG_CVE";

    private final JdbcTemplate jdbc;
    private final NamedParameterJdbcTemplate namedJdbc;
    private final FindingDeltaQueueEntryRepository findingQueue;
    private final TenantService tenants;
    private final TenantSchemaExecutionService schemas;
    private final SoftwareIdentitySummaryProjectionService softwareSummaries;
    private final OrgCveRecordService orgCves;
    private final BackgroundTaskExecutionPolicy background;
    private final TransactionTemplate transactions;

    public InventoryRollupWorker(JdbcTemplate jdbc, NamedParameterJdbcTemplate namedJdbc,
            FindingDeltaQueueEntryRepository findingQueue, TenantService tenants, TenantSchemaExecutionService schemas,
            SoftwareIdentitySummaryProjectionService softwareSummaries, OrgCveRecordService orgCves,
            BackgroundTaskExecutionPolicy background, PlatformTransactionManager manager) {
        this.jdbc = jdbc;
        this.namedJdbc = namedJdbc;
        this.findingQueue = findingQueue;
        this.tenants = tenants;
        this.schemas = schemas;
        this.softwareSummaries = softwareSummaries;
        this.orgCves = orgCves;
        this.background = background;
        this.transactions = new TransactionTemplate(manager);
        this.transactions.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
    }

    boolean enqueueOrgCveRollups(UUID tenantId, Collection<UUID> vulnerabilityIds) {
        if (!findingQueue.usesIncrementalInventoryCorrelation(tenantId)) return false;
        var params = new MapSqlParameterSource("tenantId", tenantId).addValue("ids", vulnerabilityIds);
        namedJdbc.update("""
                insert into inventory_rollup_queue (tenant_id, rollup_kind, subject_id)
                select :tenantId, 'ORG_CVE', id from platform.vulnerabilities where id in (:ids) order by id
                on conflict (rollup_kind, subject_id) do update
                    set marked_at=least(inventory_rollup_queue.marked_at, excluded.marked_at)
                """, params);
        return true;
    }

    @Scheduled(fixedDelayString = "${app.correlation.inventory-rollup-poll-ms:3000}")
    public void poll() {
        if (!background.allowsBackgroundTask("inventory-rollup.poll")) return;
        for (Tenant tenant : TenantContext.runAsPlatform(tenants::listActiveTenants)) {
            try {
                drainBatch(tenant);
            } catch (RuntimeException failure) {
                LOG.warn("Inventory rollup batch for tenant {} will be retried", tenant.getId(), failure);
            }
        }
    }

    void drainBatch(Tenant tenant) {
        schemas.run(tenant, () -> transactions.executeWithoutResult(status -> {
            List<Rollup> pending = jdbc.query("""
                    select rollup_kind, subject_id from inventory_rollup_queue
                    where tenant_id=? order by marked_at, rollup_kind, subject_id limit ? for update skip locked
                    """, (rs, index) -> new Rollup(rs.getString(1), rs.getObject(2, UUID.class)),
                    tenant.getId(), BATCH_SIZE);
            if (pending.isEmpty()) return;
            List<UUID> identities = subjectIds(pending, SOFTWARE_IDENTITY);
            List<UUID> vulnerabilities = subjectIds(pending, ORG_CVE);
            if (!identities.isEmpty()) softwareSummaries.refreshByIdentityIds(tenant.getId(), identities);
            if (!vulnerabilities.isEmpty()) orgCves.refreshForTenantAndVulnerabilities(tenant, vulnerabilities);
            jdbc.batchUpdate("delete from inventory_rollup_queue where tenant_id=? and rollup_kind=? and subject_id=?",
                    pending, BATCH_SIZE, (ps, item) -> {
                        ps.setObject(1, tenant.getId());
                        ps.setString(2, item.kind());
                        ps.setObject(3, item.subject());
                    });
        }));
    }

    private static List<UUID> subjectIds(List<Rollup> pending, String kind) {
        return pending.stream().filter(item -> kind.equals(item.kind())).map(Rollup::subject).toList();
    }

    private record Rollup(String kind, UUID subject) {}
}
