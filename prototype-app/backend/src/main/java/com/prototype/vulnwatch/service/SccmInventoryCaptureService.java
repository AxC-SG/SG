package com.prototype.vulnwatch.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SccmCmdbConfig;
import com.prototype.vulnwatch.dto.CmdbInventorySyncResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.function.IntConsumer;
import java.util.regex.Pattern;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/** Collects a complete SCCM query before publishing any of its rows to inventory. */
@Service
public class SccmInventoryCaptureService {
    private static final int MAX_INSTALL_ROWS = 1_000_000;
    private static final long MAX_CAPTURE_BYTES = 512L * 1024 * 1024;
    private static final int MAX_ROW_BYTES = 16 * 1024;
    private static final int MAX_HOST_ROWS = 10_000;
    private static final int MAX_HOST_BYTES = 8 * 1024 * 1024;
    private static final int DISCOVERY_BATCH_SIZE = 500;
    private static final int PURGE_BATCH_SIZE = 1000;
    private static final Pattern RESOURCE_ID = Pattern.compile("-?[0-9]{1,10}");
    private static final TypeReference<Map<String, String>> ROW_TYPE = new TypeReference<>() {};

    private final JdbcTemplate jdbc;
    private final TransactionTemplate transactions;
    private final ObjectMapper mapper;
    private final SccmQueryService query;
    private final CmdbIngestionService inventory;

    public SccmInventoryCaptureService(JdbcTemplate jdbc, TransactionTemplate transactions, ObjectMapper mapper,
            SccmQueryService query, CmdbIngestionService inventory) {
        this.jdbc = jdbc;
        this.transactions = transactions;
        this.mapper = mapper;
        this.query = query;
        this.inventory = inventory;
    }

    boolean exists(UUID runId) {
        return Boolean.TRUE.equals(jdbc.queryForObject(
                "select exists (select 1 from sccm_inventory_captures where run_id=?)", Boolean.class, runId));
    }

    CmdbInventorySyncResponse collectAndIngest(SccmCmdbConfig config, UUID runId, String source,
            CmdbIngestionService.HostInventorySourceDescriptor descriptor, IntConsumer collectedProgress) throws Exception {
        Timestamp revision = Timestamp.from(config.getUpdatedAt());
        transactions.executeWithoutResult(status -> jdbc.update("""
                insert into sccm_inventory_captures (run_id, config_revision)
                select id, ? from platform.sync_runs
                where id=? and tenant_id=? and sync_type='SCCM_CMDB'
                on conflict (run_id) do nothing
                """, revision, runId, config.getTenant().getId()));
        List<Boolean> state = jdbc.queryForList("""
                select sealed from sccm_inventory_captures where run_id=? and config_revision=?
                """, Boolean.class, runId, revision);
        if (state.isEmpty()) throw new IllegalStateException("SCCM capture no longer matches its connector configuration");
        if (!state.get(0)) {
            // An interrupted SQL Server cursor cannot be reopened at a trustworthy offset.
            // Until the query has finished, its staged rows can always be discarded.
            drainStage(runId);
            var collector = new Collector(runId, collectedProgress);
            query.forEachInstallPage(config, collector::stagePage);
            seal(runId);
        }
        while (Boolean.TRUE.equals(transactions.execute(status -> applyNext(config, runId, source, descriptor)))) {
            // Each transaction consumes one complete host or a bounded batch of discovery models.
        }
        String json = jdbc.queryForObject("select result::text from sccm_inventory_captures where run_id=?",
                String.class, runId);
        if (json != null) return decodeResult(json);
        return emptyResult(source);
    }

    private void seal(UUID runId) {
        transactions.executeWithoutResult(status -> {
            boolean oversizedHost = Boolean.TRUE.equals(jdbc.queryForObject("""
                    select exists (
                      select row_key from sccm_inventory_capture_rows where run_id=? and section='INSTALL'
                      group by row_key having count(*)>? or sum(octet_length(payload::text))>?
                    )
                    """, Boolean.class, runId, MAX_HOST_ROWS, MAX_HOST_BYTES));
            if (oversizedHost) throw new IllegalStateException("SCCM inventory exceeded its per-host limit");
            jdbc.update("update sccm_inventory_captures set sealed=true where run_id=?", runId);
        });
    }

    private boolean applyNext(SccmCmdbConfig config, UUID runId, String source,
            CmdbIngestionService.HostInventorySourceDescriptor descriptor) {
        String prior = jdbc.queryForObject("""
                select result::text from sccm_inventory_captures where run_id=? and sealed for update
                """, String.class, runId);
        List<StagedRow> rows = jdbc.query("""
                select row_key, payload::text from sccm_inventory_capture_rows
                where run_id=? and section='DISCOVERY' order by row_key limit ?
                """, (rs, index) -> new StagedRow(rs.getString(1), decodeRow(rs.getString(2))), runId, DISCOVERY_BATCH_SIZE);
        if (!rows.isEmpty()) {
            var result = inventory.ingestRows(config.getTenant(), source, List.of(),
                    rows.stream().map(StagedRow::payload).toList(), descriptor);
            jdbc.batchUpdate("""
                    delete from sccm_inventory_capture_rows where run_id=? and section='DISCOVERY' and row_key=?
                    """, rows.stream().map(row -> new Object[] {runId, row.key()}).toList());
            saveProgress(runId, prior, result);
            return true;
        }
        List<String> nextHost = jdbc.queryForList("""
                select row_key from sccm_inventory_capture_rows where run_id=? and section='INSTALL'
                order by row_key limit 1
                """, String.class, runId);
        if (nextHost.isEmpty()) return false;
        String host = nextHost.get(0);
        List<Map<String, String>> installs = jdbc.query("""
                select payload::text from sccm_inventory_capture_rows
                where run_id=? and section='INSTALL' and row_key=? order by sequence_no
                """, (rs, index) -> decodeRow(rs.getString(1)), runId, host);
        var result = inventory.ingestRows(config.getTenant(), source, installs, List.of(), descriptor);
        jdbc.update("delete from sccm_inventory_capture_rows where run_id=? and section='INSTALL' and row_key=?",
                runId, host);
        saveProgress(runId, prior, result);
        return true;
    }

    void finish(UUID runId) {
        jdbc.update("delete from sccm_inventory_captures where run_id=? and sealed", runId);
    }

    void discard(UUID runId) {
        drainStage(runId);
        transactions.executeWithoutResult(status -> jdbc.update(
                "delete from sccm_inventory_captures where run_id=?", runId));
    }

    void pruneTerminalCaptures() {
        List<UUID> expired = jdbc.query("""
                select capture.run_id from sccm_inventory_captures capture
                join platform.sync_runs run on run.id=capture.run_id and run.tenant_id=capture.tenant_id
                where run.status in ('completed', 'failed')
                order by run.completed_at limit 1
                """, (rs, row) -> rs.getObject(1, UUID.class));
        if (!expired.isEmpty()) {
            UUID runId = expired.get(0);
            transactions.executeWithoutResult(status -> {
                if (deletePage(runId) == 0) {
                    jdbc.update("delete from sccm_inventory_captures where run_id=?", runId);
                }
            });
        }
    }

    private void drainStage(UUID runId) {
        int deleted;
        do {
            deleted = transactions.execute(status -> deletePage(runId));
        } while (deleted > 0);
    }

    private int deletePage(UUID runId) {
        return jdbc.update("""
                delete from sccm_inventory_capture_rows where ctid in (
                    select ctid from sccm_inventory_capture_rows where run_id=? limit ?
                )
                """, runId, PURGE_BATCH_SIZE);
    }

    private void saveProgress(UUID runId, String prior, CmdbInventorySyncResponse delta) {
        var total = prior == null ? delta : plus(decodeResult(prior), delta);
        jdbc.update("update sccm_inventory_captures set result=cast(? as jsonb) where run_id=?", json(total), runId);
    }

    private static CmdbInventorySyncResponse plus(CmdbInventorySyncResponse a, CmdbInventorySyncResponse b) {
        return new CmdbInventorySyncResponse(b.sourceSystem(), a.installRowsProcessed() + b.installRowsProcessed(),
                a.discoveryRowsProcessed() + b.discoveryRowsProcessed(), a.unmatchedDiscoveryRows() + b.unmatchedDiscoveryRows(),
                a.assetsIngested() + b.assetsIngested(), a.ciCreated() + b.ciCreated(), a.ciAliasesCreated() + b.ciAliasesCreated(),
                a.softwareInstancesCreated() + b.softwareInstancesCreated(), a.softwareInstancesUpdated() + b.softwareInstancesUpdated(),
                a.inventoryComponentsCreated() + b.inventoryComponentsCreated(),
                a.inventoryComponentsUpdated() + b.inventoryComponentsUpdated(),
                a.findingsRecomputed() + b.findingsRecomputed(), b.message());
    }

    private static CmdbInventorySyncResponse emptyResult(String source) {
        return new CmdbInventorySyncResponse(source.trim().toLowerCase(Locale.ROOT), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                "CMDB host software sync completed");
    }

    private String json(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JsonProcessingException failure) {
            throw new IllegalStateException("Could not stage SCCM inventory", failure);
        }
    }

    private Map<String, String> decodeRow(String payload) {
        try {
            return mapper.readValue(payload, ROW_TYPE);
        } catch (JsonProcessingException failure) {
            throw new IllegalStateException("Could not read staged SCCM inventory", failure);
        }
    }

    private CmdbInventorySyncResponse decodeResult(String payload) {
        try {
            return mapper.readValue(payload, CmdbInventorySyncResponse.class);
        } catch (JsonProcessingException failure) {
            throw new IllegalStateException("Could not read SCCM inventory progress", failure);
        }
    }

    private record StagedRow(String key, Map<String, String> payload) {}

    private final class Collector {
        private final UUID runId;
        private final IntConsumer progress;
        private int observed;
        private long payloadBytes;

        private Collector(UUID runId, IntConsumer progress) {
            this.runId = runId;
            this.progress = progress;
        }

        private void stagePage(List<Map<String, String>> page) {
            if (page.size() > MAX_INSTALL_ROWS - observed) {
                throw new IllegalStateException("SCCM inventory exceeded its row limit");
            }
            List<Object[]> args = new ArrayList<>();
            int sequence = observed;
            for (Map<String, String> row : page) {
                String host = row.get("sys_id");
                if (host == null || !RESOURCE_ID.matcher(host).matches()) {
                    throw new IllegalStateException("SCCM inventory returned an invalid resource ID");
                }
                args.add(new Object[] {runId, "INSTALL", host, sequence++, encodeRow(row)});
            }
            for (Map<String, String> row : query.buildDiscoveryRows(page)) {
                args.add(new Object[] {runId, "DISCOVERY", row.get("primary_key"), 0, encodeRow(row)});
            }
            int count = sequence;
            transactions.executeWithoutResult(status -> jdbc.batchUpdate("""
                    insert into sccm_inventory_capture_rows(run_id, section, row_key, sequence_no, payload)
                    values (?, ?, ?, ?, cast(? as jsonb)) on conflict do nothing
                    """, args));
            observed = count;
            progress.accept(observed);
        }

        private String encodeRow(Map<String, String> row) {
            String payload = json(row);
            int bytes = payload.getBytes(StandardCharsets.UTF_8).length;
            if (bytes > MAX_ROW_BYTES || bytes > MAX_CAPTURE_BYTES - payloadBytes) {
                throw new IllegalStateException("SCCM inventory exceeded its payload limit");
            }
            payloadBytes += bytes;
            return payload;
        }
    }
}
