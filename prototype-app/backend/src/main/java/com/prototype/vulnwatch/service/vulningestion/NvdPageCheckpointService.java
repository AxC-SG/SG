package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.service.VulnerabilitySourceFilterConfigService.NvdFilters;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Retains the immutable NVD inputs and commits each page with its normalized evidence. */
@Service
public class NvdPageCheckpointService {
    record Scan(Instant start, Instant end, NvdFilters filters) {}
    record Progress(int nextIndex, int fetched, int inserted, int updated, int reportedTotal, boolean finished) {
        static Progress initial() { return new Progress(0, 0, 0, 0, 0, false); }
    }

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;

    public NvdPageCheckpointService(JdbcTemplate jdbc, ObjectMapper mapper) {
        this.jdbc = jdbc;
        this.mapper = mapper;
    }

    @Transactional
    public Scan open(UUID runId, Scan proposed) {
        jdbc.update("""
                insert into platform.nvd_run_plans(run_id,start_at,end_at,filters)
                select ?,?, ?,?::jsonb where not exists (
                    select 1 from platform.intelligence_staged_records where sync_run_id=?)
                on conflict (run_id) do nothing
                """, runId, timestamp(proposed.start()), timestamp(proposed.end()), encode(proposed.filters()), runId);
        return jdbc.query("""
                select start_at,end_at,filters::text from platform.nvd_run_plans where run_id=?
                """, (rs, index) -> new Scan(instant(rs.getTimestamp(1)), instant(rs.getTimestamp(2)),
                decode(rs.getString(3))), runId).stream().findFirst().orElseThrow(() ->
                new IllegalStateException("NVD run has staged records without a committed checkpoint"));
    }

    Progress load(UUID runId, String window, Set<String> observedIds) {
        var progress = jdbc.query("""
                select next_index,fetched,inserted,updated,reported_total,finished
                from platform.nvd_page_checkpoints where run_id=? and window_key=?
                order by start_index desc limit 1
                """, (rs, index) -> new Progress(rs.getInt(1), rs.getInt(2), rs.getInt(3), rs.getInt(4),
                rs.getInt(5), rs.getBoolean(6)), runId, window).stream().findFirst().orElseGet(Progress::initial);
        if (progress.fetched() > 0) {
            observedIds.addAll(jdbc.queryForList("""
                    select unnest(observed_ids) from platform.nvd_page_checkpoints where run_id=? and window_key=?
                    """, String.class, runId, window));
        }
        if (observedIds.size() != progress.fetched()) {
            throw new IllegalStateException("NVD checkpoint does not match its observation manifest");
        }
        return progress;
    }

    @Transactional
    public void finish(Runnable completion) {
        completion.run();
    }

    @Transactional
    public Progress commit(UUID runId, String window, int start, List<String> observedIds, Supplier<Progress> stage) {
        // Order the lease and evidence locks consistently with the commit fence.
        jdbc.queryForObject("select id from platform.sync_runs where id=? for update", UUID.class, runId);
        Progress progress = stage.get();
        jdbc.update(connection -> {
            var statement = connection.prepareStatement("""
                    insert into platform.nvd_page_checkpoints
                        (run_id,window_key,start_index,next_index,fetched,inserted,updated,reported_total,finished,observed_ids)
                    values (?,?,?,?,?,?,?,?,?,?)
                    """);
            statement.setObject(1, runId);
            statement.setString(2, window);
            statement.setInt(3, start);
            statement.setInt(4, progress.nextIndex());
            statement.setInt(5, progress.fetched());
            statement.setInt(6, progress.inserted());
            statement.setInt(7, progress.updated());
            statement.setInt(8, progress.reportedTotal());
            statement.setBoolean(9, progress.finished());
            statement.setArray(10, connection.createArrayOf("varchar", observedIds.toArray()));
            return statement;
        });
        return progress;
    }

    private String encode(NvdFilters filters) {
        try { return mapper.writeValueAsString(filters); }
        catch (JsonProcessingException failure) { throw new IllegalStateException("Cannot store NVD scan filters", failure); }
    }

    private NvdFilters decode(String filters) {
        try { return mapper.readValue(filters, NvdFilters.class); }
        catch (JsonProcessingException failure) { throw new IllegalStateException("Invalid saved NVD scan filters", failure); }
    }

    private static Timestamp timestamp(Instant value) { return value == null ? null : Timestamp.from(value); }
    private static Instant instant(Timestamp value) { return value == null ? null : value.toInstant(); }
}
