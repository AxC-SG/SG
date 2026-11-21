package com.prototype.vulnwatch.service.vulningestion;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.prototype.vulnwatch.domain.SyncRun;
import java.util.Collection;
import java.util.HashSet;
import java.util.UUID;
import java.util.function.Supplier;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;

/** Pins a provider request and commits advancement only with the corresponding staged evidence. */
@Service
public class FeedRunCheckpointService {
    record Progress(int nextBatch, String cursor, Integer reportedTotal,
                    int fetched, int inserted, int updated, int failed, boolean finished) {
        static Progress initial() { return new Progress(0, null, null, 0, 0, 0, 0, false); }

        Progress advance(String nextCursor, Integer total, Counts counts, boolean finished) {
            return new Progress(nextBatch + 1, nextCursor, total, fetched + counts.fetched(),
                    inserted + counts.inserted(), updated + counts.updated(), failed + counts.failed(), finished);
        }
    }

    record Counts(int fetched, int inserted, int updated, int failed) {}
    record RunScope<T>(T input, Progress progress) {}

    private final JdbcTemplate jdbc;
    private final ObjectMapper mapper;
    private final VulnerabilityAttemptService attempts;
    private final TransactionTemplate transactions;

    public FeedRunCheckpointService(JdbcTemplate jdbc, ObjectMapper mapper, VulnerabilityAttemptService attempts,
            PlatformTransactionManager manager) {
        this.jdbc = jdbc;
        this.mapper = mapper;
        this.attempts = attempts;
        this.transactions = new TransactionTemplate(manager);
    }

    <T> RunScope<T> open(SyncRun run, String source, Class<T> type, Supplier<T> inputs) {
        var saved = jdbc.query("""
                select source,scope::text,next_batch,cursor_value,reported_total,fetched,inserted,updated,failed,finished
                from platform.feed_run_checkpoints where run_id=?
                """, (rs, row) -> {
            if (!source.equals(rs.getString(1))) throw new IllegalStateException("Feed checkpoint source changed");
            return new RunScope<>(decode(rs.getString(2), type), new Progress(rs.getInt(3), rs.getString(4),
                    rs.getObject(5, Integer.class), rs.getInt(6), rs.getInt(7), rs.getInt(8), rs.getInt(9), rs.getBoolean(10)));
        }, run.getId()).stream().findFirst();
        if (saved.isPresent()) return saved.get();

        T input = inputs.get();
        transactions.executeWithoutResult(status -> {
            lockRun(run);
            int created = jdbc.update("""
                    insert into platform.feed_run_checkpoints(run_id,source,scope)
                    select ?,?,?::jsonb where not exists (
                        select 1 from platform.intelligence_staged_records where sync_run_id=?)
                    on conflict (run_id) do nothing
                    """, run.getId(), source, encode(input), run.getId());
            if (created != 1) throw new IllegalStateException("Feed has staged records without a committed checkpoint");
        });
        return new RunScope<>(input, Progress.initial());
    }

    @Transactional
    public Progress commit(SyncRun run, Progress prior, String consumedCursor, Collection<String> recordKeys,
            String nextCursor, Integer reportedTotal, boolean finished, Supplier<Counts> stage) {
        lockRun(run);
        if (prior.finished() || !Boolean.TRUE.equals(jdbc.queryForObject("""
                select exists(select 1 from platform.feed_run_checkpoints
                    where run_id=? and next_batch=? and not finished)
                """, Boolean.class, run.getId(), prior.nextBatch()))) {
            throw new IllegalStateException("Feed checkpoint position changed before commit");
        }

        recordKeys(run.getId(), "RECORD", recordKeys);
        if (consumedCursor != null) recordKeys(run.getId(), "CURSOR", java.util.List.of(consumedCursor));
        if (nextCursor != null && Boolean.TRUE.equals(jdbc.queryForObject("""
                select exists(select 1 from platform.feed_run_checkpoint_keys
                    where run_id=? and key_kind='CURSOR' and key_value=?)
                """, Boolean.class, run.getId(), nextCursor))) {
            throw new IllegalStateException("Feed returned a repeated pagination cursor");
        }

        Progress settled = prior.advance(nextCursor, reportedTotal, stage.get(), finished);
        jdbc.update("""
                update platform.feed_run_checkpoints set next_batch=?,cursor_value=?,reported_total=?,
                    fetched=?,inserted=?,updated=?,failed=?,finished=? where run_id=?
                """, settled.nextBatch(), settled.cursor(), settled.reportedTotal(), settled.fetched(), settled.inserted(),
                settled.updated(), settled.failed(), settled.finished(), run.getId());
        jdbc.update("""
                update platform.sync_runs set records_fetched=?, records_inserted=?, records_updated=?, records_failed=?
                where id=?
                """, settled.fetched(), settled.inserted(), settled.updated(), settled.failed(), run.getId());
        return settled;
    }

    @Transactional
    public void finish(Runnable completion) { completion.run(); }

    private void lockRun(SyncRun run) {
        if (run.getClaimToken() != null) attempts.requireOwned(run.getId());
        else jdbc.queryForObject("select id from platform.sync_runs where id=? for update", UUID.class, run.getId());
    }

    private void recordKeys(UUID runId, String kind, Collection<String> keys) {
        if (keys.isEmpty()) return;
        if (keys.stream().anyMatch(key -> key == null || key.isBlank()) || new HashSet<>(keys).size() != keys.size()) {
            throw new IllegalStateException("Feed returned a missing or repeated " + kind.toLowerCase(java.util.Locale.ROOT));
        }
        int inserted = jdbc.update(connection -> {
            var statement = connection.prepareStatement("""
                    insert into platform.feed_run_checkpoint_keys(run_id,key_kind,key_value)
                    select ?,?,key from unnest(?::text[]) key on conflict do nothing
                    """);
            statement.setObject(1, runId);
            statement.setString(2, kind);
            statement.setArray(3, connection.createArrayOf("text", keys.toArray()));
            return statement;
        });
        if (inserted != keys.size()) throw new IllegalStateException("Feed returned a previously committed "
                + kind.toLowerCase(java.util.Locale.ROOT));
    }

    private String encode(Object value) {
        try { return mapper.writeValueAsString(value); }
        catch (JsonProcessingException failure) { throw new IllegalStateException("Cannot store feed checkpoint inputs", failure); }
    }

    private <T> T decode(String value, Class<T> type) {
        try { return mapper.readValue(value, type); }
        catch (JsonProcessingException failure) { throw new IllegalStateException("Invalid saved feed checkpoint inputs", failure); }
    }
}
