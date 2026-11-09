-- Effective-owner benchmark queries (design §7). Prints EXPLAIN (ANALYZE, BUFFERS) once per query, then p50/p95
-- over :runs executions. Budgets (plan §13): owner filter p95 < 750 ms, single-subject p95 < 250 ms.
\set ON_ERROR_STOP on
SET search_path = bench, public;
SELECT set_config('app.current_tenant_id', '00000000-0000-0000-0000-0000000000be', false);

\echo '== Q1 owner-team filter (first page of open findings owned by one team)'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
SELECT f.id FROM findings f JOIN ownership_effective_assignment e ON e.subject_id = f.ownership_subject_id
 WHERE f.status = 'OPEN' AND e.owner_team_id = md5('team7')::uuid ORDER BY f.id LIMIT 100;
\echo '== Q2 status filter (first page of open UNOWNED/CONFLICT findings)'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
SELECT f.id FROM findings f JOIN ownership_effective_assignment e ON e.subject_id = f.ownership_subject_id
 WHERE f.status = 'OPEN' AND e.ownership_status = 'CONFLICT' ORDER BY f.id LIMIT 100;
\echo '== Q3 ownership coverage count over all open findings'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
SELECT COALESCE(e.ownership_status, 'UNLINKED'), count(*) FROM findings f
  LEFT JOIN ownership_effective_assignment e ON e.subject_id = f.ownership_subject_id
 WHERE f.status = 'OPEN' GROUP BY 1;
\echo '== Q1c owner-team filter from the effective cache'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
SELECT f.id FROM findings f JOIN ownership_effective_cache c ON c.subject_id = f.ownership_subject_id AND c.role = 'TECHNICAL_OWNER'
 WHERE f.status = 'OPEN' AND c.owner_team_id = md5('team7')::uuid ORDER BY f.id LIMIT 100;
\echo '== Q3c ownership coverage count from the effective cache'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
SELECT COALESCE(c.ownership_status, 'UNLINKED'), count(*) FROM findings f
  LEFT JOIN ownership_effective_cache c ON c.subject_id = f.ownership_subject_id AND c.role = 'TECHNICAL_OWNER'
 WHERE f.status = 'OPEN' GROUP BY 1;
\echo '== Q5 cache rows invalidated by a change at one application (path containment)'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
SELECT count(*) FROM ownership_effective_cache WHERE inheritance_path @> ARRAY[md5('app7')::uuid];
\echo '== Q4 single-subject explanation'
EXPLAIN (ANALYZE, BUFFERS, COSTS OFF)
SELECT * FROM ownership_effective_assignment WHERE subject_id = md5('occ12345')::uuid;

DO $$
DECLARE
    q record;
    started timestamptz;
    samples double precision[];
    runs int := current_setting('bench.runs')::int;
BEGIN
    FOR q IN SELECT * FROM (VALUES
        ('Q1 owner-team filter', 750, $q$SELECT count(*) FROM (SELECT f.id FROM bench.findings f JOIN bench.ownership_effective_assignment e ON e.subject_id = f.ownership_subject_id WHERE f.status = 'OPEN' AND e.owner_team_id = %L::uuid ORDER BY f.id LIMIT 100) x$q$),
        ('Q2 status filter', 750, $q$SELECT count(*) FROM (SELECT f.id FROM bench.findings f JOIN bench.ownership_effective_assignment e ON e.subject_id = f.ownership_subject_id WHERE f.status = 'OPEN' AND e.ownership_status = 'CONFLICT' ORDER BY f.id LIMIT 100) x$q$),
        ('Q3 coverage count', 1000, $q$SELECT count(*) FROM (SELECT e.ownership_status, count(*) FROM bench.findings f LEFT JOIN bench.ownership_effective_assignment e ON e.subject_id = f.ownership_subject_id WHERE f.status = 'OPEN' GROUP BY 1) x$q$),
        ('Q1c owner-team filter (cache)', 750, $q$SELECT count(*) FROM (SELECT f.id FROM bench.findings f JOIN bench.ownership_effective_cache c ON c.subject_id = f.ownership_subject_id AND c.role = 'TECHNICAL_OWNER' WHERE f.status = 'OPEN' AND c.owner_team_id = %L::uuid ORDER BY f.id LIMIT 100) x$q$),
        ('Q3c coverage count (cache)', 1000, $q$SELECT count(*) FROM (SELECT c.ownership_status, count(*) FROM bench.findings f LEFT JOIN bench.ownership_effective_cache c ON c.subject_id = f.ownership_subject_id AND c.role = 'TECHNICAL_OWNER' WHERE f.status = 'OPEN' GROUP BY 1) x$q$),
        ('Q5 invalidation page (cache)', 1000, $q$SELECT count(*) FROM (SELECT subject_id FROM bench.ownership_effective_cache WHERE inheritance_path @> ARRAY[%L::uuid] LIMIT 10000) x$q$),
        ('Q4 single subject', 250, $q$SELECT count(*) FROM bench.ownership_effective_assignment WHERE subject_id = %L::uuid$q$)
    ) AS t(name, budget_ms, sql) LOOP
        samples := '{}';
        FOR i IN 1..runs LOOP
            started := clock_timestamp();
            -- Bind a fresh literal per sample: a volatile expression in the predicate would defeat the index.
            EXECUTE format(q.sql, CASE WHEN q.name LIKE 'Q1%' THEN md5('team' || (1 + floor(random() * 200))::int)
                                       WHEN q.name LIKE 'Q5%' THEN md5('app' || (21 + floor(random() * 1980))::int)
                                       ELSE md5('occ' || (1 + floor(random() * 1000))::int) END);
            samples := samples || extract(epoch FROM clock_timestamp() - started) * 1000;
        END LOOP;
        RAISE NOTICE '% : p50 % ms, p95 % ms, budget % ms -> %', q.name,
            round((SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY s) FROM unnest(samples) s)::numeric, 1),
            round((SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY s) FROM unnest(samples) s)::numeric, 1), q.budget_ms,
            CASE WHEN (SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY s) FROM unnest(samples) s) <= q.budget_ms THEN 'PASS' ELSE 'MISS' END;
    END LOOP;
END $$;
