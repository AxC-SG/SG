-- migration-guard: platform-only
-- Supports DISTINCT canonical_id keyset pagination during publication.
CREATE INDEX CONCURRENTLY IF NOT EXISTS intelligence_candidate_records_canonical_page_idx
    ON platform.intelligence_candidate_records (candidate_id, canonical_id)
    WHERE canonical_id IS NOT NULL;
