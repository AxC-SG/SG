# Import profile execution status

Profiles filter platform source intelligence independently of tenant inventory.
Year limits use source publication timestamps in UTC, never the CVE identifier year.
NVD records are filtered before observation and associated artifact staging.

## Current acquisition limitation

Manual and scheduled profile runs currently execute an NVD baseline scan. Publication
year, numeric CVSS and severity predicates are applied locally after acquisition.
Consequently a scheduled profile can download the full NVD corpus again each day.
The profile completion watermark is isolated but is not yet a resumable acquisition
cursor. This implementation must not be described as efficient incremental ingestion.

## Required acquisition follow-up

Use NVD `pubStartDate` and `pubEndDate` query parameters to acquire the selected
publication-year interval in bounded windows of at most 120 days. Checkpoint each
successfully completed window within the immutable profile scope. Track baseline
completion separately from last-modified coverage. Following baseline completion,
fetch overlapping last-modified windows using that scope's own checkpoint and retain
the publication-year predicate for every returned record. Account for API-supported
combinations of publication and modification filters before combining them.

Never advance an ordinary NVD watermark from a profile scan. Never infer withdrawals
from absence in a filtered response. Explicit source withdrawals need their own
coverage semantics. Unknown scores are included when no score bounds are configured.

Only NVD is supported; saving other source selections returns an explicit error.
Schedule auto-publication predecessor isolation still requires coordination with the
publication owner: do not silently include unpublished manual/full runs.
