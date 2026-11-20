# Large-volume intelligence publication rollout

## Invariants

- Source acquisition and platform correlation do not depend on tenant software inventory.
- Tenant applicability and findings are evaluated after catalog activation.
- No partial active catalog may become visible when a worker pauses, crashes, or retries.
- An activity cursor is not a committed resume checkpoint. UI/API must distinguish them.
- An import profile's year means the source publication date in UTC, never the identifier year.
- Missing records in a filtered or incomplete import do not establish withdrawal evidence.
- Manual/full imports require review; automatic scheduled publication must select only scheduled scope-compatible runs.

## Existing local publication

The active legacy publication started on November 19, 2026 around 07:43 IST.
Candidate: `ce4ddff7-174b-4906-91dc-7738eba2505e`.
Publication job: `21367da2-387b-4309-8f9e-1c6109e5e640`.
API and worker use separate processes on ports 8080 and 8081.
Do not activate new runtime code by restarting this worker without first checking its
transaction and evaluating the cost of discarding uncommitted work.

## Qualification gates

1. Compile backend and typecheck frontend; run focused behavioral tests.
2. Apply new migrations to a disposable database and validate table/index/control contracts.
3. Verify telemetry commits while a publication holds its candidate row lock.
4. Verify pause/cancel visibility and activation fencing from competing connections.
5. Run an NVD profile with an empty tenant inventory; assert year, score and severity boundaries,
   retained source artifacts, scope-specific watermarks and no implied withdrawals.
6. Crash a version builder after a committed batch; resume without duplicates or skipped rows.
7. Compare old and new catalog readers before activation; assert active reads remain unchanged.
8. Activate once under competing workers; verify complete data and tenant delivery generation.
9. Benchmark realistic artifact distributions and capture elapsed time, batch rate, database
   I/O, heap usage, connection usage and failure recovery. Do not infer percentage from activity alone.

## Deployment requirements

Telemetry and profile migrations must precede runtime code using them. New concurrent indexes
require nontransactional migration configuration. Preserve all existing source evidence,
published releases, tenant records and secrets. No AWS deployment is authorized by this local
implementation task. Full-volume acceptance remains separate from unit or synthetic database tests.

## Implementation status — November 19

Implemented: independent progress/activity persistence, platform-owner progress/control endpoints,
review-screen operations UI, scoped NVD profile save/run/schedule endpoints and filtering,
scope-compatible predecessor expansion, canonical lookup caching and direct keyset scans.
An isolated canonical projection version store supports committed batches, fencing, replay,
stale-base checks and pointer activation, behind `app.intelligence.isolated-catalog.enabled=true`.

Not yet complete: replacing the legacy full-artifact catalog readers/writers with this version
store, resumable live artifact application, bulk correlation/write benchmarking, independent
profile filters for non-NVD sources, and full-volume runtime qualification. Do not enable the
projection switch as a replacement for the production catalog: its active pointer currently
governs only isolated canonical projections. Legacy pause rolls back; resume restarts.

No new runtime has been activated and no current publication has been cancelled for this work.
