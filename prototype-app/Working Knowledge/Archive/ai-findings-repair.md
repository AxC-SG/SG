# AI findings repair

## Behavior changes

Static assessment, customer policy views, default initialization, coverage/readiness, bulk selection, and rollout assessment use the same distributed policy version resolution. A distribution pin wins over an unpublished replacement. Unpinned distributions select an eligible published/canary version deterministically with `NULLS LAST`. Visibility, approval revocation, package digests, and applicable release bindings are checked. Legacy null-mode policies remain supported.

Only saved `TENANT_OVERRIDE` selections override current platform defaults. A saved `PLATFORM_DEFAULT` no longer freezes an old default. Publishing records `ai_grid.policy_defaults.rollout_impact` with the affected tenant/policy pair count before distribution changes. Moving a platform default to PREVIEW/DISABLED withdraws owner-facing findings on reassessment; moving it to ENABLED/REQUIRED can create findings only when current evidence qualifies. Existing explicit tenant choices remain effective.

Collection persists observations, complete scope snapshots, facts, and assessment requests before dispatch. Each applicable policy runs in a separate transaction and persistence context. A failed policy rolls back its own changes, leaves prior findings intact, and records one policy-level `POLICY_EVALUATION_ERROR` gap, an UNKNOWN assessment, and an audit event in a separate transaction. Coverage/readiness and exposure correlation finalize after policy processing. Baseline observations and comparisons remain atomic with their source operation; baseline finding reconciliation runs after commit against the latest observation and approval state. Paused guardrail drift retains its separate release gate.

Current reassessment reads the union of latest COMPLETE connector scope heads, with facts bound to authoritative snapshot manifests and relationships bound to authoritative source runs. Current evidence uses the current time; replay retains the source's captured time and cannot reconcile current findings. Policy edits validate the edited policy before saving, commit accepted configuration, and enqueue targeted reassessment. DISABLED/PREVIEW withdraw findings immediately. Stale evidence preserves prior finding evidence, reports current uncertainty and evidence age, and requests discovery through existing connector admission and job deduplication.

Exposure correlation persists all path observations before reconciling each shared root finding. Any validated open path keeps the finding validated. Hypotheses pause the SLA, preserving its deadline in finding events. The first evidence recovery in an unresolved episode may reset a future deadline once; later recoveries restore the saved deadline, and overdue deadlines receive no extension. Verified closure followed by recurrence starts a new episode. Active timed and indefinite suppressions survive evidence refresh. Only fresh authoritative absence can resolve a path; expired relationships demote it.

Customer finding lists and counts return one row per canonical finding. `EXPOSURE_PATH` subjects have deterministic matching artifact context and associated path summaries. Existing posture fields remain. `executionId` remains nullable and is always null; execution joins and runtime fallback labels are removed. Committed exposure changes refresh the canonical finding projection, including evidence API and scheduler paths.

## Durable delivery

The existing `ai_grid_outbox` stores `STATIC_ASSESSMENT_REQUESTED` events. Other event types are never claimed by the assessment worker. Tenant context is established before every background transaction. Claims use `FOR UPDATE SKIP LOCKED`; JSON claim tokens and expiring leases fence reclaimed workers both before writes and before commit. Recovered requests evaluate current heads and current configuration rather than applying saved obsolete results.

Defaults:

- `app.ai-grid.assessment.poll-ms`: 5000
- `app.ai-grid.assessment.lease-seconds`: 120
- `app.ai-grid.assessment.heartbeat-seconds`: 30
- Five requests per active tenant per polling pass.
- One-minute retry delay for connection, serialization, and deadlock failures, with five total attempts. Validation and constraint failures are terminal immediately.

Terminal and exhausted requests remain in the outbox. `POST /api/ai-assessments/requests/{requestId}/retry` explicitly resets a failed/partial request for delivery. `GET /api/ai-assessments/{runId}/status` and `GET /api/ai-policies/{id}/assessment-status` report assessment completion independently of collection completion. Inspect pending work, terminal failures, attempts, policy-level gaps, audit events, and finding transitions during incremental rollout.

Run, execution, and configuration responses retain existing fields and add collection/assessment status, actual assessed subjects, failed-policy totals, and sanitized failure summaries. Assessment states are PENDING, RUNNING, COMPLETE, PARTIAL, and FAILED. COMPLETE requires successful policies and finalization. PARTIAL includes healthy results alongside failures. First-party consumers keep polling when collection is complete but assessment is pending/running and invalidate policy, findings, readiness, coverage, and exposure queries as results arrive.

## Verification

Focused regression coverage includes all sixteen seeded pin/replacement mismatches, legacy policies and saved defaults, independent malformed-rule/SQL failures, preflight rejection, multi-scope freshness, tenant isolation, concurrent claims, lease reclamation, heartbeat renewal, duplicate delivery, retry classification/exhaustion, suppression, repeated SLA recovery, overdue deadlines, expired edges, canonical pagination, context filters, and projection freshness.

Run backend unit/SpotBugs/coverage checks with `mvn verify`, PostgreSQL checks with `mvn -Ppostgres-it verify`, and frontend checks with `npm run lint`, `npm run typecheck`, `npm run build`, and `npm run test:coverage`. Migration and policy-package CI guards remain applicable. No V1 changes or schema migrations are required.

Runtime telemetry remains deferred. AI-BOM repairs, deleted-artifact closure, general status-filter repair, broader projection maintenance, platform-console alerts, and alert deduplication remain follow-ups.
