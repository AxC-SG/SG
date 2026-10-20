# R2 implementation review — commit `3e431fa`

Date: 2026-08-03  
Reviewed against: [`PRD-AI-Grid-Final-Scope.md`](../PRD-AI-Grid-Final-Scope.md)  
GitHub: PR #22, branch `codex/ai-grid-exposure-management`

## Executive conclusion

R2 has a credible **mechanism-complete backend foundation**, but it is not yet release-complete or R2-certified.
The implementation includes stable AI-system revisions and lineage, temporal host-context facts, three versioned
bounded correlation templates, hypothesis-versus-validated workflow separation, deterministic replay manifests,
canonical host-finding graduation, complete-reassessment closure, exposure APIs, and computed certification gates.

The release claim remains blocked by four categories of work:

1. the platform/tenant migration boundary is red and PR #22 is still open;
2. real CIEM/DSPM/ASM/reachability producers are not connected to the host-context ports;
3. R2 precision governance is weaker than the ratified FR-19/R1 governance contract; and
4. analyst UI, calibrated confidence enforcement, and affected-subgraph economics are incomplete.

Use the following language until those gaps close:

> R2 backend mechanisms are implemented and integration-tested. R2 is not certified, release-approved, or merged
> to `main` as of this review.

## What is implemented correctly

- Stable AI-system identity is rooted in provider resource identity; membership changes create immutable revisions.
- Split, merge, successor, and retirement lineage are recorded without silently transferring findings.
- Current correlation consumes the multi-provider current-coverage epoch rather than one global latest run.
- Traversal is bounded by governed node/edge types, depth, fan-out, cycle prevention, and a hard path ceiling.
- The three PRD exposure templates are separately versioned and emit hypotheses or validated exposures.
- Configuration proxies cannot satisfy the distinct verified/confirmed fact keys used for validation.
- Temporal validity and fact freshness are evaluated against an epoch/run as-of time.
- Replay captures correlation versions, artifact bindings, relationship IDs, host-fact IDs, system revisions, and a
  material digest, then verifies the result without provider calls.
- Only validated exposures graduate into the canonical host `findings` workflow; shared root causes compress tickets.
- A path closes only after absence in an authoritative complete coverage epoch, with an `ABSENT` observation.
- Stale validating evidence demotes the exposure to a hypothesis without falsely resolving its existing finding.
- Exposure list/detail, system graph/lineage/findings, membership-review, host-context, disposition, precision, and
  release-decision APIs exist.
- Focused PostgreSQL integration tests pass: 7 exposure tests and 1 certification test.

## Release blockers and required modifications

### P1 — Migration ownership is unresolved

`postgres_reset/V59` performs tenant `findings` DDL across `tenant_default` and `tenant_*` schemas. This makes the
integration suite start, but violates the platform/tenant migration boundary and requires a runtime/platform
migration role to own tenant DDL. The guard is correctly failing.

Recommendation: choose the architectural fix, not a permanent exemption. `ProductionBootstrapCli` already migrates
`tenant_default` through the tenant Flyway line before runtime verification. Make that bootstrap an enforced
deployment precondition and make PostgreSQL integration tests run the equivalent tenant migration **before JPA
initialization** (for example, a test-only Flyway migration strategy/initializer). Then remove the V59 tenant loop.
If an exemption is used to unblock an urgent branch, time-box it, match only the exact V59 block, and open a required
follow-up with an expiry condition.

### P1 — Validated templates have no trusted production evidence producers

The seven strong facts required by the three templates are not emitted by an AWS/Azure connector or a host
CIEM/DSPM/ASM/reachability adapter in main code. They are seeded in PostgreSQL tests and can otherwise enter through
`POST /api/ai-artifacts/{id}/host-context`.

Implement authenticated producer adapters/contracts for at least:

- verified reachability and inadequate authentication;
- confirmed sensitive-data access;
- derived effective excessive privilege and confirmed consequential/secret access; and
- verified untrusted input, autonomous execution, and inadequate execution boundary.

Until one or more real producers exist, the templates are executable but operationally dark for validated exposure.

### P1 — Host-context trust and confidence controls are insufficient

The host-context endpoint is writable by a security analyst, while evidence class, provenance, confidence method,
and evidence reference are caller-provided strings. The service checks the fact dictionary and rejects
`CONFIGURATION` for validating claims, but it does not bind a fact to an authorized producer or approved method
identity. In addition, nullable confidence is read as `1.0`, and R2 correlation requirements declare no calibrated
minimum-confidence or corroboration rule.

Required changes:

- distinguish trusted integration ingestion from analyst attestation;
- register/authorize producer and method versions server-side;
- require non-null confidence for confidence-bearing validating evidence;
- never coalesce missing confidence to `1.0`;
- add per-correlation requirements for calibrated method/evidence class, minimum confidence where permitted,
  corroboration, and scope completeness; and
- add negative tests proving low, null, uncalibrated, or analyst-self-asserted evidence cannot validate or ticket.

### P1 — R2 precision certification does not meet FR-19

`AiGridR2CertificationService.recordPrecision` passes on the raw accepted/sample ratio. It has no minimum sample
size, confidence interval, stratification, two independent reviewers, adjudication, or label-set/version binding.
Consequently, `1/1` can pass a 95% threshold. This regresses from the already-corrected R1 Wilson-lower-bound model.

Reuse the R1 precision-review governance contract for correlations. A correlation version should release only when
the configured confidence-interval lower bound meets its threshold and the current material digest has the required
reviewers, adjudication state, sample disclosure, and answer-key provenance.

### P2 — No analyst exposure experience exists in the frontend

The backend exposes exposure list/detail APIs, but the frontend has no AI exposure list, path trace, evidence,
temporal-validity, root-cause, breakpoint, hypothesis/validated state, disposition, or finding-link experience.
This leaves the PRD's analyst journey and explainability outcome API-only.

### P2 — Correlation recomputes the full current graph

Every complete scope and host-context update refreshes the current epoch, derives all systems, loads all current
artifacts/edges/facts, and traverses every system/template path. This is bounded but not the PRD's affected-subgraph
recompute. Add changed-artifact/edge/fact tracking, reverse dependency lookup, and per-root/template invalidation;
retain a full rebuild as reconciliation and measure equivalence.

### P2 — Exposure demotion does not reconcile the existing finding's workflow state

Stale evidence correctly demotes `VALIDATED_EXPOSURE` to `EXPOSURE_HYPOTHESIS` and deliberately does not false-close
the existing finding. However, the finding remains open with workflow class `VALIDATED_EXPOSURE` and its SLA remains
active. Define and implement the desired owner-facing state: for example `NEEDS_EVIDENCE`/SLA-paused while retaining
the ticket and history, followed by revalidation, verified closure, or recurrence. Do not resolve it merely because
evidence expired.

### P2 — R2 certification is not forward-compatible or cohort-complete

The precision gate requires exactly three globally published correlations, so publishing a later correlation can
make an old R2 gate fail. Bind R2 to an immutable release manifest containing the three required IDs/versions.
Also make operational closure/freshness gates require representative evidence rather than pass vacuously when no
closure or stale-demotion cohort exists.

## Current verification and GitHub state

- Local migration-boundary guard: **FAIL**, caused by the V59 tenant-DDL loop.
- Focused PostgreSQL R2 exposure tests: **7 passed**.
- Focused PostgreSQL R2 certification tests: **1 passed**; the test intentionally proves readiness remains blocked
  after synthetic precision rows because operational gates are missing.
- GitHub PR #22 at `3e431fa`: **OPEN**, `mergedAt = null`.
- GitHub checks at review time: backend, backend-postgres, frontend, docs, secrets, CodeQL, Trivy, images, and
  certification green; `migration-boundaries` is the only failed check.

## Recommended completion order

1. Remove the tenant DDL from V59 by fixing the pre-JPA test/bootstrap migration lifecycle.
2. Harden the host-context producer trust boundary and calibrated confidence semantics.
3. Reuse R1 precision governance for the three correlation versions.
4. Connect at least one real end-to-end host producer for each correlation domain and run answer-key environments.
5. Add the analyst exposure/path UI and disposition workflow.
6. Add affected-subgraph recomputation and economics tests.
7. Collect real precision, explainability, owner/SLA, stale-demotion, closure, and design-partner evidence; then
   record an explicit R2 approval.
