# ADR-0001: Use an application-packaged, tenant-controlled CBOM rule system

**Status:** Accepted for implementation planning<br>
**Date:** 2026-11-02<br>
**Owners:** CBOM backend and tenant administration

## Context

ScoutGrid already has two related but different rule mechanisms:

- The AI Grid policy catalog governs shared AI-security policy definitions, certification, distribution, and rollout.
- Canonical `RiskPolicy` supplies finding severity/SLA behavior such as `due_at`.

CBOM assessment evaluates cryptographic components and claim assurance directly. Reusing the AI Grid catalog would add a platform approval and rollout dependency, while storing complete rule definitions through tenant schema migrations would turn DDL into a content-delivery channel, prevent rule-only hotfixes, and leave `DRIFTED` tenants on outdated rule content.

The product decision is that CBOM rule configuration is controlled by `TENANT_ADMIN` without platform approval.

## Decision

Create a deliberately separate CBOM rule system with these boundaries:

1. Immutable rule definitions ship as versioned application packages loaded by `CbomRulePackageRegistry`.
2. Packages are keyed by stable rule-set ID and semantic version and include a deterministic digest.
3. Mandatory-rule flags, parameter types, default values, and hard safety bounds live in package metadata and cannot be changed through tenant rows.
4. Tenant tables store selection, supported parameter values, `FOLLOW_LATEST` or `PINNED` mode, effective/pinned version, discovered package digest, actor/reason, and audit history.
5. `TENANT_ADMIN` controls optional rules, supported parameters, and pinning. No platform policy approval or distribution workflow is used.
6. `CbomRiskEngine` evaluates CBOM projections and important claims directly; CBOM data is not copied into `ai_grid_facts`.
7. A tenant reconciler discovers newly packaged versions. `FOLLOW_LATEST` tenants move to the new effective version and receive idempotent, admission-controlled reassessment jobs. `PINNED` tenants receive an upgrade-available state without behavior change.
8. Canonical `RiskPolicy` remains the sole SLA/default-due-date authority. CBOM rules do not duplicate SLA configuration.
9. Assessment runs record package ID, semantic version, digest, evaluator version, tenant parameters, and evidence snapshot for reproducibility.

## Consequences

### Positive

- Tenant control does not depend on a platform policy team or approval workflow.
- Rule fixes can ship with an application release without requiring a schema migration.
- `DRIFTED` schema state does not by itself block delivery of rule content after the supporting tenant tables exist.
- Mandatory rules and safety bounds cannot be weakened by editing tenant configuration rows.
- Rule version and digest make assessments reproducible.

### Negative

- ScoutGrid has a third rule mechanism alongside AI Grid policies and `RiskPolicy`.
- CBOM package compatibility, reconciliation, pinning, telemetry, and reassessment require dedicated code and tests.
- A rule-only correction still requires an application release unless a future authenticated package-delivery mechanism is introduced.
- Cross-product policy reporting must understand that CBOM rule versions are not AI Grid policy versions.

## Required controls

- Reject duplicate package ID/version pairs with different digests at startup.
- Fail closed when a tenant pins a package version unavailable to the running application; keep the last known valid effective version and surface an operational error.
- Validate tenant parameters against immutable package types and bounds before activation and again during evaluation.
- Prove by automated test that mandatory rules cannot be disabled through tenant rows.
- Use per-tenant admission limits and idempotency keys when rule reconciliation queues reassessment.
- Emit rule-set ID/version as low-cardinality telemetry without tenant-identifying labels.
- Preserve package backward compatibility for any version tenants are permitted to pin.

## Convergence triggers

Reconsider convergence with the AI Grid policy catalog only if one or more of these become material:

- customers require one cross-domain policy authoring and approval workflow;
- duplicate evaluator/governance maintenance becomes a measurable reliability burden;
- CBOM rules require platform-wide compliance certification or coordinated distribution;
- the AI Grid evaluator gains a direct, non-duplicating CBOM input model without imposing platform approval;
- shared policy reporting cannot be implemented safely through an aggregation layer.

Any convergence requires a new ADR and a migration plan that preserves tenant pins, rule digests, assessment reproducibility, and canonical finding history.
