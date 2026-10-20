# Policy Framework Enhancement Plan

## Summary

Make `platform.ai_grid_policy_versions` the single authoritative, platform-owned policy catalog. Policy definitions are authored as versioned Git packages; the product provides the platform-owner workflow for validation, review, canary rollout, distribution, rollback, and audit.

Use a staged migration so existing tenant selections and policy history remain intact while legacy policy paths are retired.

## Implementation changes

### 1. Establish the canonical policy package and catalog

- Add a versioned policy-package format in the repository: identity/version, applicability, evidence contract, safe predicate, typed parameters, severity/workflow, remediation, OWASP/framework mappings, tests, rollout defaults, deprecation/replacement metadata.
- Add package compile/lint/import tooling that validates fact keys, evidence classes, types, predicate bounds, lifecycle rules, mapping IDs, and policy-version immutability.
- Extend the governed catalog schema with package digest/source reference, author, approver, changelog, replacement policy/version, release notes, and rollout metadata.
- Replace the Bedrock-specific evaluator branch with generic typed parameter resolution supported by the declarative predicate engine.
- Treat missing or insufficient evidence as readiness/coverage output, never as a pass or fail.

### 2. Build platform-only policy governance

- Create platform-owner APIs and Policy Studio surfaces for:
  - Candidate intake and prioritization.
  - Draft definition inspection, lint output, answer-key status, and impact preview.
  - Independent review/approval, including author/approver separation.
  - Canary cohorts, publication, distribution, version pinning, rollback, and retirement.
- Keep authoring in Git for v1. Policy Studio manages imported drafts and releases; it does not expose a free-form customer rule builder.
- Enforce lifecycle gates: `DRAFT → VALIDATED → APPROVED → CANARY → PUBLISHED → RETIRED`.
- Require certified answer-key validation for all policies and passing dual-reviewed precision review for High/Critical policies.
- Record immutable release decisions with actor, rationale, package digest, test evidence, and affected catalog version.

### 3. Separate release, distribution, tenant choice, and evidence state

- Define four independent state dimensions:
  - Catalog lifecycle: whether a version is valid to ship.
  - Platform distribution: available, default selection, cohort/canary status, pinned version.
  - Tenant selection: required, enabled, preview, disabled.
  - Evaluation state: applicability, evidence readiness, decision, finding/exposure workflow.
- Publish does not automatically enable a policy for all tenants.
- Preview evaluates policy coverage and quality but does not create normal owner-facing findings.
- Required policies cannot be disabled by tenants; enabled and preview policies remain tenant-selectable.
- Add distribution rules for global availability, selected design-partner cohorts, new-tenant defaults, and explicit tenant pins.

### 4. Migrate from the legacy policy system

- Build a policy-ID/version mapping from `AiSecurityPolicyRegistry` to governed catalog entries.
- Backfill governed catalog versions and migrate tenant enabled/disabled settings to governed selections without changing their effective behavior.
- Temporarily serve legacy policy APIs from governed catalog read models so existing UI routes remain functional.
- Switch Policies, policy detail, asset detail, findings, and platform controls to governed catalog APIs.
- Remove the Java registry, legacy distribution table, and policy-specific evaluator branches only after migration reconciliation confirms:
  - every legacy policy has a governed equivalent or explicit retirement record;
  - every tenant setting is migrated;
  - policy/finding counts reconcile within agreed tolerance.
- Preserve prior findings with their evaluated policy version for audit and historical explainability.

### 5. Add policy portfolio management and framework coverage

- Add a candidate backlog with source type: connector capability, coverage gap, threat research, customer request, incident, compliance framework, or design-partner feedback.
- Score candidates by customer risk, affected-asset reach, evidence maturity, expected precision, and remediation clarity.
- Add an OWASP LLM Top 10 coverage matrix showing:
  - mapped controls;
  - unmapped risks;
  - policy state;
  - evidence/connector readiness;
  - planned versus shipped policies.
- Start from the current 18-policy governed catalog; target 12–14 default-enforced controls and retain uncertain controls in Preview.
- Prioritize new policies only where collectors can prove the required evidence contract; otherwise create connector/coverage work rather than a noisy policy.

## Public API and interface changes

- Governed policy catalog APIs: list/detail/version/history, tenant selection, platform distribution, policy release readiness, impact preview, canary status, rollback, and framework coverage.
- Policy package import API or CI integration endpoint restricted to platform automation.
- Platform Policy Studio restricted to `PLATFORM_OWNER`; tenant policy UI restricted to selecting distributed versions and viewing evidence/coverage.
- UI policy detail shows version, selection, readiness, framework mappings, evidence contract, recent release notes, and explanation of why a decision is unavailable.

## Test plan and definition of done

- Package lint rejects unknown facts, incompatible types, unsupported predicates, invalid mappings, missing answer-key cases, and mutable published versions.
- Evaluation tests cover enabled, required, preview, disabled, missing/stale evidence, typed parameters, policy replacement, and rollback.
- Governance tests verify independent author/approver requirements, High/Critical precision gates, canary restrictions, audit persistence, and immutable publication.
- Migration tests prove legacy policy IDs/settings migrate correctly, preserve tenant behavior, and retain historical finding provenance.
- UI/API tests verify platform-only governance access, tenant-only selection behavior, Preview non-finding behavior, and framework-coverage reporting.
- Release is complete when the governed catalog is the only evaluation and UI source of truth; all existing tenant settings reconcile; platform owners can ship, canary, distribute, roll back, and retire policies without direct production database edits.

## Assumptions

- Policy definitions begin as Git-managed packages, reviewed through pull requests and imported through controlled automation.
- Customers do not author policies or execute arbitrary policy code.
- The current 18 governed policies are the initial catalog; the legacy 14-policy registry is transitional only.
- OWASP LLM Top 10 is a mapping and portfolio-coverage lens, not a claim that one policy fully mitigates an entire OWASP category.
