# AI Grid — Vertical-Slice Implementation Plan (Epics 0→1→2→3, one rule)

**Date:** 2026-07-31 (updated session 3) · **Author:** Claude · **Status:** Proposed (awaiting build kickoff)
**Updated with the session-3 connector-metadata findings** — see
[`../evaluations/2026-07-31-connector-metadata-gap.md`](../evaluations/2026-07-31-connector-metadata-gap.md)
and [`../evaluations/2026-07-31-policy-superset-matrix.md`](../evaluations/2026-07-31-policy-superset-matrix.md).
**Goal:** Drive **one rule end-to-end** through a data-driven engine so all architecture risk is proven in the
smallest unit; afterward Epic 4 (breadth) is pure content. Everything is gated behind the disabled-by-default
`ai.security` entitlement → zero impact on existing CVE/finding workflows.

**Piloted rule:** `AWS_BEDROCK_WEAK_GUARDRAIL` — "Attached guardrail below MEDIUM strength" (HIGH).
Chosen because it already has applicability + evidence-gating + ordinal-comparison logic, so it exercises
every hard part of the generic evaluator.

**End-to-end target for the slice:**
> Discovery emits normalized facts → a **catalog row** (data, not code) is evaluated by a **generic predicate
> evaluator** → the artifact carries **owner + criticality** → a violation becomes a **host `Finding`** with
> ownership + SLA + ServiceNow eligibility → tagged **OWASP LLM06 Excessive Agency** on a **compliance** view.

---

## Scope guardrails (decided 2026-07-31 s4–s6)
- **Initial framework = AWS Bedrock only, agent-centric, reported against OWASP LLM Top 10 (2025) (s6).** The
  Bedrock Agent "hero" chain (agent + guardrail + action-group Lambda + KB→S3 + execution role) is the slice.
  Include ≥1 Bucket-C stub fact (`has_admin_privileges`) so the `NO_DECISION` path is proven. Azure OpenAI is
  framework #2. **Coverage must never present `NO_DECISION` as pass** — foreground the 5-way status. See
  [`../known-limitations.md`](../known-limitations.md).
- **AI Security Attribution Rule (s5):** every finding is attributed to an **AI artifact** and justified by that
  artifact's own config OR a security-relevant **relationship edge**. IN = artifact config + the config of non-AI
  resources it depends on (execution role, action-group Lambda, backing bucket, KMS, network), consumed
  **artifact-first** as facts/edges. OUT = generic CSPM with no AI nexus. Author every catalog rule artifact-first
  (e.g. "Knowledge base exposes a public S3 source", NOT "Bucket X is public"). Cloud-config *reads* are in scope;
  standalone cloud-resource *findings* are not.

- **Curated, platform-owned catalog; tenants only enable/disable** (matches existing
  `ai_security_policy_distribution` + `ai_security_policy_settings`). **Out of scope:** tenant-authored custom
  policies, a query-builder authoring UI, a customer-facing fact-schema registry. Epic 0's declarative engine
  is for *internal* authoring-at-scale + data-driven compliance/coverage — not a customer feature.
- **REST only — no GraphQL.** The `filterBy`/cursor/field-projection ideas may be borrowed on REST endpoints
  if the inventory table needs them; no GraphQL runtime.
- The §0.2 **fact dictionary** is an internal seed/test validation helper (validate `predicate_json` fact
  references + document available facts), not a shipped UI.

## Conventions (from repo CLAUDE.md — follow exactly)

- Two Flyway lines. Platform: `db/migration/postgres_reset/` (startup, `public`, latest **V49** → add **V50**,
  must start with `-- migration-guard: platform-only`). Tenant: `db/migration/tenant/` (control-plane applied,
  latest **V47** → add **V48**; may use `${tenantId}`/`${tenantSchema}`). Bump
  `platform.tenant_schema_versions.target_version` to 48 in the platform migration (follow V48/V49 pattern).
- Never edit an applied migration. Tests are required to call it done (service IT / `@PostgresControllerIntegrationTest`
  / vitest). Enable RLS + forced RLS + `tenant_isolation` policy on every new tenant table (copy the V45 block).

---

## Epic 0 — Data-driven policy engine + normalized facts

### 0.1 Platform catalog table — `platform.ai_policy_catalog` (migration **V50**)
```
platform.ai_policy_catalog (
  policy_id            varchar(128) PK,
  version              varchar(32)  NOT NULL,
  name                 varchar(512) NOT NULL,
  severity             varchar(32)  NOT NULL,            -- CRITICAL/HIGH/MEDIUM/LOW/INFO
  applies_to_types     jsonb NOT NULL DEFAULT '[]',      -- artifact types
  applies_to_kinds     jsonb NOT NULL DEFAULT '[]',      -- native_kinds (optional narrowing)
  required_evidence    jsonb NOT NULL DEFAULT '[]',      -- resource families that must be COMPLETE
  applies_when_json    jsonb,                            -- predicate; false => NOT_APPLICABLE (nullable = always)
  condition_json       jsonb NOT NULL,                   -- predicate; true => FAIL, false => PASS
  framework_json       jsonb NOT NULL DEFAULT '{}',      -- {owasp_llm, mitre_atlas, nist_ai_rmf, cwe, cis}
  remediation          text NOT NULL,
  default_enabled      boolean NOT NULL DEFAULT true,
  updated_by varchar(255), updated_at timestamptz DEFAULT now()
)
```
- Keep `platform.ai_security_policy_distribution` (availability) and tenant `ai_security_policy_settings`
  (enable/disable) unchanged — they now key off `ai_policy_catalog.policy_id`.
- Seed the **13 existing rules** as rows in V50 (mechanical transcription of `AiSecurityPolicyRegistry`), with
  `condition_json`/`applies_when_json` reproducing today's `evaluate()`/`isApplicable()` logic exactly.

### 0.2 Normalized fact model (tenant migration **V48**) — `UNKNOWN`-aware + provenance-tagged
- Add `normalized_facts_json jsonb NOT NULL DEFAULT '{}'` to `ai_security_artifacts` — provider-agnostic facts
  computed at ingestion. **Each fact is a small object, not a bare value**, so we can distinguish "false" from
  "not yet determined":
  ```
  "public_network_unrestricted": { "value": true,  "state": "KNOWN",   "provenance": "aws:GetAccount",     "observed_at": "…" }
  "has_admin_privileges":        { "value": null,  "state": "UNKNOWN", "provenance": "ciem:not-implemented" }
  ```
  `state ∈ {KNOWN, UNKNOWN}`. (Sugar: a bare scalar is treated as `{value, state:KNOWN}`.)
- **Three fact tiers** (mirrors Wiz's `cloudResourcesV2` two-tier shape):
  1. **Config facts** — read from a single describe call: `guardrail_attached`, `guardrail_min_strength`,
     `public_network_unrestricted`, `local_auth_enabled`, `cmk_encryption`, `diagnostic_logging_enabled`, …
  2. **Capability flags** — the scope doc's normalized booleans: `tool_execution`, `code_execution`,
     `autonomous_action`, `network_egress`, `secrets_access`, …
  3. **Enrichment booleans (Wiz graph-derived, default `UNKNOWN`)** — the six that Wiz leaves null at scan time:
     `is_accessible_from_internet`, `is_open_to_all_internet`, `has_admin_privileges`, `has_high_privileges`,
     `has_access_to_sensitive_data`, `has_sensitive_data`. Populated later by CIEM/DSPM/ASM capability epics;
     `UNKNOWN` until then.
- Each discovery provider (`AwsBedrockDiscoveryService`, Azure services) gains a `normalize(...)` step mapping
  raw provider attributes → tier-1/2 facts, written into the `ObservationEnvelopeV1` artifact observation.
- **Rules read facts only, never `attributes_json`.** A rule referencing an enrichment boolean that is `UNKNOWN`
  resolves to `NO_DECISION` (see 0.3) — so C-dependent policies can exist as catalog rows today and light up
  automatically when the capability lands, with no schema/rule change.

### 0.3 Generic predicate evaluator (replaces the `switch`)
- Predicate grammar (JSON): `{all:[…]}` | `{any:[…]}` | `{not:…}` | `{fact, op, value, type?, scale?}`.
  Ops: `eq, ne, lt, lte, gt, gte, in, exists, absent`. Ordinal compares use `scale` (e.g. guardrail strengths).
- New `AiPolicyPredicateEvaluator` (pure, unit-tested). Outcome resolution in
  `AiSecurityPolicyEvaluationService`, preserving current semantics:
  1. `applies_when_json` false → `NOT_APPLICABLE`;
  2. any `required_evidence` family scope not `COMPLETE` → `NO_DECISION` (keep `hasCompleteEvidence`);
  3. a referenced fact **absent OR `state=UNKNOWN`** → `NO_DECISION` (missing evidence / capability not yet
     available) — carry the fact's `provenance` into the finding so the UI can say *why* it's undecided;
  4. `condition_json` true → `FAIL`, else `PASS`.
- `exists`/`absent` ops test presence; a `KNOWN` fact with `value:null` is still a decision input, whereas
  `state:UNKNOWN` always short-circuits to `NO_DECISION`.
- `AiSecurityPolicyRegistry` becomes a **DB-backed loader** over `ai_policy_catalog` (+ distribution + tenant
  settings). Delete the hardcoded `List` and the `evaluate()`/`isApplicable()` switches once parity tests pass.

### 0.4 Guardrail rule as data (proves the generic path)
```
applies_when_json: {fact:"guardrail_attached", op:"eq", value:true}
condition_json:    {fact:"guardrail_min_strength", op:"lt", value:"MEDIUM",
                    type:"ordinal", scale:["NONE","LOW","MEDIUM","HIGH"]}
required_evidence: ["BEDROCK_AGENTS","BEDROCK_GUARDRAILS"]
framework_json:    {owasp_llm:"LLM06:2025", cwe:null, nist_ai_rmf:"MAP-2.3"}
```

### 0.5 Connector enrichment tasks (from the session-3 metadata analysis)
Two connector changes belong in the slice because ownership (Epic 1) and future breadth (Epic 4) depend on them
— and today **neither connector emits them**:
- **Emit resource `tags`** on every artifact (AWS resource tags / Azure resource tags) into the observation
  envelope + a `tags_json` column (Epic 1.1). This is the primary input to owner resolution — without it Epic 1
  has nothing to resolve from.
- **Generic "fetch full resource config" per family** — replace today's per-policy field-picking with a single
  describe→normalize pass per resource family, so Tier-1 config gaps close as catalog rows (data), not new fetch
  code. For the slice, only the Bedrock guardrail/agent path must be generic; other families follow in Epic 4.

**Epic 0 DoD:** the 13 migrated rules produce byte-identical evaluations to the old engine on a seeded fixture
(golden parity test); adding a 14th rule requires only a catalog row, no Java; artifacts carry `tags_json`;
enrichment booleans are present as `UNKNOWN` facts and any rule referencing one yields `NO_DECISION`.

---

## Epic 1 — Artifact metadata (owner, criticality, exposure)

### 1.1 Columns on `ai_security_artifacts` (tenant migration **V48**, same file as 0.2)
`owner varchar(255)`, `owner_source varchar(32)`, `business_criticality varchar(32)`,
`tags_json jsonb DEFAULT '{}'`, `exposure_json jsonb DEFAULT '{}'`, `environment varchar(64)`.

### 1.2 Owner resolution — `AiArtifactOwnershipService`
- **Depends on 0.5 tag collection** (tags are the primary signal; must ship first).
- Resolution order: resource tags (`owner`/`team`) → account/subscription alias → existing `OwnershipRuleService`
  rules → **unowned**. Run post-ingestion per artifact.
- **Unowned artifact ⇒ synthesize an "AI artifact without owner" finding** (INFO/LOW) via the same path as Epic 2.

### 1.3 Criticality derivation — `AiArtifactCriticalityService`
- Rules-based v1: `exposure_json.public` + `facts.sensitive_data_reachable` + linked-asset
  `assets.business_criticality` (host column exists) → `LOW|MEDIUM|HIGH|CRITICAL`. Store on the artifact.

### 1.4 API
- Extend `GET /api/ai-security/artifacts/{id}` → `owner`, `ownerSource`, `businessCriticality`, `exposure`,
  `recommendations` (from failing rules' `remediation`), `relationships` (already present).

**Epic 1 DoD:** every discovered artifact resolves an owner (or an unowned-finding exists) and a criticality;
both surface in the detail API + inventory row; vitest asserts render.

---

## Epic 2 — Graduate AI Findings into the host `Finding` workflow (strangler)

### 2.1 Host model changes
- `FindingCreationSource` → add `AI_SECURITY`.
- Tenant migration **V48**: add nullable `ai_artifact_id uuid` to host `findings` (+ FK to
  `ai_security_artifacts`); keep `asset_id` nullable for AI findings.
- **Subject linkage:** if the artifact maps to a known host `asset` (e.g. compute/host), link `asset_id` so
  ownership/criticality/SLA inherit; else stand alone on `ai_artifact_id`.

### 2.2 Wiring (reuse, don't rebuild)
- On `FAIL`, `reconcileFinding` (in `AiSecurityPolicyEvaluationService`) creates/updates a **host `Finding`**
  (source `AI_SECURITY`, severity from catalog, evidence pointer) instead of only `ai_security_findings`.
- Route through `OwnershipRuleService` (assignment), `FindingSlaService` (SLA clock from severity +
  criticality multiplier), suppression + hourly auto-close, and make it **eligible** for
  `ServiceNowIncidentService` like any finding. AI-specific evidence stays in a side table
  (`ai_security_finding_evidence` or the retained `ai_security_findings` as detail-only).
- **Strangler:** only the piloted guardrail rule takes the new path first (behind the entitlement); other 12
  keep the old path until parity is verified, then migrate all and retire `ai_security_findings` as a workflow store.

**Epic 2 DoD:** a seeded weak-guardrail artifact produces a host `Finding` that gets an owner, an SLA due date,
and can open a ServiceNow incident; existing CVE findings are provably unaffected (entitlement off = no AI findings).

---

## Epic 3 — Framework mapping + compliance posture (thin)

- Populate `framework_json.owasp_llm` on catalog rows (guardrail rule → `LLM06:2025`).
- `AiComplianceService.computePosture(tenant)`: per-policy `posture% = FAIL-free applicable ÷ applicable`;
  category (OWASP cat) rollup; **5-way status** PASS / FAIL / NO_RESOURCES / DISABLED / NO_POLICY derived from
  evaluation outcomes (`NO_DECISION`/`NOT_APPLICABLE` already distinguish these).
- `GET /api/ai-security/compliance` → categories → policies → counts + posture%. Minimal dashboard card reusing
  the existing AI Policies page styling.

**Epic 3 DoD:** compliance endpoint shows LLM06 with the guardrail policy's live pass/fail posture; fixing the
seeded misconfig moves the number predictably (satisfies the previously-unmeetable DoD gate).

---

## Migrations added by this slice
- **Platform V50** — `ai_policy_catalog` + seed 13 rules + bump `tenant_schema_versions.target_version=48`.
- **Tenant V48** — `normalized_facts_json` + artifact metadata columns + host `findings.ai_artifact_id`
  + evidence side table; RLS block for any new tenant table.

## Services touched / added
- Modify: `AiSecurityPolicyEvaluationService` (evaluator + host-finding reconcile), `AiSecurityPolicyRegistry`
  (→ DB loader), `AwsBedrockDiscoveryService` (+ `normalize`), `AiSecurityApiService` (artifact detail fields),
  `FindingService`/`FindingSlaService`/`OwnershipRuleService` integration points.
- Add: `AiPolicyPredicateEvaluator`, `AiArtifactOwnershipService`, `AiArtifactCriticalityService`,
  `AiComplianceService`.

## Testing / DoD (whole slice)
- Golden parity test: old vs new engine agree on the 13 rules over a seeded fixture.
- Service IT: seeded weak-guardrail → host Finding with owner + SLA; compliance posture reflects it and moves on fix.
- Controller ITs for `/artifacts/{id}` (owner/criticality) and `/compliance`.
- vitest: artifact detail render (owner/criticality), compliance card.
- All behind `ai.security` (off by default). No change to non-AI findings — assert in an IT.

## Rollout
- Ship behind the entitlement; enable on the internal canary only; re-run the pilot-readiness gates in
  `docs/ai-security-pilot-readiness.md` (the rollup/coverage gate is now measurable via Epic 3).

## Open follow-ups (post-slice)
- **Epic 4 breadth (data + enrichment):** load the 48 AWS/Azure Wiz rules as catalog rows; per-family generic
  config fetch (0.5). Priority Tier-1/B enrichment: **Azure OpenAI content-filter/RAI policy config** (unlocks
  the OWASP-LLM01 prompt-injection story — highest-value enrichment), model CMK/LEGACY, SKU/DLP/storage, and new
  resource types (AgentCore, SageMaker, Comprehend, Copilot Studio).
- **First Tier-3 capability epic: CIEM-lite** — effective-permission + IAM trust-policy condition resolution.
  Unlocks the 4 AI-identity rules (admin/impersonation/secrets-KMS) and confused-deputy; trust-policy parsing is
  a B-extension of the role-reading the AWS connector already does. Populates `has_admin_privileges` /
  `has_high_privileges` from `UNKNOWN` → `KNOWN`.
- **Deferred Tier-3 (fact-feeding capabilities):** DSPM → `has_sensitive_data`/`has_access_to_sensitive_data`
  (coarse proxy or defer); ASM → validated `is_accessible_from_internet`; model-artifact scan; SAST; MCP; runtime.
- Epic 5: `ai_security_correlated_issues` graph evaluator (reuse host CVE findings + asset sensitivity) — becomes
  meaningful once CIEM/DSPM/ASM move the enrichment booleans off `UNKNOWN`.
- Retire `ai_security_findings` as a workflow store once all rules are on the host-Finding path.
