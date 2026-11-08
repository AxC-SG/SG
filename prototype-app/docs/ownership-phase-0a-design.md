# Ownership MVP — Phase 0A Architecture Gate Design

Status: draft for approval  
Source plan: `docs/ownership-capability-mvp-plan.md` §16.2  
Baseline: `main` @ `98155ae6` — tenant migrations V1–V19, platform migrations V1–V10.

This document records the repository-grounded decisions for the nine Release-1 prerequisites. Items that need
deployed infrastructure, production-scale data or people are marked **OPEN** and must be closed by their owners
before the Release-1 authority switch (§15.3). Code in Release 1 is written against the interfaces defined here so
that the open items change configuration, not structure.

## 1. Storage map and migrations (prerequisite 1)

Next free versions: **tenant V20**, **platform V11** (re-verify before each merge; `PackagedMigrationCatalog`
derives targets from the highest packaged version and rejects gaps/duplicates).

Conventions copied from tenant V19: `-- migration-guard: tenant-only` header, `${tenantSchema}` /
`${tenantId}`, `tenant_id uuid NOT NULL DEFAULT '${tenantId}'::uuid REFERENCES platform.tenants(id)`,
`ENABLE` + `FORCE ROW LEVEL SECURITY`, and a `tenant_isolation` policy on `app.current_tenant_id`.

| Migration | Contents |
|---|---|
| platform V11 `tenant_data_keys_and_ownership_authority` | `tenant_data_keys` (tenant, key version, KMS key ref, wrapped DEK, state, created/rotated); `ownership_domain_authority` (tenant, domain, state `LEGACY/DARK/CANONICAL`, accepted_by/at); `ownership_kill_switches` (source kind, tenant nullable, state) |
| tenant V20 `identity_and_teams` | `team`, `team_alias`, `directory_user`, `directory_group`, `external_identity`, `external_group`, `directory_group_member`, `external_group_team_mapping`, `team_member`, `identity_source`, `identity_import_run` |
| tenant V21 `ownership_core` | `ownership_subject`, `ownership_subject_edge`, `ownership_claim`, `ownership_assignment`, `ownership_review_item`, `ownership_event`, `ownership_effective_assignment` (view), optional `ownership_effective_cache` |
| tenant V22 `ownership_projection_columns` | additive `ownership_subject_id`, `assignee_principal_id` on asset/finding projections; exception owner-snapshot columns (§7.3) |
| later releases | campaign/investigation columns (R2/R3), cleanup drops (post-GA) |

Rules: DDL is forward-only; every cross-row reference is tenant-inclusive (`(tenant_id, id)` candidate keys);
no cross-tenant cascade; new tables are added to tenant purge coverage and `TenantSchemaFingerprint`; grants follow
the existing tenant-role grant block used by V19.

V20 as built: also adds `directory_search_token` (HMAC prefix tokens for users/groups). External IDs are stored as
`external_id_enc` + `external_id_index` (blind index) so uniqueness never needs plaintext; PII columns carry a
`LIKE 'enc:t1:%'` check. `TenantSchemaCompatibility` now requires tenant V20.

Namespace uniqueness for `team.name_key` + `team_alias.alias_key` is enforced by one transactional
`TeamNamespaceService` taking a tenant-scoped `pg_advisory_xact_lock`; table unique indexes are a backstop only.

## 2. Tenant encryption and KMS (prerequisite 2)

Current state: `CredentialEncryptionService` is single-key AES-256-GCM with `enc:v1:` prefix, key id and previous
keys from config; `ProviderCredentialMigrator` re-encrypts stored provider credentials. There is no tenant key
hierarchy and no KMS client.

Design:

```text
TenantDataCipher (new interface)
  encrypt(tenantId, purpose, plaintext) -> "enc:t1:<tenantKeyVer>:<base64(iv||ct)>"
  decrypt(tenantId, purpose, ciphertext)
  blindIndex(tenantId, purpose, normalizedValue) -> byte[] (HMAC-SHA256)
KeyWrapper (interface)       : wrap/unwrap(dek, encryptionContext{tenantId,purpose,keyVersion})
  AwsKmsKeyWrapper           : production; encryption context bound to tenant+purpose
  LocalKeyWrapper            : local/test only; refuses to start with APP_ENVIRONMENT != local/test
TenantKeyRegistry            : platform.tenant_data_keys, caffeine cache (bounded TTL), versioned rotation
```

- Per-tenant DEKs wrapped by KMS; AAD = `tenantId|purpose|keyVersion`; plaintext DEK cached in memory only, bounded TTL.
- Prefix is `enc:t1:` because `CredentialEncryptionService` already writes `enc:v2:<keyId>:` with platform keys.
  Wrap context is `{tenantId, purpose=tenant-data-key, keyVersion}`; field AAD is `tenantId|purpose|keyVersion`.
- Blind-index key is derived from tenant key **version 1** so indexes survive DEK rotation; destroying v1 or
  rotating the index key needs a reindex job (not in Release 1).
- `enc:v1:` ciphertext stays readable through `CredentialEncryptionService`; `ProviderCredentialMigrator` gains a
  re-envelope pass (v1 → v2) driven by `ProviderCredentialMigrationTool`, resumable, never logging plaintext.
- Gate: identity-source enablement and any PII write call `TenantDataCipher.readiness(tenantId)`; failure blocks with a
  typed error (§6.1 step 2). Outage behaviour: reads of already-cached keys continue until TTL, writes fail closed.
- Blind indexes (HMAC, tenant-derived index key) replace plaintext indexes for exact email/employee-id lookup;
  prefix search uses bounded n-gram tokens of the normalized display name under the same HMAC key (limit set by the
  100k/300k plan check below).

**OPEN (blocking):** deployed Render→KMS spike (auth, wrap/unwrap latency, rotation, outage, redacted logging).
Until it passes, no production PII write and no new connector-secret write; Release-1 code ships behind the
readiness gate with `LocalKeyWrapper` in local/test only.

## 3. Identity canonical key and search (prerequisite 3)

- Canonical identity key: `(tenant_id, source_id, external_id)`; email is a *link hint*, never a merge key.
- Ambiguity (same email across sources, mutable-identifier collision) → `ownership_review_item(AMBIGUOUS_IDENTITY)`;
  no automatic merge.
- Search: exact via blind index; prefix via token index. **OPEN:** 100k/300k-user query-plan evidence.

## 4. Authorization matrix (prerequisite 4)

Existing tenant roles (`TenantRolePolicy`): `TENANT_ADMIN`, `INVENTORY_ADMIN`, `SECURITY_ANALYST`,
`READ_ONLY_AUDITOR`; plus `SERVICE_ACCOUNT` (registry-bound). The plan's "read-only tenant role" maps to
`READ_ONLY_AUDITOR`. The matrix in plan §5 is adopted verbatim and implemented as a single
`OwnershipAuthorization` component; every controller method is annotated and covered by a parameterized
authorization integration test (role × endpoint). Wrong-tenant IDs return 404.

Analyst manual assignment: server-derived scope check (finding assigned to caller, or CVE the caller leads — CVE
leg arrives in Release 3), reason mandatory, expiry ≤ 30 days, impact preview ≤ 100 descendants / 1,000 findings,
alert event `OWNERSHIP_ANALYST_ASSIGNMENT` written in the same transaction as the claim.

## 5. Resolver, inheritance, TTL (prerequisite 5)

Implements plan §6.9 exactly. Contract points fixed here:

- Priorities (lower wins): 1 manual, 2 ServiceNow, 3 cloud account/project, 4 AI Grid, 5 cloud tag/label, 6 Entra/Okta.
- Direct specificity beats any inherited result; ≤ 6 parent hops; cycle/missing/overflow → `CONFLICT` + review item.
- Resolver is a pure function `resolve(directClaims, parentResolver) -> DirectResult` with a `resolverVersion` constant;
  `OwnershipResolutionService` is the only writer of `ownership_assignment`; unchanged inputs ⇒ zero writes.
- Default source TTL/staleness: claims carry `observed_at`; a source claim becomes stale after **2× sync interval**
  and ineligible after **7 days** without re-observation (tenant-lowerable). Anomaly pause: a producer batch that would
  change > **20 %** of its claims (min 50) pauses and raises a review item. **OPEN:** product confirmation of thresholds.

## 6. ServiceNow CMDB contract (prerequisite 6)

Initial fields per plan §6.4 (`support_group`, approved owner-team/department field, approved person field);
watermark `sys_updated_on` + `sys_id` tie-breaker; minimum table permissions read-only on `cmdb_ci*`, `sys_user*`.
Existing `ServiceNowCmdbConfigService` is the configuration home; the claim producer is new and must not reuse the
platform feed credentials (CLAUDE.md boundary). **OPEN:** representative CMDB sample and permission list from the
ServiceNow admin.

## 7. Effective-owner join benchmark (prerequisite 7)

Harness (to be built in Release 1 week 1, under `backend/scripts/perf/ownership/`): seeds 1M/3M findings and
5M/15M occurrence topology into a disposable Postgres, then records `EXPLAIN (ANALYZE, BUFFERS)` and p95 for:
owner-team filter, status filter, ownership coverage count, single-subject explanation. Decision rule: if p95
misses plan §13 budgets, enable `ownership_effective_cache` (schema ships in V21 but is unused until then).
**OPEN:** results.

## 8. Authority switch, read flags, compatibility adapter (prerequisite 8)

- `platform.ownership_domain_authority(tenant_id, domain, state)`; domains `CORE`, `CLOUD_BOM`, `AI_GRID`.
- `OwnershipAuthorityService.stateFor(tenant, subjectFamily)` is the only authority lookup; legacy and canonical
  writers both call it and fail closed on mismatch (service guard + DB check on writer-identity column).
- Per-consumer read flags (`inventory`, `findings`, `campaigns`, `tickets`, `ai`) as server-side config per tenant.
- `OwnershipReadAdapter` returns the §7.5 envelope (`authorityState`, `legacyOwnerLabel`); legacy rows are
  `LEGACY_PENDING_MIGRATION`, never `UNOWNED`.
- Recovery test plan: switch rehearsal on an internal canary tenant, 24 h gates, rollback only before step-5 go.

## 9. Staffing and acceptance owners (prerequisite 9)

**OPEN — human decision.** Needs named leads for ownership/platform, connectors, consumer UI, QA/SRE/security and
the release authority, plus provider-tenant access dates (ServiceNow, Entra, Okta, AWS, GCP).

## 10. Gate status

| # | Prerequisite | Status |
|---|---|---|
| 1 | Storage map, versions, RLS/grants/purge | Platform V11 + tenant V20 implemented and IT-verified; V21/V22 pending |
| 2 | KMS spike + cipher interface | Implemented (`security.tenantkey`, platform V11, local wrapper only); **spike OPEN** |
| 3 | Identity key + search | Designed; **100k/300k plan OPEN** |
| 4 | Authorization matrix | Designed |
| 5 | Precedence/inheritance/TTL | Designed; thresholds **need product confirmation** |
| 6 | ServiceNow CMDB contract | Initial contract; **samples OPEN** |
| 7 | Effective-owner benchmark | Harness planned; **results OPEN** |
| 8 | Authority/read-flag/adapter plan | Designed |
| 9 | Leads, staffing, ROM | **OPEN** |

Implementation proceeds against these interfaces. Anything marked OPEN is enforced in code as a disabled-by-default
switch (publication, identity-source enablement, domain authority) so unfinished evidence cannot be bypassed at runtime.
