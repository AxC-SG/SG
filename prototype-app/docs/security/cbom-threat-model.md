# CBOM Workflow Threat Model

## Assets and trust boundaries

CBOM uploads, source metadata, component claims, assessment outputs, suppression decisions, reports, tenant rule configuration, and canonical findings are tenant-confidential. Upload/API boundaries, tenant-schema selection, background workers, report generation, and support sessions are explicit trust boundaries.

## Required controls

- Reject oversized, malformed, decompression-bomb, XXE/entity-expansion, and secret-bearing uploads before persistence.
- Establish tenant context before opening worker transactions; all V11/V12 tables enforce RLS.
- Never reveal whether an artifact checksum exists in another tenant. Deduplication is source- and tenant-scoped.
- Sanitize HTML report content and forbid external report resources.
- Treat missing evidence as unknown, not compliant or failed.
- Keep source withdrawal distinct from remediation and resolution.
- Use bounded queries, per-tenant job claims, dedicated executors, retry limits, and observable dead-letter state.
- Restrict tenant administrative changes to direct `TENANT_ADMIN` membership and audit every mutation.
- Redact secrets, authorization headers, internal source URLs, and sensitive identifiers from errors, logs, reports, and tickets.
- Do not expose a Slice 1 unredaction endpoint. Platform support access remains grant-bound and cannot perform suppression decisions.

## Abuse cases and verification

| Threat | Control and acceptance evidence |
|---|---|
| Cross-tenant repository/API access | Tenant-context integration tests and forced RLS |
| Artifact hash existence oracle | Tenant-scoped lookup and identical not-found response |
| Rule downgrade or mandatory-rule disable | Application package bounds and fail-closed pin validation |
| Worker starvation | Dedicated CBOM executor and one active assessment per tenant |
| Stored script injection | Escaped HTML report and React text rendering tests |
| False remediation through omission | Withdrawal/auto-close semantics; no automatic `RESOLVED` transition |
| Unauthorized risk acceptance | Canonical suppression guard, request state machine, and structural CI test |
| Support-session privilege escalation | Request/decision denial tests |
| Stale or replayed work | Immutable provenance tuple and idempotent assessment uniqueness |

Runtime collectors are outside this release. Any TLS, KMS, or key-custody collector requires a separate outbound-network, SSRF, credential-custody, rate, and kill-switch review.
