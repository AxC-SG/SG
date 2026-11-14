# Documentation map

Updated October 28, 2026 against the UI 2.0 source in this checkout. Runtime code and committed configuration define implemented behavior; historical migration plans describe intent and evidence for their recorded commits.

| Document | Use it for |
|---|---|
| [UI development standard](<../New UI 2.0/ui-development-standard.md>) | Required architecture, reusable components, screen composition, consistency checks and approval for departures |
| [Frontend](../../docs/frontend.md) | Routes, feature modules, auth, query state, component APIs and local development |
| [UI 2 styles and rollback](<../New UI 2.0/ui2-styles-and-rollback.md>) | Exact stylesheet ownership/order, presentation boundary, browser gates and retained rollback artifacts |
| [UI improvement package](<../New UI 2.0/UI 2.0 improvements/README.md>) | UI-only reviews, ranked adoption plan, shared UI proposal, Workbench journey and separate non-UI ledger |
| [Architecture](../../docs/architecture.md) | System boundaries, tenant isolation, pipelines and deployment shape |
| [Backend](../../docs/backend.md) | Controllers, services, authorization, capabilities and operations |
| [Database](../../docs/database.md) | Schema ownership, projections, migration lines and tenant control plane |
| [Business logic](../../docs/business-logic-guide.md) | End-to-end workflows and supported/contained capabilities |
| [CI security](<../CI Pipeline/ci-security.md>) | Security scanners and frontend regression gates |
| [Deployment sources](deployment-sources.md) | Canonical GitHub repository, Vercel frontend settings, Render backend source, and Resend configuration ownership |

The [UI 2.0 migration record](<../New UI 2.0/README.md>) retains the previous state, implemented plans, current state, historical evidence and rollback material. Implementation completion does not imply final branch-tip release qualification; its outstanding evidence is listed in [CURRENT_STATE.md](<../New UI 2.0/CURRENT_STATE.md>).

All future tenant, platform and authentication screens follow the same UI 2.0 standard. Public `/demo` content has an intentional separate presentation boundary. Any proposed departure requires the user's approval during development after explaining the reason, alternatives, pros, cons, affected screens and consistency/rollback plan.
