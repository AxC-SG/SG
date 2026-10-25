# Start here — Claude implementation handoff

Prepared October 24, 2026. This guide supplies the conversation context needed to use the package with the existing ScoutGrid repository. It does not contain or replace the full application.

## Required environment

**Recommended:** run Claude Code in the current `/Users/karthik/Desktop/SG` workspace. The application lives in `prototype-app/`; the production frontend is `prototype-app/frontend/`; this reference is a separate project.

The ZIP plus this current repository is the intended handoff. Claude does not need access to the Codex conversation. It does need filesystem, shell and browser/test access in its own environment to execute and verify the work.

If using another machine or a fresh clone, transfer the relevant current working-tree changes as well. A clone at the recorded Git commit alone omits uncommitted workbench repairs, tests, route error boundary, research and reference files. Do not substitute the standalone mock for the missing production app. The package deliberately excludes credentials, runtime secrets, database contents, dependency installations and authenticated browser sessions.

If using Claude chat with only the ZIP attached, it can review the design and plan, but cannot safely implement the real application without the production repository and execution environment.

## User intent and scope

Modernize the complete tenant and platform application with a consistent experience. Preserve all existing behavior, especially CVE Assessment Workbench and Findings filters. Bring Vulnerability and AI Findings into the same visual system while preserving their distinct domain behavior. Use the existing research and reference; inspect only changed or uncovered behavior as necessary. Marketing/blog/demo marketing content is outside this redesign.

The user requested a phased implementation plan with minimal interaction. All phases in the ledger remain planned. There is no running scheduler or background implementation. The handoff itself is not production deployment authorization. When the user explicitly starts implementation, progress through the authorized phases automatically; do not stop for approval after every navigation item.

## Read in this order

1. The actual repository's applicable `AGENTS.md` instructions, if present, and `prototype-app/CLAUDE.md`, `prototype-app/frontend/CLAUDE.md`; read backend instructions before backend work. `repository-context/` contains dated instruction/CI snapshots for reference. Follow current applicable repository instructions over stale snapshots, subject to the user's instructions.
2. `IMPLEMENTATION_PLAN.md` — phase sequence, architecture, automation loop and acceptance gates.
3. `BEHAVIOR_PARITY_AND_IMPLEMENTATION.md` — exact Findings/AI/CVE behavior contracts, known baseline quirks, selectors, route-family gaps and non-negotiable boundaries.
4. `VERIFICATION_RESULTS_2026-10-24.md` and `evidence/CVE_WORKBENCH_VERIFICATION_2026-10-24.md` — distinguish the last frontend rerun from earlier PostgreSQL/browser evidence.
5. `IMPLEMENTATION_PROGRESS.json`, `IMPLEMENTATION_ROUTE_CHECKLIST.json` and `BEHAVIOR_BASELINE_2026-10-24.json` — planned state, initial declared route patterns and source hashes.
6. `design-reference/CONTEXT.md` and `design-reference/src/design-preview/README.md`, then the relevant tokens, shared components and page compositions.

The newer behavior contract and verification report supersede historical initial-copy claims in the reference notes. The 65 route patterns are an initial inventory, not 65 completed visual designs or resolved optional subviews. The mock is representative, not a complete feature implementation.

## Critical behavior reminders

- Keep the actual production queries, hooks, reducers, types, API serialization, route helpers, state and authorization checks. Transfer presentation, not the mock's arrays, simulated saves, simplified queues or pagination.
- Findings: queue-wide widgets/groups remain queue-scoped while filters narrow the table. Preserve column multi-select, widget toggles/reset semantics, cursor paging, page-local filters, preferences, selection lifetime and existing saved-queue behavior.
- Vulnerability row click selects; Finding/CVE links remain separate. AI rows navigate to detail with existing return scope. Do not unify these interactions accidentally.
- CVE applicability and analyst impact are separate. Computed VEX impact remains server-driven. Partial assessment saves are allowed. Preserve investigation draft/persistence boundaries, dirty guards, eligibility/overrides, both finding-creation entry paths, creation modes and partial failures.
- Notification email delivery is unconnected; drafts must not claim delivery. Preserve containment of generic Azure/SCCM, retired Patch Management, runtime execution, Fix Intelligence and other restricted features.
- Keep existing labels, accessible names, selectors, default-dark theme and `scoutai-theme` storage. Optional command palette/sidebar collapse/resizing are not automatic production requirements.

## Baseline and current work

The last complete live frontend run passed **715 tests across 79 files**; the reference passed **35 tests**. Both builds passed. Production lint had three existing unrelated warnings. These are recorded results, not a promise that checks have run in Claude's environment.

The tested local baseline included uncommitted workbench repairs and tests. Source hashes identify important files, but do not reconstruct the application. Run the bundled helper before editing:

```sh
python3 verify-baseline.py --repo /path/to/SG
```

It only compares hashes and checks presence of required working-tree files. It never changes the repository or exposes file contents. Investigate changed/missing files as a focused delta; do not overwrite them to force a match. Additional required files listed by the helper are presence checks, not a complete dependency inventory.

`production-regression/` contains test snapshots for comparison. Do not blindly replace newer tests with them. Keep current assertions and merge missing relevant cases only after checking the actual repository.

## Execution and verification

Use the existing Node/React/TypeScript/Vite/CSS stack. CI currently uses Node 20; local Node 26 required a test-only Web Storage compatibility option. Respect current lockfiles and repository commands.

Production checks from `prototype-app/frontend`:

```sh
npm run lint
npm run typecheck
npm run build
npm run test:coverage
```

On the recorded local Node 26 environment only, the test command was `NODE_OPTIONS=--no-experimental-webstorage npm run test:coverage`. Preserve coverage floors and all existing behavioral assertions. Keep feature behavior changes separate from restyling. A test count or screenshot does not prove persistence.

Run the reference separately:

```sh
cd design-reference
npm ci --legacy-peer-deps
npm run dev
```

Open `http://127.0.0.1:5174/design-preview.html#/reference`. Reference checks: `npm run typecheck`, `npm test`, `npm run build`.

The fixture-backed browser checks moved from `browser-fixtures/` in this folder to `prototype-app/frontend/e2e/`. Historical commands recorded in the ledgers keep the old path.

Use browser tools available in Claude's environment; Codex-specific tool bindings and browser sessions do not transfer. Establish reproducible browser checks as planned. The fresh authenticated application check previously redirected to login. Continue independent code/fixture work while recording that release gate as pending. Do not inject tokens, bypass auth or claim authenticated verification from mocked fixtures. Request approved test access once when it becomes necessary. Never use customer records for destructive or external-delivery testing.

Checkpoint phase progress, files, tests, screenshots, limitations and rollback after each verified slice. Resume from the ledger after interruption. Preserve unrelated local changes. Do not reset the repository, weaken tests, lower coverage or silently declare unresolved release checks complete.

## Suggested instruction to start implementation

> Implement ScoutGrid UI 2.0 using this handoff and the current repository. Read CLAUDE_START_HERE.md, IMPLEMENTATION_PLAN.md and BEHAVIOR_PARITY_AND_IMPLEMENTATION.md first. Reuse the existing reference, audit and regression tests. Preserve the current working-tree repairs and all existing behavior, especially Findings filters and the complete CVE workbench. Start with phase 0 and proceed through the dependent phases automatically, recording checkpoints in IMPLEMENTATION_PROGRESS.json. Validate each slice, repair regressions and continue without asking for approval after each page. Ask only for a material product decision or required access/approval after completing independent work. Prepare a qualified, reviewable release candidate and rollback; do not deploy to production under this instruction.
