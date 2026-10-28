# Previous state: before UI 2.0 and before legacy retirement

Recorded October 28, 2026 from the retained archives, manifests and implementation ledgers. This is historical context, not a specification for new screens.

## Before the redesign

The React/TypeScript SPA already contained the live Findings queues, AI Findings, full CVE Assessment Workbench, inventory/lifecycle/AI graphs, tenant/platform governance, connectors/configuration, dashboards/campaigns/operations and auth entry flows. Their APIs, query/filter behavior, DTOs, permissions, entitlement boundaries, URLs and persistence contracts were the behavioral authority. The standalone design mock supplied visual direction and simulated interactions; it was not a production data/authorization implementation.

Presentation was spread across `base.css`, shared before/after/public styles, page/family sheets, component-local table CSS and lazy route imports. Theme/spacing/color aliases and cross-family selectors made some computed styles depend on navigation order. The migration preserved the real workflows while replacing the presentation in complete families.

`checkpoints/P0-baseline-frontend-src.tar.gz` preserves the previous frontend source (320 per-file manifest entries, including package/configuration files). The manifest records the archive-creation commit `ed4efc91`; that field is not a claim that the archived source is the final UI 2.0 source. Archive SHA-256:

```text
487865af537e764fbeb1e3ed701913f48214a9f88c775275ece4c57d56b13fe1
```

## Transitional state before retirement

UI 1 and UI 2 coexisted behind `VITE_UI_VERSION` and `src/lib/uiVersion.ts`. UI 2 rules activated through `data-ui="2"` and a compatibility bridge mapped old tokens to design tokens. Both builds were tested during qualification; this was a migration mechanism, not the future screen architecture.

Step 5 froze a production UI 1 build from `a3f1d1db` as `checkpoints/UI1-frozen-a3f1d1db.tar.gz` (86 per-file manifest entries). Its frontend tree is recorded as `69690f13b5de458fb0612836032deb2558ea5744`, equal to the Step 4 gate's frontend tree. Archive SHA-256:

```text
f040137d4956b5bcc68133b89b2eb1f28136a456561a76f7236200352c81a707
```

The user's October 27 instructions authorized the focus-ring fix and proceeding with retirement, waived staging/human review, and deferred long checks to the agreed checkpoints/final gate. The exact instructions, interpretation and limits remain in `CLEANUP_PROGRESS.json` (S5 `userDecisions`/`decision`, `checkDeferral`, and S6 authorization). This permitted legacy retirement; it did not certify the resulting artifact or authorize deployment.

After retirement, legacy comparison and rollback use that frozen artifact. Never rebuild UI 1 from the current app or restore P0 over the live source as a substitute for the qualified artifact.

## Preserved behavior and current authority

The migration did not add APIs, change schemas, expand permissions/entitlements or enable contained capabilities. Findings queue aggregates remain distinct from narrowed/page-local rows; AI Findings retain domain-specific navigation and scope; CVE applicability, analyst impact and computed impact remain distinct; supported writes still require real backend persistence. These contracts are maintained in the live feature code, tests, [frontend reference](../../docs/frontend.md), [business logic](../../docs/business-logic-guide.md) and [UI development standard](../../docs/ui-development-standard.md).

The original mock, review reports, source-hash verifier, intermediate screenshots/logs and family maps were removed during documentation cleanup. Their tracked versions are recoverable from Git at `eedc8a0864cadf7c0cd0e55ec733f4637ff6622a`. The two immutable archives and dated ledgers remain the retained baseline, decision and rollback evidence.
