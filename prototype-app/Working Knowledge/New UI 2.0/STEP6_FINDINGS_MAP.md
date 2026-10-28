# Step 6 Findings retirement slice

Starting commit: `baedb16d`. The Step 6 starting baseline remains the verified run on `68a4a3bc`, retained in `/private/tmp/sg-ui2-step6.QsSmLw/baseline`.

## Ownership before editing

The Findings presentation sheet already covered vulnerability lists, finding details, AI Findings and AI Exposures. It still needed base layout and controls from legacy sheets. These classes also appear on other app pages, so their shared defaults must keep their existing specificity and values.

| Legacy source | Rules selected | New owner | Rules deliberately retained |
|---|---:|---|---|
| `base.css` | 33 | `ui2/findings-base.css` | Five Inventory-context overrides stay with Inventory; unrelated base rules unchanged |
| `finding-detail.css` | 108 | `ui2/findings-base.css` | Five `iov-*` overview rules stay until the Inventory slice |
| `ai-security.css` | 19 | `ui2/findings-base.css` | Eight Inventory-scoped rules plus policy, graph, connector and other AI rules stay with their own slices |
| `findings-list.css` | 156 | `ui2/findings-base.css` | No style rules remain; an import stub stays until the final entry-point slice |

Selected rules include hover, selected, active, disabled, focus, modal, responsive and reduced-motion states. AI policy-specific hero variants were excluded. No selectors were removed merely because they were absent from a coverage run.

## Consolidation and cascade

- Removed 37 declarations already superseded by unconditional UI 2 rules with the identical selector body and property. For example, `findings.css` already owns the `.fpl-root` and `.fd3-page` surface/padding and the column-filter surface. The manifest records the replacing sheet, selector and property.
- Removed 37 identical repeated declarations under the same selector and conditional context. Different values, fallbacks and priorities remain intact.
- Required declarations retain their values and relative order. The new base wraps original selectors in `:where(html[data-ui='2'])`, adding no specificity. Existing family presentation rules keep their stronger scope and page roots.
- The shared base loads after primitives and before family presentation sheets. It is available on direct loads of CVE and Inventory pages; it no longer depends on a visit to the lazy Findings route. This intentionally addresses the recorded cold-load versus navigation difference caused by `findings-list.css`.
- Base animation names are private to this sheet (`ui2-findings-reveal`, `ui2-findings-spin`). The original AI reveal keyframes remain for the connector layout, which has not been retired.
- Raw legacy defaults and token fallbacks are preserved; this slice does not recolour statuses or severities. The legacy token bridge remains until the final slice.

## Evidence and limits

Scratch evidence: `/private/tmp/sg-ui2-step6.QsSmLw/gate-findings/`.

- `cascade-before.json` was captured before any CSS edit; `cascade-after.json` includes the new base in effective load order and the Findings focus set.
- `migration-manifest.json` records every selected selector, conditional context, source line and declaration, plus each superseding UI 2 declaration.
- `migration-verification.json` checks 1,455 retained declaration/selector pairs and confirms that the remaining 1,667 base rules, 5 Inventory overview rules and 311 AI rules are unchanged.
- The affected-route map selects all 35 routes for the shared base, including the public-route isolation checks.
- Scope tests retain the existing page-boundary assertions and add checks for zero-specificity base ownership, private animation names, eager control availability and retired legacy definitions.

The static cascade map compares subjects and properties. Its overlap counts include different ancestor contexts and expected presentation overrides; they are not browser regression counts. No visual, axe or live pass is claimed from this map or from the declaration verifier.

The fast slice gate is recorded in S6 of `CLEANUP_PROGRESS.json`. Full visual, affected-route, axe, live, coverage and bundle checks remain due at checkpoint B before the final version-switch/bridge removal, then at Step 8. No visual baseline or tolerance was changed in this slice.

The first fast gate reported 774 passed / 1 failed / 0 skipped. The new base-ownership assertion at `scope.test.ts:122` rejected eight `.inventory-shell.ai-security-page ...` selectors selected by an overbroad AI predicate. The predicate was corrected to require a leading shared AI root; those eight Inventory selectors remain in `ai-security.css`. The assertion was retained unchanged. The first attempt is preserved in `gate-findings/attempt-1/`; the corrected gate is recorded in S6.

Corrected fast gate: lint 0 errors / 2 existing warnings; typecheck passed; Vitest 775 passed / 0 failed / 0 skipped in 84 files, including 19 scope tests. This is the fast slice gate only; the full checkpoint B gate remains open.
