# UI 2.0 parity verification — October 24, 2026

## Fresh checks from this pass

| Check | Result |
|---|---|
| Live frontend complete suite | **715 tests passed, 79 files** |
| New live regression cases | **25 added**: eight Findings, three AI Findings, nine CVE eligibility/result helper cases, five workbench integration cases |
| Live coverage | Lines **49.41%**, statements **46.78%**, functions **38.94%**, branches **38.18%** |
| Coverage floors | Increased to 49.4 / 46.7 / 38.9 / 38.1 respectively |
| Production frontend build | Passed TypeScript, Vite build and production-bundle policy verification |
| Production ESLint | Passed with three existing unrelated warnings |
| Standalone reference | **35 tests passed**, TypeScript and production build passed |
| Mock browser | AI provider filtering; AI detail/return route; CVE partial save → impacted assets → configuration; light/dark and 390px responsive layout verified |
| Fresh authenticated live browser | **Not completed**: current in-app browser redirected from Intelligence to login |
| Backend/external providers/deployment | Not rerun or deployed by this parity pass |

The three existing lint warnings are in `GithubPipelineManager.tsx`, `PageFreshnessStatus.tsx` and `ConfigurationsPage.tsx`. The reference build reports a large single-chunk advisory; it remains a standalone review application. Vite/Vitest report existing configuration/plugin deprecation warnings.

## Live behavior protected by new tests

- Repeated URL severity/status/source/asset-type scope; invalid source values excluded; current request shape and page limit.
- Column multi-selection, independent chip removal and severity widget toggle semantics while aggregate queries stay queue-scoped.
- Local finding-ID/minimum-risk narrowing, cursor reset and retained results during refresh, row selection versus CVE navigation, clear-all retaining queue, stored columns and read-only workflow gate.
- AI policy/provider/status/trimmed subscription combinations, retained URL severity/resource-kind/policy context and detail return URL. AI software vulnerability queries retain finding-kind and affected-AI-resource constraints for All states.
- CVE result derivation for impacted/not impacted/unknown/review, eligibility versus analyst override, computed impact remaining separate from analyst disposition, applicable-only scope.
- Partial assessment failure and retry, removal/restoration of applicability clearing/defaulting impact, unsaved-rationale Stay action, per-component VEX failure/retry/cache, finding configuration retention and CVE_FIX retry without a mode fallback or unwanted ticket call.

Existing live tests also remain unchanged for investigation persistence/load failure/retry, fix generation failure/retry, notification draft content, finding severity/due date metadata, grouped-finding errors and partial ServiceNow failure.

## Reproduction

From `prototype-app/frontend`:

```sh
NODE_OPTIONS=--no-experimental-webstorage npm run test:coverage
npm run lint
npm run build
```

The Node option accommodates Node 26 Web Storage behavior in the existing jsdom setup. No production runtime setting was changed.

From `prototype-app/Working Knowledge/New UI 2.0/design-reference`:

```sh
npm run typecheck
npm test
npm run build
npm run dev
```

Review `http://127.0.0.1:5174/design-preview.html#/reference`, then Findings experience parity and CVE assessment workbench.

## Evidence and limits

- Browser screenshots: repository-root `output/ui-2-cve-parity-review.jpg` and `output/ui-2-ai-findings-parity.jpg`.
- Behavior source snapshot: `BEHAVIOR_BASELINE_2026-10-24.json` records SHA-256 hashes for the critical tested local controllers/hooks.
- Earlier workbench browser/PostgreSQL evidence: repository-root `output/CVE_WORKBENCH_VERIFICATION_2026-10-24.md`. Its 690-test result and PostgreSQL/browser checks belong to that earlier verification, not this fresh rerun.
- This pass changed design-reference files and production regression tests/coverage floors. It did not change production page behavior or deploy anything.
- The existing workspace already contained workbench repairs and a route error boundary. They were preserved and included in the tested local baseline.
- Mock state is simulated and does not prove live persistence or provider delivery. Authenticated staging browser checks, database verification and real deployment qualification remain release gates.

See [the implementation contract](BEHAVIOR_PARITY_AND_IMPLEMENTATION.md) for exact preserved behavior, known baseline quirks, remaining route acceptance and the migration sequence.
