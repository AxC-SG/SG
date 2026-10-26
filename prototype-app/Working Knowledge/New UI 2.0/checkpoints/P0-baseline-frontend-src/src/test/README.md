# Frontend page-test scaffolding

Goal: a new page test should be ~40 lines, not ~150. The boilerplate that
every test repeats lives here so the test file can focus on what's actually
being asserted.

## Pieces

| Piece | When to use |
|---|---|
| `renderWithProviders(ui, opts?)` | Always. Wraps in `QueryClientProvider` + `MemoryRouter`. |
| `buildFinding(overrides?)` | Page that renders a `Finding` (Findings, FindingDetail, dashboards). |
| `defaultRiskPolicy(overrides?)` | Anything that calls `api.getRiskPolicy()` / `useRiskPolicyQuery()`. |
| `defaultFindingFilterValues(overrides?)` | Anything that calls `api.listFindingFilters()`. |
| `pageOf(items)` / `findingPageOf(items)` | Mocking paginated `Page<T>` API responses. |

## Routing variants

`renderWithProviders` accepts either form:

```ts
renderWithProviders(<FindingsPage />);                          // / by default
renderWithProviders(<FindingsPage />, { route: '/findings' });  // string entry
renderWithProviders(<FindingDetailPage />, {
  initialEntries: [{ pathname: '/findings/F-001', state: { finding } }],
});
```

Use `initialEntries` when the page reads `useLocation().state` — passing
`route` alone won't carry router state.

## Minimal page-test skeleton

```tsx
import { screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { buildFinding, defaultFindingFilterValues, defaultRiskPolicy, findingPageOf }
  from '../test/fixtures';
import { renderWithProviders } from '../test/test-utils';
import { FindingsPage } from './FindingsPage';

describe('FindingsPage', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    localStorage.clear();
  });

  it('renders rows for findings returned by the API', async () => {
    vi.spyOn(api, 'listFindings').mockResolvedValue(findingPageOf([buildFinding()]));
    vi.spyOn(api, 'listFindingFilters').mockResolvedValue(defaultFindingFilterValues());
    vi.spyOn(api, 'getRiskPolicy').mockResolvedValue(defaultRiskPolicy());

    renderWithProviders(<FindingsPage />);

    expect(await screen.findByText('F-001')).toBeInTheDocument();
  });
});
```

## Conventions for new page tests

- **One assertion theme per test method.** A test that checks render +
  filter + paging + auth in one function turns into a maintenance trap when
  one of those drifts.
- **`vi.spyOn(api, 'method').mockResolvedValue(...)`** is the standard mock
  shape. Use `mockRejectedValue` for error-state tests. Call
  `vi.restoreAllMocks()` in `afterEach` so spies don't leak across tests.
- **Don't mock things the page doesn't call.** Mocking every API on the
  client creates false coupling — only mock the endpoints the test
  actually exercises.
- **Don't repeat fixtures.** If you would write a 25-field `Finding` literal
  or 30-field `RiskPolicy` literal, use `buildFinding()` /
  `defaultRiskPolicy()` and pass overrides for the fields that matter.
- **Don't reach into internals.** Assert on rendered DOM (`screen.findBy*`,
  `getByRole`), not on hook output or component state.
- **`localStorage.clear()` in `afterEach`** for any page that persists
  filter / column / view preferences.

## Existing tests that pre-date this scaffolding

`FindingsPage.test.tsx`, `FindingDetailPage.test.tsx`,
`VulnRepoOrgCvePage.test.tsx`, `VulnRepoVulnerabilitiesPage.test.tsx`, etc.
inline their own `buildFinding` / `RISK_POLICY` literals. They work — don't
touch them just to migrate. New tests should use the scaffolding; migrate old
ones opportunistically when you're already in the file for another reason.
