# UI 2.0 visual CI repair — 30 October 2026

## Failure and cause

[PR #43's frontend-e2e job](https://github.com/AxG-SG/SG/actions/runs/41030161511/job/123977805205) passed the build boundary checks and all 823 functional journey assertions, then failed 164 of 172 screenshot comparisons. Eight public landing/blog screenshots passed.

The last UI 2 screenshot refresh was commit `a1f87f03`, before the Stage 2b–6 shared-shell, header, table and form changes included in `05a64dfa`. The PR updated the implementation and functional expectations but retained the earlier screenshots.

Representative failures were reproduced from an isolated copy of `05a64dfa` in the exact pinned CI browser image, using `linux/amd64`:

`mcr.microsoft.com/playwright:v1.63.0-noble@sha256:eff16c30e6f3f4af0a03fa4b706120d5e9b0891c344a27d64559aff5900a4a27`

All 24 comparisons for findings, Exposure, connectors, login, setup and demo request failed as expected. Sample dimensions and pixel-difference counts matched the CI log exactly. The image-provided Node version was 24.20.0; CI uses setup-node 24.22.1. Browser binaries and system fonts came from the pinned image in both cases.

## Bounded repair

Refreshed only the 164 screenshots identified by the CI failures: 41 routes, dark/light, 1280/390px. The eight passing public landing/blog screenshots remain byte-identical.

The refreshed changes reflect the existing source:

- Grouped, icon-labelled navigation; collapsed sidebar subsections; one shared route H1.
- Shared table controls, result counts, paging, form and family-layout adoption.
- Existing Exposure widget ordering and KPI presentation changes.
- Explicit missing/empty states and route titles already covered by functional tests.
- Login/setup recovery guidance, and company-email/CAPTCHA helper text on demo request. The unrelated marketing landing and blog pages were not refreshed.

All changed images were inspected through eleven before/after comparison sheets, with full-size representative findings and auth/form comparisons. This is Codex's automated visual-diff review, not an invented human designer approval. Product/design acceptance and other open qualification requirements remain separate.

The [snapshot manifest](verification/ui2-ci-visual-2026-10-30/snapshot-manifest.json) records each route, actor, theme, width, before/after image size, SHA-256 hashes and expected change. The original images remain recoverable from Git history. Reproduction, diff sheets and local comparison output are retained under `/private/tmp/sg-pr43-e2e/` on the verification host.

## Guardrails and validation

- Used the visual spec's route filter and `--update-snapshots=changed`; did not run the broad `e2e:update` command.
- Screenshot tolerance remains `maxDiffPixelRatio: 0.001`.
- No screenshot masking, disabled tests or modified assertions.
- No journey or accessibility baseline changes; legacy UI 1 snapshots are untouched.
- Full visual comparison was rerun with snapshot updates disabled: **172/172 passed**, zero failures. The result is recorded in the manifest.

This commit changes screenshot expectations and qualification evidence only; it does not change application behavior. Roll back by reverting the snapshot/evidence commit.
